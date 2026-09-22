# 工具调用持久记录与延后执行：本轮实现及边界

> 本文保留 2026-09-06 的实现和验证快照。后续工具任务租约、接管、丢通知补投及真实集群结果见 [2026-09-07 Outbox 恢复报告](outbox-recovery-20260907.md)；下文的 660 秒工具任务租约不是后续版本配置。

## 结论

在原有网关、逐事件审批、BackgroundJob / Outbox / Redis RQ 基础上增加工具调用记录。
正常请求仍同步返回；客户端主动选择排队时才返回 202。**受理不是完成，失败也不等于工具从未执行。**

没有替换传输层、扫描器或授权策略，没有引入 Temporal 等新调度平台；没有调整旧压测的失败统计、超时门槛或数据库复制要求。

## 已实现

1. 所有经过 `tools_call` 的普通调用在执行前保存请求编号、参数摘要及执行状态；下发工具前必须成功提交 dispatch 标记。保存失败不得下发。数据库唯一约束和带随机令牌的条件更新防止并发重复执行；同一身份、同一编号换参数返回 409。
2. 请求状态只允许原调用身份在原项目查询。正常成功有持久回执；执行后失联且无法确认时保留 `outcome_unknown`。查询不会重放工具，不保存原始工具输出，不把未知伪装成成功。
3. 增加管理员维护的逐工具执行策略，绑定当前工具版本摘要和核验材料 SHA256。默认不允许排队、不允许自动重试。模型判断和上游 `readOnlyHint` 不授予重试资格。工具描述、目标或核验策略变化后，旧排队请求不能继续执行。
4. 显式排队只接受持久项目 API Key；后台执行前重新检查项目状态、Key 吊销/过期/权限、Agent 身份、工具版本，并走原有参数扫描、服务端原始要求对齐和审批流程。下发前再检查身份和工具配置。操作员临时身份、网页登录及工作负载短期令牌暂不支持延后执行。
5. 排队参数用独立 Fernet 密钥加密，并绑定请求、项目和身份；不得复用 API 进程的凭据 Vault 密钥。检测到的秘密值拒绝入队，普通邮件/电话号码不因此拒绝；这不是“能识别一切密钥”的承诺。BackgroundJob 和 Redis/RQ 只携带系统生成的 invocation ID。最终状态或过期清理时删除执行参数密文，保留回执。
6. 回执、密文、任务和待投递事件在同一数据库事务提交之后才返回 202。Redis 暂时不可达时保留待投递记录；数据库本身不可写时返回真实错误。投递进程遇到可识别的数据库暂时不可用后继续巡检，其他程序错误照常暴露。

## 重试规则

| 情况 | 处理 |
| --- | --- |
| 默认工具、写入/发送/扣款等操作 | 不自动重试工具；结果不明则标记未知 |
| 管理员核验过版本的只读工具，传输尝试已返回并清理，但没有结果 | 允许重新排队；最多 3 次下发，且每次重新执行原授权流程 |
| 进程在下发后丢失，包括已核验只读工具 | 不自动重放；等待状态过期后显示未知 |
| 工具明确报错、策略拒绝 | 不因报错而自动重做 |
| 在下发前遭遇并发配额/依赖暂时不可用 | 允许有界重投递；仍须成功取得执行资格才能下发 |
| 审批等待 | `/resume` 仅恢复检查，不等于批准；仍由原审批记录决定是否能执行 |

目前没有启用“下游具备幂等写入协议”的自动重试；需要对具体下游进行重复请求契约测试后再接入，不能仅凭配置或自报开启。

一次正常传输重试与一次进程丢失不是同一件事。过期 lease 不能证明远端没执行；新增随机 worker 领取令牌也避免旧投递代次冒充新执行者。

## 调用方式

同步调用保持 `POST /mcp/tools/call`。建议客户端**发请求前**生成 UUID，放在顶层 `requestId`；收到响应后再生成编号不能解决“响应整个丢失”的问题。标准 MCP 的扩展参数放在 `_meta["io.agentops/request"].requestId`，回执在 `_meta["io.agentops/control"].invocation`。

排队是显式 HTTP 扩展，不宣称实现标准 MCP Tasks：

```text
POST /mcp/invocations
  {requestId: <UUID>, serverId: <已登记服务>, name: <工具>, arguments: {...}, runId?: ...}
  → 202：回执已可靠保存，尚未完成

GET /mcp/invocations/<同一 UUID>
  → state / attempts / summary / clientMayReplay=false / resultStored=false

POST /mcp/invocations/<同一 UUID>/resume
  → 仅适用于尚未过期的排队审批等待；执行器重新走完整审批检查

PUT /v1/mcp/tools/<tool_id>/execution-policy
  → mcp:admin + 项目权限；提交 revision_digest、queue_enabled、
    retry_mode=never|read_only、evidence_sha256
```

`failed` 可能表示工具报错或结果被安全策略拦截，不能推断没有副作用。`succeeded` 表示网关已完成该次检查和结果处理，不代表任意下游业务的独立核账证明。`resultStored=false` 表示状态查询不提供原始工具结果；确需异步下载结果需另行设计受控结果存储。

同步审批继续沿用原 approval/execution 机制，批准后使用新 invocation 请求编号重新提交；不能通过重复原请求编号自动恢复执行。

## 限额、部署与未覆盖项

- 单个排队参数包上限 64 KiB；每项目最多 1,000 条占用队列的记录；1 小时内必须进入执行，审批等待同样有时效。队列入场计数在 PostgreSQL 上按项目行锁串行判断。
- 领取执行资格默认 120 秒；下发后覆盖至少工具超时加 60 秒。原 RQ 任务上限 600 秒、后台 lease 660 秒仍保留。因此丢失 worker 的投递恢复可能等待约 11 分钟，不承诺秒级接管。只读传输重试随既有 outbox 做有界退避。
- 先运行 `uv run alembic upgrade head`，新增迁移 `0017_tool_invocations`；生产数据库不使用开发环境建表。
- Helm 的 `invocationEncryption.existingSecret/key` 只挂载给 gateway / worker。未配置时普通同步记录仍可用，排队入口返回 503；不会使用默认硬编码密钥。没有在本轮替用户设置生产密钥或永久启用队列。
- 必须运行 worker 和 outbox-dispatcher，并让 worker 访问与网关相同的受信 MCP 目标、数据库、Redis、OPA 和扫描服务。增加 worker 到小模型服务的定向网络权限，没有放开所有出站网络。
- 同一 PostgreSQL 切主时，队列也可能暂时不能接单。若要求此时仍受理，接单存储必须另有可靠可用性保证，不能靠进程内内存代替。
- 本轮不提供任意写操作 exactly-once、不支持自动批准、不提供异步原始结果下载，也未新增回执历史的自动删除策略。

## 验证证据

第一轮真实依赖定向验证：20 passed，`artifacts/verification/invocation-focused-20260906.xml`，SHA256 `63c40a3436578cf7fb3cebd0ca847448adeba13f74f012bedd790baa27f0f140`。

首次全量：775 passed，零失败/错误/跳过，`artifacts/verification/invocation-full-20260906.xml`，SHA256 `283934ce7a31ccb0c7f4fda6b15bb4d82d1a17858f367d88dbf8330e6ded8882`。之后补了过期准备状态被撤权后的关闭测试；最终复跑结果另列，不能用首次全量代替最终源码验证。

最终运行代码全量验证：**776 passed**，零失败/错误/跳过，`artifacts/verification/invocation-final-20260906.xml`，SHA256 `449c7960572d2046ebca0ad19a604433e6e8ed83752d5744bf2e4502d3bde489`。真实 PostgreSQL 16、Redis 7、HAProxy 3.0 集成均启用。随后只增加/扩充测试，没有再修改运行代码；审批批准后的队列恢复与投递进程数据库恢复两条路径再次定向通过（`invocation-resume-paths-20260906.xml`），不把这两条与全量数字简单相加。

另用独立 PostgreSQL 16 容器实际运行 `alembic upgrade head`，查询确认版本 `0017_tool_invocations` 及两张新表存在；不是仅用 ORM 建表代替迁移。全部本轮临时 PostgreSQL / Redis 容器已删除，测试数据随容器删除；XML、源码及旧压测报告保留，未修改旧 Windows 回滚副本，未提交或推送 Git。

运行代码核对：

| 文件 | SHA256 |
| --- | --- |
| `backend/services/tool_invocations.py` | `df3ce8df8da43c82331064488a739e366f238a1287e7708aa181a9f8098673cf` |
| `backend/services/jobs.py` | `e419060830f3a9ab4f617a146242e1c6307a1d0931a6ca51ba734aa8d911a878` |
| `gateway/app.py` | `45b2ec45b59974ffa98f9c742ed7aa69bce3f5a6c8fd5f9cc2007d8b1b3cd270` |
| `alembic/versions/0017_tool_invocations.py` | `41e646250fdc7f7a00a7679d53b2c21d845b90c927a6d9e679ef5c972f28919f` |

前 3 项均相对于 `src/agentops_guard/`，第 4 项相对于项目根目录。这不是完整镜像冻结清单，不把源码核对等同于本版集群压测。

实际覆盖与注入边界：

- 真实 PostgreSQL 的只读写入失败：下发前记录无法提交时，没有调用工具，前序记录可查。
- 真实 PostgreSQL 四个并发连接竞争同一请求：一条记录、一方取得资格、一次下发。这个测试的工具副作用为进程内计数器，不是四台机器。
- 真实 PostgreSQL、Redis/RQ、网关完整处理函数和独立 MCP 子进程：正常完成、重复提交、再次投递均只执行一次。入口使用 FastAPI TestClient，RQ 用同进程 SimpleWorker，不冒充真实跨主机网络。
- 在真实 MCP 已返回之后，主动抛异常模拟 worker 丢失；随后推进数据库中的 lease 到过期并重投递，状态为未知，没有第二次工具调用。没有实际等待 660 秒，也不是本轮真实 kill 进程或物理断网。
- 权限撤销/收窄、工具版本变化、密文篡改、排队过期、审批未批准的恢复、提示注入参数，均验证未下发。API Key 在扫描后、实际下发前撤销也被拒绝。
- 模拟数据库提交前出错时，回执、任务和 outbox 一起回滚，入口返回 503 而非 202。
- 检查生成的纯数字片段 ID 不被脱敏器误改，Redis 不承载工具正文；工具自报审批编号不能把已执行动作变成可恢复的审批等待。
- Ruff、`git diff --check`、Helm lint / 完整渲染校验通过；额外渲染检查了独立密钥只进入 gateway / worker，以及 worker 的扫描服务网络规则。旧 Helm 校验脚本错误要求 `--bundle=/path`，已同步为当前 OPA 的 `--bundle /path`，仍严格检查签名公钥、签名范围和批准版本。

### 还不能下的结论

没有重跑这版源码的四节点完整集群断网和峰值 benchmark；也没有测量新增持久记录的 p95 开销、排队积压恢复时间或新队列的生产 RPO/RTO。既有 `46/360` 两轮业务失败仍是旧候选结果，不因增加“已受理”而消失。

因此：`current_candidate_full_cluster_rerun=false`，`failure_rate_improvement_demonstrated=false`，`production_sla_verified=false`。新增恢复能力的行为测试通过，不等于生产高可用验收通过。下轮应固定新镜像与配置，分别测同步原指标、可靠受理、最终完成、未知结果、重复副作用及排队完成时间。

依据：[AWS 安全重试与请求编号](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/)、[Azure 异步请求与状态查询模式](https://learn.microsoft.com/en-us/azure/architecture/patterns/asynchronous-request-reply)、[RQ 官方文档](https://python-rq.org/docs/)。RQ 的任务去重不是下游业务幂等，202 也不是最终业务成功。
