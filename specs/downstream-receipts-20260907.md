# 第一、二步实施：分段定位与下游回执

## 当前范围

保留现有 PostgreSQL + Outbox + RQ，不新增 RabbitMQ，不改变模型、阈值、审批或默认并发。本轮实现针对可检查的两个目标：

1. 后续故障复测可以区分数据库借连接、提交、身份校验、策略、并发等待、上游调用和扫描；分别观察数据库角色与真实测试写入能否完成。
2. 对管理员核验过的单个工具，能按原操作编号查询下游已经提交的业务结果；查询、重投通知或旧执行器恢复都不能重新执行业务。

**第一步尚未通过性能与故障验收。** 首次交付时完成的是测量点、探针和受控并发配置入口；后续经用户同意临时调整系统监听额度，已完成 1 / 2 / 4 对照、默认额度复跑、两轮断网与积压恢复，详见 [四节点复测报告](multinode-receipts-validation-20260907.md)。两轮新测试仍分别有 45、48 次未获受理确认，另有 1 条已受理请求结果未知；原来的 37/600 次限流和两轮 43、95 次未获受理确认仍保留。重连后的 34 次 503 本次没有复现，不等于已永久修复；未凭猜测修改数据库超时或同步复制。

## 分段测量与并发对照入口

- Helm 新增 `gatewayConcurrency.maxPerServer`、`waitSeconds`，默认仍为 1、1 秒；网关与 worker 通过同一个 ConfigMap 使用相同配置。
- `verify_multinode_capacity.py setup --concurrency 1|2|4` 只为受控上游准备对照，配置保存在冻结测试状态中。不能把测试参数直接当作生产推荐值。
- 测试运行时记录分段耗时、次数与错误计数，不输出 SQL、调用参数、结果或密钥。嵌套阶段有重叠，分位数不能相加；排队准备失败且尚未解析到受控请求编号时可能没有逐请求阶段事件。
- 新数据库时间线从控制节点通过数据库 Service 连接，记录角色、地址、借连接耗时与确认提交。只修改独立的 `eval_database_probe` 合成计数，不改变业务表；探针本身增加少量测试负载，应在所有对照组中一致启用。
- 真实 PostgreSQL 锁阻塞测试验证：角色可写不等于测试写入可完成。该测试是锁阻塞，不冒充 Patroni 同步复制或完整切主演练。

## 回执合同与执行绑定

新增迁移 `0018_tool_receipt_contract`：

- `tool_execution_policies.receipt_contract`：管理员核验的查询方式。
- `tool_invocations.receipt_binding`：执行前与下发标记一起持久保存的原操作绑定。

通过已有 `PUT /v1/mcp/tools/{tool_id}/execution-policy`、`mcp:admin` 权限配置可选 `receipt_contract`，内容为：

```json
{
  "protocol": "agentops-receipt-v1",
  "key_argument": "operation_id",
  "lookup_tool_id": "受控服务ID:lookup_receipt",
  "lookup_revision_digest": "填写真实查询工具版本的64位十六进制摘要",
  "retention_seconds": 3600
}
```

同时填写已有版本、证据摘要字段，并保持 `retry_mode=never`。上例说明字段，不是可直接提交的有效摘要。需要人工验证下游将去重记录、业务修改、结果回执一起提交；填写合同本身不证明第三方服务具备此能力。

限制及语义：

- 查询工具必须已注册、启用，与原工具属于同一项目、同一服务，且版本摘要匹配；不接受 Agent 指定查询 URL 或临时工具名称。
- `key_argument` 必须为原工具声明的字符串字段。调用方不得填写该保留字段，受信执行器生成与项目、身份、原请求、工具版本和参数摘要绑定的固定操作编号。
- 编号在参数扫描、动作对齐和审批绑定之前注入；下发前再次核验合同。原始请求的同编号不同参数仍拒绝，排队恢复不生成新业务编号。
- 查询前后检查原 API key 的有效期、吊销、项目和 Agent 权限，以及服务、原工具、查询工具和合同版本。当前回执恢复仅支持持久项目 API key 身份。
- 一次查询只使用原编号。查无、处理中、连接失败、回执不匹配或超过核验的保留期，均不能授权重跑。此版本没有自动重试外部业务动作。

下游 `lookup_receipt(operation_id)` 返回 MCP `structuredContent`，只允许这些字段：

```json
{
  "operation_id": "原操作的64位十六进制编号",
  "tool": "原工具名称",
  "state": "completed",
  "result_sha256": "原结果的64位十六进制摘要"
}
```

`state` 也可为 `not_found`、`pending`；它们不构成未执行证明。`completed` 必须有匹配的编号、原工具名称与结果摘要。

## 查询与自动核账

- `POST /mcp/invocations/{request_id}/reconcile`：仅原身份可以触发该请求的查询，不接受额外执行参数。
- `GET /mcp/invocations/{request_id}`：沿用现有状态查询。
- 独立进程 `uv run --offline agentops-guard receipt-reconciler`：自动分批查询未知请求，默认每批最多 10 条、轮询间隔 10 秒，支持 `--once`。一次运行时间还包含有界网络查询耗时，不保证每 10 秒完成全部积压。游标避免前面的未知记录挡住后面的记录。
- 查询进程不放进 Outbox 投递循环；慢下游不阻塞原任务通知。本轮未部署常驻查询服务，启用前须迁移数据库、核验合同，并由部署环境提供受信数据库和网络权限。

确认后状态是 **`execution_confirmed`**，不是 `succeeded`：

- `businessExecutionConfirmed=true`。
- `resultAvailable=false`、`resultScanned=false`、`resultStored=false`。
- `clientMayReplay=false`；原业务下发次数不增加。

当前只恢复业务确认和结果摘要，不获取、扫描或释放原始输出。安全扫描缺失仍保留；不把它计为完整网关成功。原审批执行记录和已结束后台任务的历史结果不重写为成功。原输出恢复/重扫、第三方工具适配及查询进程生产部署不在本轮已验证范围。

## 验证边界

最终全量 **837 passed，0 failed / error / skipped**，启用真实 PostgreSQL、Redis/RQ、HAProxy 和 MCP 测试。报告：`artifacts/verification/receipt-contract-release-20260907.xml`，SHA256 为 `319e8ffe89b9f6be71c693b705e8b67c33aa98dac7254dd689ceba60b30b2116`。Ruff、`git diff --check`、Helm lint / 完整模板检查通过。测试通过不代表生产高可用验收通过。

保留前序失败报告：第一轮新增测试因夹具使用了不存在的工具名，19 failed / 33 passed / 2 skipped；修正后第二轮因错编号测试断言和 MCP 字典返回封装不符，2 failed / 19 passed。第三轮定向 59 passed。全量先后为 825 passed / 4 skipped（未启用真实 HAProxy）、835 passed、836 passed，最终上述 837 passed；不覆盖旧报告。

- `tests/fixtures/receipt_mcp_server.py` 是 loopback 限定的受控 MCP 服务，独立 SQLite 文件保存业务效果与回执，不使用网关数据库。
- 真实进程在 SQLite 事务提交后、MCP 回复前 `os._exit(71)`；网关记录未知，服务重启后查询同一编号，业务效果仍为 1。是真实下游进程退出，不是网关 worker 被物理杀死，也不证明断电下磁盘耐久性。
- 16 次并发同编号提交，业务效果为 1；同编号不同参数拒绝。该试验只证明该受控工具，不代表任意 MCP 工具具备幂等能力。
- 覆盖查询错编号、错工具、无效结构、查无、处理中、超时、版本变更、跨身份、吊销、查询期间吊销，以及确认后旧执行器不能覆盖结果。
- 原有真实 PostgreSQL、Redis/RQ、HAProxy、MCP 与安全回归继续执行。冻结规则、模型配置与原始故障报告，不产生新的风险识别准确率数字。

## 首次交付时的集群边界与后续复测

四节点测试预检要求 `fs.inotify.max_user_instances >= 512`，首次交付时为 128，因此当时没有调整系统参数或启动候选集群。后续经用户同意，已临时调整至 512 并完成上述复测，随后清理集群、恢复 128，未修改永久配置。新回执合同未在该集群受控上游启用，仍不能声称它已经通过节点故障下的集群验收；具体证据与未通过项见后续报告。

没有实施第三步独立接单队列，没有提交或推送 Git，未修改 Windows 回滚副本。

首次单元/集成测试产生的自有 Redis 容器、夹具 PostgreSQL 容器、受控 MCP 进程和 `/tmp/agentops-receipts-tests-H84bgO` 合成数据库均已清理；临时数据不再保留，源码和验证报告保留。首次交付没有修改系统参数；后续集群复测临时调整后已还原，目前系统监听额度为 128。
