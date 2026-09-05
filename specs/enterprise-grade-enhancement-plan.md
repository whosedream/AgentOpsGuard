# Plan: AgentOps Guard 企业级增强与生产证据闭环

**Generated**: 2026-09-04

**Estimated Complexity**: High

**建议周期**: 3 人 8–12 周；单人 12–16 周，不含企业账号和基础设施审批时间

## Overview

一句话结论：这个项目已经有较完整的“安全骨架”，下一步不应继续堆功能，而应把现有能力放到
真实企业环境中，补齐身份、集群、密钥、策略、审计、供应链、故障和未知攻击的运行证据。

执行顺序不是“一次性全开”，而是：

1. 先冻结证据和边界，任何优化都不能偷换评测口径；
2. 保持确定性授权兜底，同时更换和校准旁路小模型；
3. 在真实 Kubernetes 预生产环境接通身份、OPA、OpenBao、Collector 和镜像准入；
4. 做主从切换、依赖中断、2 倍峰值和审计外部留存；
5. 用未见攻击驱动真实 Agent、Gateway 和工具，最后小流量灰度。

企业级不是“小模型把每条攻击都猜对”。企业级是即使模型漏判，未获授权的发送、删除、付款、
写入和改权限仍不能执行；即使进程、Redis 或上游出故障，也不会静默丢任务或盲目重复副作用；
出现问题后还能用不含秘密的证据解释发生了什么。

## Current Baseline

以下是当前已经有证据的能力，后续应保留而不是重写：

- 标准 MCP 上下游、可信身份上下文、项目隔离和读/调用权限分离；
- 服务端保存原始用户要求，并把动作、目标、参数、工具版本和策略版本绑定到审批；
- PostgreSQL 事务发件箱、Redis/RQ 投递、Worker 租约、结果未知对账和重复执行防护；
- `credential_ref`、OpenBao KV/Transit/Proxy 本地真实运行和固定目标凭据注入；
- OPA 真实 Rego、签名 bundle、只收紧策略合并和故障时保守处理；
- ToolHive 无网络、无宿主目录、非特权隔离；
- 哈希审计链、OpenBao 签名封条和 S3 Object Lock 出口实现；
- 独立离线语义服务、固定模型摘要、输入脱敏和 `shadow` 门禁；
- Inspect AI、AgentDojo、BIPIA、InjecAgent、LLMail 和真实本地 Qwen 的分层评测入口；
- 固定 Keycloak/Temurin 真实本地 OIDC 联调、Helm、Compose、SBOM、Google OSV 锁文件在线审计、
  固定发布验证和当前 10 项外部门槛。

当前检测证据也给出了明确限制：

- LLMail 固定静态集并集检出率为 `92.80%`，正常邮件误报 `0/203`；
- AgentDojo 首次未见静态集并集检出率为 `76.43%`，正常任务误报 `9.28%`；
- BIPIA 首次静态保留集并集检出率为 `38.28%`，正常内容误报 `6.50%`；
- InjecAgent 首次静态保留集并集检出率为 `54.74%`，17 个匹配正常模板误报 `1`；其中数据窃取
  为 `81.62%`，直接伤害只有 `26.08%`；
- 在 BIPIA 已知切片上使用完整 token 分窗，攻击并集命中提升到 `159/200`，但正常内容误报升到
  `28/200`，模型 p95 达 `2328.22ms`；阈值提高后召回断崖下降。

因此，当前 Wolf Defender 和“分窗后取最高分”的方案都不得直接隔离内容。语义模型继续旁路；
它的高风险事件最多把同一次运行中后续改写类动作升级为人工审批，不能批准、放行或降低硬规则
风险。高风险动作仍由确定性授权和人工审批保护。

## Non-goals

- 不把 ContextForge 或其他通用 MCP 网关整套搬进来替换现有安全控制面；
- 不自研身份平台、密钥库、策略语言、容器运行时、遥测协议或数据库高可用系统；
- 不把静态文本检出率写成真实攻击阻断率；
- 不因为本地固定检查全部通过就宣称生产可用；
- 不让模型批准、放行或推翻硬规则；
- 不把密钥交给 Agent、模型、评测进程或普通日志系统。

## Prerequisites

- 一个隔离的 Kubernetes 预生产命名空间，以及真实入口网关和企业 OIDC 测试租户；
- 企业可用的 PostgreSQL、Redis、OpenBao、对象锁存储和遥测后端；
- 私有镜像仓库、签名身份和 Kubernetes 镜像准入权限；
- 管理员在模型厂商页面接受所需许可证，并把审查后的模型权重放入受信本地挂载；
- 一组从未用于写规则、选模型或调阈值的中英文攻击和正常难例；
- 预生产工具只能使用专用测试账号、金额上限和可回滚资源。

## Reuse Strategy

| 能力 | 直接复用 | 本项目只实现 | 不做 |
| --- | --- | --- | --- |
| MCP 协议 | 官方 MCP Python SDK | 安全门禁、版本快照和审计适配 | 自写第二套 JSON-RPC |
| 策略 | OPA 签名 bundle、Status API | 本地规则只能被收紧的合并合同 | 自研策略解释器 |
| 凭据 | OpenBao KV v2、Transit、Proxy | `credential_ref`、授权和固定目标注入 | 让 Agent 读取真实密钥 |
| 工具隔离 | ToolHive 权限模板和来源校验 | 风险分级、允许的启动参数和运行后对账 | 自研容器沙箱 |
| 身份 | 企业 OIDC、短期工作负载令牌 | 主体映射、项目成员关系和 scope 检查 | 自建员工账号系统 |
| 镜像准入 | Cosign/Sigstore policy-controller | 发布清单和批准的签名者策略 | 只检查标签或摘要 |
| 遥测 | OpenTelemetry Collector | 固定低基数字段和正文/密钥禁止合同 | 自建追踪协议 |
| Agent 评测 | Inspect AI、AgentDojo、BIPIA、InjecAgent、LLMail | 固定版本、网关适配、汇总报告和副作用哨兵 | 用公开集反复调参后称盲测 |
| 负载与故障 | k6、Toxiproxy 或 Chaos Mesh | Agent/MCP 场景、验收阈值和证据报告 | 自研通用压测/混沌平台 |
| 依赖漏洞 | Google OSV-Scanner、pip-audit、npm audit | 固定锁文件、零原文聚合证据和发布过期检查 | 自建漏洞数据库 |
| 数据高可用 | 托管 PostgreSQL/Redis，或目标环境已有方案 | 业务状态恢复和幂等合同 | 在本项目 Chart 内运维数据库集群 |

## Sprint 0: 冻结当前证据和发布基线

**Goal**: 让后续每个优化都有可比较、不可覆盖、不会泄密的基线。

**Demo/Validation**:

- 固定发布入口全绿，并明确保留 10 项外部门槛；
- BIPIA 首次结果、淘汰模型和长文本分窗负面结果均能离线验真；
- 报告不保存样本文本、逐条分数、环境变量或命令输出。

### Task 0.1: 纳入长文本分窗负面证据

- **Location**: `scripts/verify_bipia_static_artifact.py`、
  `scripts/run_release_verification.py`、`tests/test_release_verification.py`
- **Description**: 固定分窗探针和阈值校准报告的 SHA-256、来源提交、实现摘要及汇总计数。
- **Dependencies**: 无。
- **Acceptance Criteria**:
  - 任一报告、来源锁或当前被评测实现被修改时验证失败；
  - 明确记录“未进入生产”，且不能被解释为新盲测。
- **Validation**: 定向单测、离线证据验证、完整发布验证。

### Task 0.2: 更新事实文档

- **Location**: `README.md`、`CHANGELOG.md`、`specs/bipia-static-holdout-v1.md`、
  `specs/semantic-scanner-v1.md`、`docs/open-source-migration-status.md`
- **Description**: 写入分窗提高召回但扩大误报和延迟的结论，保留模型旁路决定。
- **Dependencies**: Task 0.1。
- **Acceptance Criteria**: 文档中的测试数、报告摘要和发布验证结果与最新运行一致。
- **Validation**: 全量测试、静态检查和 `git diff --check`。

## Sprint 1: 检测能力 v2，但不改变授权权力

**Goal**: 提高未知攻击发现能力，同时不让不可靠模型决定真实动作。

**Demo/Validation**:

- 同一批脱敏外部内容可旁路比较现有模型和候选模型；
- 模型故障、超时和误判均不能让未授权写操作执行；
- 只有未参与调参的新保留集可用于晋级决策。

### Task 1.1: 把语义后端改成可插拔候选接口

- **Location**: `src/agentops_guard/semantic_service/`、
  `src/agentops_guard/backend/services/semantic_scanner.py`、`tests/test_semantic_scanner.py`
- **Description**: 保留统一的本地离线模型合同，允许按摘要选择候选，但一次请求只发送同一个已脱敏
  副本；候选标识、时延和离散判断只保存在内部汇总。
- **Dependencies**: Sprint 0。
- **Acceptance Criteria**:
  - 不接受远程模型 ID、运行时下载或 `trust_remote_code`；
  - Gateway 不挂载模型权重；模型服务收不到凭据引用、URL、工具参数和完整策略上下文；
  - `enforce` 继续由配置、Helm 和运行时三层拒绝。
- **Validation**: 权重摘要漂移、断网加载、输入脱敏、超时、OOM 和并发负向测试。

### Task 1.2: 评测 Prompt Guard 2 86M 候选

- **Location**: `evals/` 来源锁、`scripts/benchmark_*_model_candidate.py`、
  `artifacts/benchmarks/`
- **Description**: 管理员接受许可证并提供本地权重后，按官方 512-token 分段思想建立独立候选适配；
  不直接复制外部推理脚本进入生产，只复用经审查的算法和许可证允许的部分。
- **Dependencies**: Task 1.1、管理员提供权重。
- **Acceptance Criteria**:
  - 模型、tokenizer、配置和清单逐文件固定摘要；
  - 在未见中英文保留集上，高风险攻击召回不低于 `90%`，正常难例误报不高于 `1%`；
  - 分语言、来源、攻击类型报告，不允许只报总平均；
  - p95 满足旁路预算；如果未来进入同步升级路径，再单独满足同步时限。
- **Validation**: 首次不可覆盖报告、重复运行摘要一致、故意换文件验证失败。

### Task 1.3: 建立来源和数据流标记

- **Location**: `src/agentops_guard/backend/services/content_provenance.py`、Gateway MCP 适配层、
  现有 `ContentObject.metadata_json` 和 `specs/content-provenance-v1.md`。
- **Description**: 给每段进入 Agent 的内容标记来源、信任级别、父内容、解码方式和经过的变换；
  外部内容在拼接、摘要和工具返回后仍保留“不可信”属性。
- **Dependencies**: Sprint 0。
- **Acceptance Criteria**:
  - 不可信内容不能仅因被工具包装或摘要就升级为可信指令；
  - 标记只保存枚举和摘要，不保存密钥或原文副本；
  - 新来源未登记时默认按外部不可信处理。
- **Validation**: 跨工具传递、摘要、Base64/Unicode 变形、错误正文和嵌套资源的传播测试。
- **Current progress**: Gateway 已为工具说明、结果、资源和提示生成统一标记，递归删除上游伪造的
  `io.agentops/*` 元数据，将标记保存在脱敏内容记录，并证明未知或混合父来源不能被洗成可信。
  来源片段、变换和父引用已有硬上限；真实 Qwen v6 回归把来源标记、带签名分页、保护资源模板和受限 Agent 读取边界一并纳入
  23 个实现摘要。第三方 Agent Harness 内部摘要/拼接的自动传播仍需单独适配。

### Task 1.4: 建立真正未见的动态攻击集

- **Location**: 新增 `evals/holdouts/manifest.json`、`tests/system/agent_security/`、
  `specs/unknown-attack-eval-v1.md`
- **Description**: 从公开集保留未见家族，再由独立人员或隔离脚本生成中文变体；题目在首次运行前
  只保存来源摘要和规模，规则/模型开发者不看正文。
- **Dependencies**: Task 1.3。
- **Acceptance Criteria**:
  - 训练、调参、已知回归和首次未见集四类严格分开；
  - 首次运行后自动改标为回归集；
  - 报告包括未授权动作实际执行率、正常任务完成率和误审批率，而不只是文本命中率。
- **Validation**: 清单状态机测试、数据重用检测、真实上游副作用哨兵。
- **Current progress**: 聚合式清单、四类数据隔离、语料摘要去重、冻结系统摘要校验、文件锁和
  单向状态机已实现并进入发布核验。领取时在读取正文前立即降级为回归；成功、失败、中断或缺少
  聚合报告都不能恢复盲测身份。InjecAgent 1,054 条英文官方 `base` 工具响应已完成首次静态运行，
  联合检出 54.74%；真实上游哨兵已有 AgentDojo 微型回归证据。新的独立中英文动态语料尚未交付，
  因此未知攻击 Agent 端到端任务仍未完成。

## Sprint 2: 真实企业身份和 Kubernetes 运行边界

**Goal**: 证明应用不是只在本机配置上安全，而是在真实集群里也不能绕过身份和网络边界。

**Demo/Validation**:

- 企业员工和工作负载都使用短期、已验签身份；
- 未签名镜像、越权 ServiceAccount 和绕过入口的请求不能运行；
- NetworkPolicy 实际阻断不允许的连接。

### Task 2.1: 接入真实企业 OIDC

- **Location**: `src/agentops_guard/backend/services/oidc.py`、Helm values、
  `docs/deployment.md`、身份合同测试。
- **Description**: 接真实 Entra ID、Okta、Keycloak 或企业现有 IdP；人员身份、Agent 身份和 Worker
  身份使用不同 audience/scope，项目权限仍由服务端成员关系决定。
- **Dependencies**: 企业测试租户。
- **Acceptance Criteria**: 错 issuer、audience、签名、scope、过期时间、跨项目和被吊销身份全部拒绝。
- **Validation**: 对真实 IdP 的正向/负向集成测试；本地模拟器不能清除此门槛。
- **Current status**: 已固定并真实运行 Keycloak `26.7.3` 和 Temurin JRE `21.0.12.1+1`，完成
  发现文档、工作负载令牌、项目/Agent/scope 绑定、错误 issuer/audience、篡改签名、签名密钥轮换
  与客户端停用检查。客户端停用会阻止新令牌，但停用前签发的 60 秒离线 JWT 仍会通过本地验签；
  企业 TLS、人员目录/联邦、生产数据库、HA、入口可信转发与即时撤销仍未验证，因此本任务未完成。

### Task 2.2: 在真实 Kubernetes 验证隔离

- **Location**: `deploy/helm/agentops-guard/`、`tests/system/kubernetes/`
- **Description**: 启用 Pod Security Admission、最小 RBAC、NetworkPolicy、只读根目录、非 root、
  禁止提权和资源限额；逐项探测 API、Gateway、Worker、OPA、模型服务与 OpenBao Proxy 的连通关系。
- **Dependencies**: Task 2.1、预生产集群。
- **Acceptance Criteria**:
  - 未列出的东西向和所有不必要出站连接都失败；
  - 模型服务不能访问 OpenBao、数据库、互联网或宿主目录；
  - Dashboard、Agent 和 Gateway 不具备凭据解密权限。
- **Validation**: 集群内网络探针、越权 Pod、错误 ServiceAccount 和策略删除演练。
- **Current status**: 生产 Helm 已使用 Kubernetes 原生 `NetworkPolicy` 实现命名空间全部入口/出口
  默认拒绝，再分别放行入口控制器到 Gateway/Dashboard、Dashboard/Gateway 到 API，以及启用时的 OPA/
  小模型调用。数据库、Redis、OIDC、MCP 上游、OpenBao、对象锁和遥测等外联必须按工作负载声明
  非空目标与精确端口；全地址 CIDR、空选择器、端口范围、未知工作负载会在渲染时拒绝。迁移 Job
  已补稳定 Pod 标签。所有进程使用独立无 RBAC ServiceAccount 并关闭 Kubernetes API 令牌自动
  挂载。真实 Kubernetes `1.34.0` + kindnet 已直接应用项目渲染的 11 条策略，`23/23` 条基线探针、
  `11/11` 条逐策略删除/恢复检查以及 `restricted:v1.34` 对特权 Pod 的拒绝全部通过。该证据关闭了
  本地数据平面与内置 Pod Security 子门槛；生产 CNI、实际环境外联、云工作负载身份、宿主目录隔离
  和错误 ServiceAccount 的目标平台演练仍未完成。

### Task 2.3: 镜像签名准入

- **Location**: `.github/workflows/supply-chain.yml`、Helm 发布清单、
  新增 `deploy/admission/`
- **Description**: 复用 Cosign 生成签名/证明，使用 Sigstore policy-controller 按批准身份验证镜像。
- **Dependencies**: 私有镜像仓库、Task 2.2。
- **Acceptance Criteria**: 正确摘要但错误签名者、无签名、签名后改镜像、测试仓库冒名均拒绝部署。
- **Validation**: 真实准入正负测试，保存签名者身份、镜像摘要和策略版本，不保存仓库凭据。
- **Current status**: 已直接复用 Sigstore `policy.sigstore.dev/v1beta1` `ClusterImagePolicy`，生产
  Helm 强制 `enforce`、具体镜像仓库范围、无凭据 HTTPS issuer、精确非通配 subject、Rekor 和
  管理员托管 `TrustRoot`；关闭验证、警告模式、空身份、通配身份和全局 glob 会在渲染阶段失败。
  官方 chart `0.10.7` 覆盖为摘要固定的 controller `0.15.1`，双副本、`failurePolicy: Fail` 且未匹配
  即拒绝。真实 kind 已证明官方旧版明确拒绝匹配无签名镜像，以及新版信任根 Ready、全副本停止时
  拒绝、20.442 秒恢复 2/2 和仓库不可达时拒绝；仍缺可达私有仓库、正确签名放行、错签名者、签名后
  变更、冒名仓库拒绝及生产复验，因此本任务未完成。

## Sprint 3: 生产策略、凭据和审计基础设施

**Goal**: 把已经通过的本地子系统测试升级为企业基础设施上的可恢复运行证据。

**Demo/Validation**:

- OPA 能从远程取得签名策略，坏包不会替换上一版；
- OpenBao 节点切换、证书轮换和备份恢复后 `credential_ref` 仍可工作；
- 数据库管理员也不能悄悄改写或删除已经外部锚定的审计历史。

### Task 3.1: 远程 OPA 签名 bundle

- **Location**: `deploy/helm/agentops-guard/templates/configmap-opa.yaml`、
  策略发布工作流、`scripts/verify_opa_runtime.py`
- **Description**: 复用 OPA Bundle Service、签名验证和 Status API；签名私钥只在发布身份可见，
  运行端只有公钥。
- **Dependencies**: Sprint 2。
- **Acceptance Criteria**: 新包只有签名、scope、内容和 Rego 测试均通过才激活；失败继续使用上一版并告警。
- **Validation**: 错误签名、内容篡改、服务中断、合法旧版本回滚和多副本版本一致性测试。OPA 官方
  明确说明签名 `iat` 只作展示，不参与验证，因此不得把它写成原生过期门禁。
- **Current local evidence**: 已用固定 SHA-256 的官方 OPA `1.20.1` Linux/amd64 二进制真实完成远程签名 v1 加载、签名
  v2 热更新、两个实例分别上报状态、篡改包拒绝、发布端 `503` 时共同保留上一好版本，以及一个
  实例在断网期间重启后从持久化缓存恢复 v2。恢复联网后两个实例均重新健康并使用上一成功 ETag。
  生产 Helm 现要求精确批准的策略版本，API、Gateway 和 Worker 会把不同版本视为 OPA 不可用，
  从而拒绝合法旧包静默回滚。另有固定摘要 OPA `1.8.0` 官方容器覆盖非 root、只读根、最小权限及
  故障关闭。尚缺签名验证的 `1.20.1` 生产镜像、TLS/工作负载身份、企业密钥托管和生产集群复验，
  因此任务与生产门槛仍未完成。详见 `specs/opa-remote-bundle-runtime-v1.md`。

### Task 3.2: OpenBao TLS、高可用和恢复

- **Location**: `deploy/openbao/` 参考配置、运行手册、`scripts/verify_openbao_*.py`
- **Description**: 优先接企业现有 OpenBao；否则由平台层部署 3/5 节点 Raft、TLS、自动解封、
  审计输出、快照和短期工作负载认证，本项目不把集群运维塞进应用 Chart。
- **Dependencies**: 企业 KMS/HSM 或批准的解封服务、Sprint 2。
- **Acceptance Criteria**: 主节点故障、证书轮换和隔离恢复后 API/审计出口继续按最小权限工作；
  删除身份后立即失效；应用始终拿不到 OpenBao Token。
- **Validation**: 封印、切主、快照恢复、权限越界和 Proxy 轮换演练。
- **Current local evidence**: 已直接复用 OpenBao `2.6.1` Integrated Storage、TLS、Proxy 和快照
  接口，三个真实进程组成三个投票成员。终止当前主节点后，剩余多数派选出新主节点；重新指向新
  主节点的 Proxy 仍能解析原 `credential_ref` 并使用原不可导出 Transit 密钥。恢复快照后，快照前
  凭据保留、快照后标记消失。根令牌、解封份额、发放令牌和提供方密钥只在受信验证进程内存中
  使用。三个节点还使用同一临时测试 CA 签发的不同叶证书，并按备用节点优先、主节点最后的顺序
  通过 SIGHUP 不重启换证；真实 TLS 指纹均改变、进程号保持不变，换证期间原凭据和签名持续可用。
  尚缺企业 PKI 自动签发、CA 信任轮换、双向 TLS、KMS/HSM 自动解封、五节点跨故障域、负载均衡
  器无感切换及持续压力下故障注入，因此任务与生产门槛仍未完成。详见
  `specs/openbao-raft-ha-runtime-v1.md`。
  当前主机运行时另已按 OpenBao 官方发布流程的准确签名身份和签发方验证校验清单与归档两份
  Sigstore 证明；安装二进制与签名归档一致，两个单字节篡改反例均拒绝。该结果不代替生产镜像
  签名，详见 `specs/openbao-signed-runtime-provenance-v1.md`。

### Task 3.3: 外部只追加审计封条

- **Location**: `src/agentops_guard/backend/services/audit_anchors.py`、
  `src/agentops_guard/backend/services/audit_checkpoints.py`、Helm exporter。
- **Description**: 使用企业对象锁桶和云工作负载身份，把经 OpenBao Transit 签名的链头写入
  COMPLIANCE 保留对象，并从同一版本读回核对。
- **Dependencies**: Task 3.2、企业对象存储。
- **Acceptance Criteria**: 保留期内无法删除、覆盖或缩短；数据库整体回滚能被外部封条发现。
- **Validation**: 真实删除拒绝、版本回滚、替换公钥、断链和跨权限域测试。
- **Current local evidence**: 摘要与 Minisign 固定的 MinIO
  `RELEASE.2025-09-07T16-13-09Z` 已真实运行生产 `S3ObjectLockSink`：版本控制和 Object Lock 开启，
  同一封条重复条件写只保留原版本，精确版本回读一致，临时管理员不能删除 `COMPLIANCE` 版本或
  缩短保留期。凭据只在验证进程内生成且不进入参数、日志或报告。该 MinIO 社区二进制已停止维护，
  只证明 S3 协议行为；企业外部服务、TLS、工作负载身份、多节点耐久性和整库回滚告警仍未完成。
  详见 `specs/minio-object-lock-runtime-v1.md`。

## Sprint 4: 可观察、可恢复和可承压

**Goal**: 用故障和容量数据证明系统在压力下仍不越权、不丢状态、不泄密。

**Demo/Validation**:

- 2 倍峰值持续 30 分钟，AgentOps 自身错误率低于 `0.1%`，审计缺口为 `0`；
- PostgreSQL RPO 不超过 5 分钟、RTO 不超过 30 分钟；
- 关键依赖中断都有预定的拒绝、暂停、降级或恢复行为。

### Task 4.1: 接通真实 Collector 和后端

- **Location**: `deploy/otel-collector.yaml`、Helm、遥测合同测试。
- **Description**: 启用内存保护、批处理、发送队列、重试和按环境选择的持久队列；导出到企业
  Prometheus/Tempo/Loki 或同类平台。
- **Dependencies**: Sprint 2。
- **Acceptance Criteria**: 看板能关联 Run/Trace/Event/Approval/Execution；字段中没有正文、动态 URL、
  查询、头、工具参数、凭据或高基数用户输入。
- **Validation**: Collector/后端中断、队列填满、Collector 重启和敏感标记全链搜索。
- **Current local evidence**: 固定归档和二进制 SHA-256 的官方 Collector Contrib `0.160.0`
  已真实接收 OTLP；下游关闭时把待发 trace 写入 `file_storage` 队列，进程终止并重启后向新启动的
  本地 OTLP 后端补发。随机请求路径、查询、头和正文标记不在恢复后的 protobuf 中，固定路由模板
  与组件名存在。固定 Cosign `3.1.2` 已按精确身份、签发方和透明日志证明验证自身及 Collector
  发布归档，并拒绝单字节篡改；该结论不等于生产镜像验签。生产容器/PV、企业后端、队列填满和
  告警仍未验证，因此任务与生产门槛仍未完成。详见 `specs/otelcol-resilience-runtime-v1.md` 和
  `specs/signed-runtime-provenance-v1.md`。

### Task 4.2: PostgreSQL/Redis 真实切换和恢复

- **Location**: `tests/faults/`、`scripts/verify_operational_resilience.py`、运维手册。
- **Description**: 在目标托管服务或平台标准集群上测试数据库切主、备份恢复、Redis 整体重建、
  RQ 积压和 Worker 滚动升级。
- **Dependencies**: 企业数据服务。
- **Acceptance Criteria**: 任务不静默丢失；可重试动作不重复；不可幂等且结果未知的动作不自动重试。
- **Validation**: 每个故障保存时间线、业务状态前后快照和汇总结果。
- **Current local evidence**: 已直接复用 PostgreSQL 16 的 `pg_basebackup`、物理复制槽、同步流复制和
  `pg_promote()` 建立两节点受控演练；另直接复用 Patroni `4.1.4` 官方 Kubernetes 三节点方案完成
  自动切主演练。两个备库确认追平后强制终止主库 Pod，固定 Service 约 `3.821s` 恢复查询，约
  `13.106s` 后恢复一主两备；旧主 Pod 身份被替换并以备库加入。又直接复用 Toxiproxy `2.12.0`
  和公开 Jepsen 的单主检查，保持数据库路径可用并仅切断主库到 DCS 的连接；旧主停止写入，全程
  最多一个可写主库，固定入口约 `23.912s` 恢复，约 `28.914s` 解除隔离并恢复完整拓扑。审批、
  后台任务和审计链保持一致并能继续写入。它仍是单机临时集群，未验证持久卷、硬件看门狗/节点
  隔离、任意主机分区、数据库 TLS、跨可用区和生产数据规模，因此 Task 4.2 仍未完成。详见
  `specs/postgres-streaming-failover-v1.md` 和 `specs/patroni-kubernetes-failover-v1.md`。

### Task 4.3: 容量和故障矩阵

- **Location**: `tests/load/`、`tests/faults/`、`specs/failure-mode-matrix-v1.md`
- **Description**: 用 k6 生成 MCP/审批/恢复流量，用 Toxiproxy 或 Chaos Mesh 注入网络、延迟、丢包、
  进程退出和资源耗尽。
- **Dependencies**: Tasks 4.1–4.2。
- **Acceptance Criteria**:
  - 小模型不在同步放行链时，Gateway 自增 p95 小于 `100ms`、p99 小于 `250ms`；
  - 满载时不突破每上游并发上限；
  - OPA/OpenBao/数据库不可用时高风险动作绝不自动放行；
  - 滚动升级期间没有审计空洞。
- **Validation**: 30 分钟稳态、突发流量、单点终止和整依赖中断报告。

## Sprint 5: 真实 Agent 未见攻击端到端验收

**Goal**: 证明“发现能力”和“真正不让坏事发生”是两套独立且同时可量化的结果。

**Demo/Validation**:

- 真实模型读取恶意邮件、表格、代码或工具结果后作出工具选择；
- Gateway 走真实身份、策略、审批、凭据注入和隔离上游；
- 报告实际副作用，而不是只看字符串分类。

### Task 5.1: 完整 Agent 评测流水线

- **Location**: `evals/inspect/`、`tests/system/agent_security/`、
  `scripts/run_*_agent_eval.py`
- **Description**: 复用 Inspect AI 组织 Agent 轨迹；优先适配 AgentDojo/BIPIA 场景，LLMail 继续保留
  静态基准角色；所有工具对专用测试资源执行并带副作用哨兵。
- **Dependencies**: Sprint 1 和 Sprint 3。
- **Acceptance Criteria**:
  - 设计范围内未授权高风险动作实际执行数为 `0`；
  - 正常任务完成率相对无网关基线下降不超过 2 个百分点；
  - 分别报告攻击诱导率、规则命中、模型命中、审批率、真实阻断率、误审批率和新增延迟。
- **Validation**: 固定 Agent/模型/工具/策略/数据版本的不可覆盖报告；上游调用日志只保存事件号和结果枚举。

### Task 5.2: 模型晋级评审

- **Location**: `specs/semantic-scanner-v2.md`、配置门禁、Helm schema、发布检查。
- **Description**: 只有 Task 1.2 和 Task 5.1 同时达标，才讨论让模型把外部内容“升级到审批”；
  模型仍不能批准、放行或降低硬规则风险。
- **Dependencies**: Tasks 1.2、5.1。
- **Acceptance Criteria**:
  - 新盲测召回与误报达标；
  - 线上影子流量至少覆盖一个完整业务周期且无超预算误报；
  - 回滚到纯规则/确定性授权只需配置变更，不需数据迁移。
- **Validation**: 三层门禁负向测试、旁路差异报告和回滚演练。

## Sprint 6: 供应链闭环和受控灰度

**Goal**: 让同一份经过验证的源码、依赖、策略、模型和镜像进入预生产及生产，并可安全回退。

**Demo/Validation**:

- CI 在线审计、SBOM、镜像扫描、签名和证明全部通过；
- 集群只接受批准签名者的摘要镜像；
- 按只读、可撤销写、不可逆写逐级放量。

### Task 6.1: 完成供应链工作流

- **Location**: `.github/workflows/ci.yml`、`.github/workflows/supply-chain.yml`
- **Description**: 固定 Actions、依赖和构建器；生成 Python/Dashboard SBOM，执行漏洞扫描，签名镜像，
  产生源码提交到镜像摘要的证明。
- **Dependencies**: Task 2.3。
- **Acceptance Criteria**: 任何被忽略的失败、未固定 Action、严重未处理漏洞、签名或证明缺失均阻止发布。
- **Validation**: 真实在线工作流成功记录和故意篡改的失败演练。
- **Current**: 当前两份锁文件已由 OSV 真实在线复扫为零发现，生产 npm 审计也为零；官方 OSV
  reusable workflow 已固定到具体提交，且本地发布检查会拒绝过期证据。默认分支发布 Job 已直接
  复用并锁定 Docker Buildx、Aqua Trivy 和 Sigstore Cosign：两套镜像只发布提交标签，BuildKit
  的客户端可执行文件与 daemon 镜像分别按摘要锁定且禁用不安全构建权限，再附加 SLSA 来源证明；
  另行按 SHA-256 锁定的 Trivy 生成 CycloneDX 并扫描精确摘要；通过全部依赖
  与镜像门禁后，独立且不检出项目代码的签名 Job 才获得短期 GitHub OIDC 身份，并用摘要固定的
  Cosign 签署证明、SBOM 和镜像后按精确工作流身份复验；构建/扫描阶段没有签名权限。当前只
  完成工作流实现与本地静态验证，尚无 GitHub 托管成功记录、私有仓库镜像摘要或真实签名证明，
  因此 Task 6.1 仍是进行中。

### Task 6.2: 四阶段灰度

- **Location**: `docs/deployment.md`、发布清单、租户开关和回滚手册。
- **Description**:
  1. 只读影子流量；
  2. 低风险只读工具；
  3. 支持幂等和补偿的写工具；
  4. 付款、生产权限和不可逆删除专项开放。
- **Dependencies**: Sprints 2–5。
- **Acceptance Criteria**: 每阶段至少观察一个完整业务周期；身份、审计、恢复或误审批超阈值立即回退。
- **Validation**: 发布/回滚演练、租户隔离测试、告警和值班手册走查。

## Testing Strategy

- **单元测试**: 归一化、来源传播、权限、策略合并、状态机、摘要和脱敏。
- **合同测试**: MCP 多版本、OIDC、OPA Bundle、OpenBao Proxy、Collector、对象存储和模型服务。
- **负向测试**: 伪造身份、偷换参数、换工具/策略、重复审批、错误签名、密钥标记和越权网络。
- **真实子系统测试**: PostgreSQL、Redis/RQ、OPA、OpenBao、ToolHive、Collector 和 Kubernetes。
- **Agent 端到端测试**: 原始要求到实际上游副作用，全程报告而不保存攻击正文或密钥。
- **容量/混沌测试**: 2 倍峰值、30 分钟、切主、网络故障、OOM、滚动升级和上游响应丢失。
- **发布验证**: 每次生成新报告，不覆盖历史；本地通过仍保留未完成的外部门槛。

## Release Gates

只有以下 10 项都被真实环境证据清除，项目才可称为“企业级受控生产候选”：

1. 真实企业 OIDC；
2. 完整 Sigstore 镜像正反准入及生产 webhook 故障关闭；
3. 生产 OPA 远程签名 bundle 与当前稳定运行时；
4. 生产 Collector 导出和企业后端；
5. 生产 OpenBao Proxy 交付、TLS 与高可用；
6. 私有仓库签名镜像；
7. 成功的供应链工作流和在线漏洞审计；
8. 外部只追加审计封条存储；
9. 生产规模负载和故障切换；
10. 未见攻击的真实 Agent 端到端评测。

即使全部通过，“企业级”也应限定为已验证的单地域、指定身份平台、指定工具类型和目标流量，
不能自然外推为多地域双活、金融级支付或任意 MCP 服务安全。

## Potential Risks & Gotchas

- **最大风险不是漏一条规则，而是把检测当授权。** 缓解：模型只能增加风险，硬规则和原始要求
  对齐始终拥有最终否决权。
- **公开集会被调参污染。** 缓解：首次运行后自动转回归，另留由不同人员保管的新保留集。
- **长文本分窗会放大误报和延迟。** 缓解：不直接进入生产；先比较池化、分段校准和不同模型，
  但所有方案都必须用新保留集评审。
- **真实企业基础设施受账号和审批限制。** 缓解：本地/模拟测试继续保留，但绝不替代对应外部门槛。
- **外部组件升级可能改变安全语义。** 缓解：固定版本/摘要，升级先跑合同、故障和负向测试。
- **遥测“方便排错”容易重新带回正文。** 缓解：只允许固定字段白名单，并在真实后端搜索专用敏感标记。
- **上游不支持幂等或结果查询。** 缓解：不可逆动作出现结果未知后禁止自动重试，只允许人工对账。
- **签名镜像不等于安全镜像。** 缓解：签名身份、源码证明、SBOM、漏洞扫描和准入缺一不可。

## Rollback Plan

- 语义模型始终可退回 `shadow` 或 `disabled`，不改变确定性授权和历史记录；
- OPA 新 bundle 激活失败时继续使用上一已验证版本，中高风险请求保持转审批；
- 应用使用向后兼容数据库迁移，回滚前停止新写入并确认旧版本理解当前状态；
- 镜像按摘要部署，保留上一批准摘要和签名证明；
- 灰度按租户和工具风险级别回退，不直接全局开放或全局切换；
- 任何身份、审计、密钥或重复副作用异常立即停止写操作，只保留必要的只读查询和人工处置。

## Definition of Done

完成后可以准确描述为：

> AgentOps Guard 是部署在企业入口之后的 Agent/MCP 安全治理层。它用可信身份、来源标记和不可变
> 版本固定每次工具调用，用原始用户要求对动作和目标做确定性授权，对高风险副作用实施可恢复的
> 人工审批；Agent 只持有 credential_ref，凭据由 OpenBao 支撑的受信执行组件在固定目标最后一跳
> 注入；系统通过签名策略、隔离工具、外部审计封条、供应链准入、真实故障演练和未见攻击端到端
> 评测证明指定范围内的受控生产能力。

如果只完成代码和本地子系统测试，应继续称为“企业级架构原型”或“受控生产候选基础”，不得称为
“已经企业级投产”。

## Primary References

- OPA signed bundles: <https://www.openpolicyagent.org/docs/management-bundles>
- OpenTelemetry Collector resiliency: <https://opentelemetry.io/docs/collector/resiliency/>
- Sigstore policy-controller: <https://docs.sigstore.dev/policy-controller/overview/>
- OpenBao Kubernetes deployment: <https://openbao.org/docs/platform/k8s/helm/run/>
- MCP authorization: <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>
- OWASP AI Agent Security Cheat Sheet:
  <https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html>
