# AgentOps Guard 需求分析文档

**生成日期**: 2026-05-08  
**目标阶段**: 从可运行 v1 scaffold 迈向完整工程化产品  
**适用范围**: 后端 API、MCP Gateway、Python SDK、Next.js Dashboard、测试、部署与运维体系

## 1. 项目定位

AgentOps Guard 是一个自托管 Agent 运行治理平台，面向 MCP 与 Python Agent 场景，提供追踪采集、风险扫描、策略决策、回放评估、MCP 网关与可视化控制台能力。当前仓库已经具备 FastAPI 后端、SQLAlchemy 存储、SDK/CLI、MCP Gateway、Next.js Dashboard、单元测试与 E2E 用例，处于“可运行 v1 雏形”阶段。

下一阶段目标不是继续堆叠 Demo 功能，而是把系统升级为可集成、可扩展、可观测、可审计、可部署、可持续演进的 AgentOps/SecOps 工程内核。

## 2. 现状盘点

### 2.1 后端 API

后端位于 `src/agentops_guard/backend`，采用 FastAPI + SQLAlchemy：

- `main.py`: 创建 API 应用、CORS、中间件与全局 API Key 依赖。
- `routes.py`: 承载 `/v1` 下大部分接口，包括 Run、Event、Content、Policy、Scanner、Risk、Replay、Eval、MCP Registry、System Status。
- `models.py`: 定义 Project、Agent、Run、TraceEvent、ContentObject、PolicyDecision、RiskEvent、McpServer、McpTool、EvalSuite、EvalRun、ReplayRun 等实体。
- `schemas.py`: 定义 API 输入输出契约。
- `services`: 拆分内容脱敏、扫描、策略、回放、评估、项目创建、DAG 构建等业务逻辑。

已具备能力：

- 系统状态: `/v1/health`, `/v1/system/status`。
- Trace: 创建/更新/查询 run，批量写入事件，查询事件和 DAG。
- 内容安全: 内容对象哈希、摘要、脱敏、按配置控制 raw content 存储。
- Policy: 内置规则决策，可选 OPA 调用，持久化策略决策。
- Scanner: Prompt injection、凭据泄露、工具劫持、隐藏 HTML/Markdown trap、Base64 混淆检测。
- Risk: 风险事件查询。
- Replay/Eval: 基于历史 run 与 YAML/JSON case 的回放和回归评估。
- MCP Registry: MCP server CRUD 与工具缓存查询。

### 2.2 MCP Gateway

Gateway 位于 `src/agentops_guard/gateway/app.py`：

- 提供 MCP 风格端点：`/tools/list`, `/tools/call`, `/resources/list`, `/resources/read`, `/prompts/list`, `/prompts/get`。
- 从数据库读取 MCP server registry。
- 对工具描述、工具参数、工具输出、resource/prompt 内容执行扫描与策略检查。
- 支持 `streamable_http` 远端转发；`stdio` 当前主要是 echo/demo 形态。

### 2.3 Python SDK 与 CLI

SDK 位于 `src/agentops_guard/sdk`：

- `client.py`: 封装 create run、update run、record events、evaluate policy、scan 等 HTTP 调用。
- `tracing.py`: 基于 context manager 记录 run、model call、tool call、handoff、policy decision、error 等事件。

CLI 位于 `src/agentops_guard/cli.py`：

- 启动 API 与 Gateway。
- 加载 MCP 配置。
- 运行 eval YAML/JSON 文件。

### 2.4 Dashboard

Dashboard 位于 `dashboard`，采用 Next.js：

- 页面: Overview、Setup、Runs、Run Detail、Risks、Scanner、Policy、Replay Studio、Eval Studio、MCP Manager。
- API 代理: `app/api/backend/[...path]/route.ts` 与 `app/api/gateway/[...path]/route.ts`。
- 组件: `ScannerForm`, `PolicyForm`, `ReplayStudio`, `EvalStudio`, `McpManager`, `RunsFilter`, `RunDagView`, `SetupStatus` 等。
- 测试: Vitest payload helper 单测，Playwright 覆盖主要控制台验收场景。

### 2.5 测试、部署与文档

已有基础：

- Python: `uv` 管理环境，`pytest`, `pytest-cov`, `ruff`。
- Frontend: `vitest`, `playwright`, `next build`。
- 部署: Dockerfile 与 docker-compose，包含 API、Gateway、Postgres、Redis。
- 文档: README、API contracts、Dashboard spec。

主要不足：

- Alembic migration 当前是 placeholder，生产 schema 生命周期不足。
- `routes.py` 聚合过多职责，后续维护成本会快速上升。
- 鉴权停留在单 API Key，缺少组织/项目/角色/密钥轮换。
- MCP `stdio` 尚未真实进程管理，网关可用性与隔离不足。
- 缺少异步任务队列，Replay/Eval/扫描在规模化后会阻塞请求路径。
- 缺少 OpenTelemetry、结构化日志、指标、审计日志与告警。
- Dashboard 以功能验证为主，缺少权限、分页、错误恢复、实时刷新等生产体验。

## 3. 用户与角色

| 角色 | 目标 | 典型行为 |
| --- | --- | --- |
| Agent 开发者 | 快速接入 SDK，定位 Agent 运行问题 | 埋点、查看 run/event/DAG、重放问题 case |
| 安全工程师 | 识别 prompt injection、工具滥用和数据外泄 | 配置策略、审查风险、隔离 MCP 工具 |
| 平台/SRE | 自托管部署、观测服务健康、容量规划 | 配置数据库、查看指标、追踪错误、升级版本 |
| 评测负责人 | 管理回归评测与红队用例 | 创建 eval suite、运行评测、比较结果趋势 |
| 管理员 | 管理项目、密钥、权限和保留策略 | 创建项目、配置 RBAC、轮换密钥、导出审计 |

## 4. 核心业务流程

### 4.1 Agent 追踪接入

1. 用户安装 Python 包并配置 API URL 与 API Key。
2. SDK 创建 run，并在 Agent 执行期间记录 model/tool/handoff/error/policy 事件。
3. 后端持久化 run、event、content object、risk event。
4. Dashboard 展示 run 列表、事件 DAG、风险标签与关联内容。

### 4.2 内容安全扫描

1. 用户或网关提交不可信文本。
2. Scanner 识别指令覆盖、凭据外泄、工具劫持、隐藏内容、编码混淆等风险。
3. 系统返回 risk labels、score、severity、evidence spans、sanitized output。
4. 高风险扫描结果写入 RiskEvent 并可在 Dashboard 聚合查看。

### 4.3 策略决策

1. Agent 或 Gateway 提交 actor/tool/command/risk labels 上下文。
2. Policy Engine 优先执行确定性内置规则，必要时调用 OPA。
3. 返回 allow/deny/redact/require_approval/quarantine/sandbox/rate_limit 等动作。
4. 策略决策持久化，并作为风险审计依据。

### 4.4 MCP 工具治理

1. 管理员注册 MCP server。
2. Gateway 刷新工具列表，扫描工具描述与 schema。
3. Agent 调用工具前，Gateway 执行 pre-policy 与参数扫描。
4. Gateway 调用上游 MCP server，并对输出执行 post-scan 与 post-policy。
5. Dashboard 显示工具风险状态，并支持测试调用。

### 4.5 Replay 与 Eval

1. 用户选择历史 run 创建 replay，检查事件数量、阻断点与置信度。
2. 用户创建 eval suite，定义 scanner/policy 断言。
3. 系统运行 suite 并记录 pass/fail、case 结果与失败建议。
4. Dashboard 展示历史趋势与回归风险。

## 5. 功能需求

### FR-1 多租户与项目治理

- 支持组织、项目、环境三层隔离。
- API 请求必须具备 project scope，不允许跨项目读取数据。
- 支持项目级配置：原文存储、保留天数、风险阈值、默认策略 fail mode。
- 支持项目初始化、归档和删除保护。

### FR-2 身份认证与授权

- 支持 API Key 多密钥管理、密钥哈希存储、过期时间、最后使用时间和轮换。
- 支持 Dashboard 登录身份，至少预留 OIDC/SAML 接入点。
- 支持 RBAC：Admin、Security Reviewer、Developer、Read Only。
- 支持服务端审计所有敏感操作。

### FR-3 Trace 数据采集

- 支持 run、span/event、content、risk 的稳定 schema。
- 支持 SDK 批量上报、失败重试、超时控制、离线缓冲。
- 支持 token、latency、cost、model、tool、用户、会话等标准维度。
- 支持 DAG、时间线、事件详情、内容引用的查询。

### FR-4 内容安全与隐私保护

- 默认不存储 raw content，只存储 hash、摘要、脱敏文本和对象引用。
- 支持项目级 raw content 开关与字段级脱敏策略。
- 支持 scanner 规则版本化，输出稳定证据结构。
- 支持风险事件关联 run/event/content/policy decision。

### FR-5 策略引擎

- 支持规则优先、OPA 可插拔、未来可扩展为策略包版本。
- 支持命令风险、数据外泄、未授权 MCP server、高风险标签等内置规则。
- 支持策略 dry-run、策略 explain、策略回放验证。
- 支持 action 的统一执行语义：deny、redact、approval、quarantine、sandbox、rate_limit。

### FR-6 MCP Gateway

- 支持真实 MCP `stdio` 生命周期管理，包括启动、健康检查、超时、stderr 捕获和重启。
- 支持 HTTP/streamable HTTP 上游调用、认证头配置、连接池与超时。
- 支持 tool/resource/prompt 三类对象的 pre/post 扫描与策略。
- 支持 MCP server trust level、allowed agents、quarantine 状态和工具缓存刷新。

### FR-7 Replay 与 Eval 平台化

- 支持 replay 模式：exact、mock、policy-only。
- 支持 eval suite CRUD、版本、标签、基线、历史趋势。
- 支持异步执行与状态查询，避免长任务阻塞 HTTP 请求。
- 支持失败聚类与修复建议。

### FR-8 Dashboard 控制台

- 支持 Setup、Overview、Runs、Risks、Scanner、Policy、Replay、Eval、MCP 管理闭环。
- 所有列表支持分页、过滤、排序、空态、错误态和 loading 态。
- Run Detail 支持 DAG + 时间线 + 事件 inspector + 内容查看权限控制。
- Risk 页面支持按 severity/type/project/date 过滤并反查相关 run。
- MCP Manager 支持 server CRUD、工具刷新、测试调用、quarantine/restore。

### FR-9 运维与可观测性

- 提供 `/healthz`, `/readyz`, `/metrics`。
- 输出结构化 JSON 日志，包含 request_id、project_id、run_id、trace_id。
- 集成 OpenTelemetry traces/metrics/logs 出口。
- 提供数据库迁移、备份、保留清理和数据导出任务。

### FR-10 开发者体验

- 提供清晰 README、SDK quickstart、MCP gateway cookbook、policy cookbook。
- 提供稳定 OpenAPI contract 与变更说明。
- 所有本地开发命令通过 `uv` 与 npm scripts 标准化。
- 提供示例 Agent、示例 MCP server、示例 eval suite。

## 6. 非功能需求

### 6.1 安全

- API Key 必须哈希存储，不得明文落库。
- 默认关闭 raw content；启用 raw content 时必须有审计记录。
- Gateway 调用上游工具必须设置超时、大小限制和隔离策略。
- Dashboard 不应把服务端密钥暴露给浏览器运行时。
- 对敏感 API 增加速率限制与审计。

### 6.2 可靠性

- API 请求失败时 SDK 不应中断业务 Agent 主流程，除非用户显式配置 fail-closed。
- 长任务必须异步化，支持重试与幂等。
- Gateway 上游失败应返回结构化错误，并持久化可审计事件。
- 数据库连接、HTTP 客户端、MCP 子进程必须有生命周期管理。

### 6.3 性能

- 事件写入支持批量，目标 P95 写入延迟小于 200ms（本地 Postgres，小批量）。
- 列表查询默认分页，避免无限 limit。
- Dashboard 首屏在本地环境应小于 2s 可交互。
- 大内容对象不直接内联返回，使用 content ref 与权限控制。

### 6.4 可扩展性

- Scanner 规则应插件化或配置化。
- Policy provider 支持 builtin、OPA、未来远端策略服务。
- Storage 支持 SQLite local-first 与 Postgres production。
- SDK 支持同步 API 起步，预留异步客户端。

### 6.5 可测试性

- 后端核心服务维持单元测试；API contract 维持集成测试。
- Gateway 使用 mock upstream 覆盖 pre/post policy。
- Dashboard 用 Vitest 覆盖数据构造与关键交互，用 Playwright 覆盖验收场景。
- CI 中必须运行 ruff、pytest coverage、frontend test、frontend build、E2E smoke。

## 7. 数据需求

核心实体与关系：

- Project 作为隔离边界，关联 Agent、Run、Risk、Eval、MCP registry。
- Run 表示一次 Agent 执行，关联多个 TraceEvent。
- TraceEvent 表示 model/tool/handoff/error/state/policy 等事件，引用 ContentObject。
- ContentObject 存储哈希、摘要、脱敏文本、标签与可选 raw/object uri。
- PolicyDecision 记录策略输入摘要与输出结果。
- RiskEvent 归一化风险，用于风险台账与审计。
- McpServer/McpTool 管理 MCP 注册表与工具风险状态。
- EvalSuite/EvalRun 管理测试集与执行结果。
- ReplayRun 管理历史 run 的回放结果。

未来应补充：

- Organization、User、Membership、Role、ApiKey。
- AuditLog、ApprovalRequest、PolicyBundle、ScannerRule、BackgroundJob。
- Artifact/ObjectStoreRef 用于大对象与导出文件。

## 8. 接口需求

已有 `/v1` API 可作为 v1 contract 基础。下一阶段需要补充：

- `/v1/projects`: 项目 CRUD 与配置。
- `/v1/api-keys`: 密钥创建、吊销、轮换、last-used 查询。
- `/v1/audit-logs`: 审计日志查询。
- `/v1/approvals`: 人工审批流。
- `/v1/jobs`: Replay/Eval/扫描等异步任务状态。
- `/v1/policy-bundles`: 策略包版本、启用、dry-run。
- `/v1/scanner/rules`: 扫描规则版本与测试。
- `/metrics`: Prometheus 指标。

## 9. 验收标准

工程化 v1.0 验收建议：

- `uv run ruff check .` 通过。
- `uv run pytest --cov=agentops_guard --cov-fail-under=80` 通过。
- `npm run test`, `npm run build`, `npm run test:e2e` 在 `dashboard` 下通过。
- Docker Compose 启动 API、Gateway、Postgres、Dashboard 后可完成 Scanner、Policy、Replay、Eval、MCP 流程。
- 所有新增表通过 Alembic migration 创建，不依赖生产运行时 `create_all`。
- Dashboard 对所有列表实现分页/过滤/错误态。
- 关键敏感操作进入 AuditLog。

## 10. 需求优先级

| 优先级 | 需求 | 说明 |
| --- | --- | --- |
| P0 | Schema migration、路由拆分、认证密钥安全、分页、审计 | 生产化基础，不做会限制所有后续能力 |
| P0 | Gateway 真实 stdio 管理、超时、大小限制 | MCP 网关从 demo 到可用的关键 |
| P1 | 异步任务、Replay/Eval 状态机、job API | 规模化评测与回放必需 |
| P1 | OTel、metrics、结构化日志、health/readiness | 可运维必需 |
| P1 | Dashboard 权限、过滤、详情体验 | 控制台可用性与安全性 |
| P2 | 策略包版本、scanner 插件化、趋势报表 | 面向团队协作和持续治理 |
| P2 | 多语言 SDK、云原生 Helm、外部对象存储 | 扩展部署和生态 |

## 11. 开放问题

- 目标用户优先是本地开发者、自托管团队，还是企业安全平台？这会影响 OIDC、RBAC 和审计深度。
- MCP Gateway 是否必须完整兼容 MCP 官方协议全部能力，还是优先覆盖工具治理路径？
- raw content 是否允许在企业私有部署中按项目开启？如果允许，需要明确加密、审计和保留策略。
- Replay 是否只做结构性回放，还是需要真正重新调用模型/工具？后者需要沙箱与成本控制。
- 是否引入 Redis/RQ/Celery/Arq 等任务系统，还是先用数据库 job worker 保持轻量？
