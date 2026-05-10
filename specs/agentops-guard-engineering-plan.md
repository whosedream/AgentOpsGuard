# Plan: AgentOps Guard 完整工程化演进

**Generated**: 2026-05-08  
**Estimated Complexity**: High

## Overview

本计划将 AgentOps Guard 从当前可运行 v1 scaffold 推进到完整工程化版本。演进策略是先稳定数据契约和安全边界，再生产化 MCP Gateway 与异步任务，最后补齐可观测、权限、审计和产品化交付。每个 Sprint 都应产出可运行、可测试、可回滚的增量。

## Prerequisites

- 使用 `uv` 管理 Python 环境。
- 本地可运行 `uv sync --extra dev` 与 `npm install`。
- Postgres 可用于 migration 与集成测试。
- 当前测试基线可执行：`uv run pytest`、`uv run ruff check .`、`npm run test`。
- 明确 v1.0 目标部署形态：Docker Compose 优先，Kubernetes/Helm 后置。

## Sprint 1: 稳定契约与代码结构

**Goal**: 将后端从单文件路由聚合拆成可维护模块，并建立生产 schema 管理基础。  
**Demo/Validation**:

- API 文档仍能展示完整 `/v1` 接口。
- 原有 Python 测试全部通过。
- Alembic 可在空数据库执行 `upgrade head`。

### Task 1.1: 拆分后端 API 路由

- **Location**: `src/agentops_guard/backend/routes.py`, `src/agentops_guard/backend/api/*.py`
- **Description**: 按 system/runs/events/content/policy/scanner/risks/replay/eval/mcp 拆分 router，并由统一 `api/router.py` 聚合。
- **Dependencies**: None
- **Acceptance Criteria**:
  - 所有原端点路径、请求和响应保持兼容。
  - `create_app()` 只 include 顶层 router。
- **Validation**:
  - `uv run pytest tests/test_api.py tests/test_gui_api.py`

### Task 1.2: 提取 API 依赖与错误模型

- **Location**: `src/agentops_guard/backend/api/deps.py`, `src/agentops_guard/backend/api/errors.py`
- **Description**: 统一 DB session、project scope、request id、错误响应 envelope。
- **Dependencies**: Task 1.1
- **Acceptance Criteria**:
  - 业务错误有稳定 code。
  - 日志和响应包含 request id。
- **Validation**:
  - 新增错误响应测试。

### Task 1.3: 建立真实 Alembic 初始迁移

- **Location**: `alembic/versions/0001_initial.py`, `src/agentops_guard/backend/models.py`
- **Description**: 用真实建表语句替换 placeholder migration，保留 SQLite/Postgres 兼容。
- **Dependencies**: None
- **Acceptance Criteria**:
  - 空 Postgres 可 `alembic upgrade head`。
  - 本地 SQLite 初始化路径不破坏开发体验。
- **Validation**:
  - `uv run alembic upgrade head`

### Task 1.4: 增加分页协议

- **Location**: run/risk/replay/eval/mcp list routes 与 schemas
- **Description**: 为列表接口增加 cursor/limit，可兼容旧数组返回或新增 envelope 参数。
- **Dependencies**: Task 1.1
- **Acceptance Criteria**:
  - 默认 limit 不超过 50。
  - Dashboard 列表可消费分页结果。
- **Validation**:
  - API pagination tests。

## Sprint 2: 安全基线与审计

**Goal**: 将单 dev API Key 升级为可轮换、可审计、可授权的安全基线。  
**Demo/Validation**:

- 可以创建、吊销、轮换项目 API Key。
- 敏感操作写入 AuditLog。
- Dashboard 不直接暴露后端密钥。

### Task 2.1: 增加 ApiKey 模型与哈希校验

- **Location**: `models.py`, `security/api_keys.py`, auth dependency
- **Description**: 新增 ApiKey 表，存储 hash/scopes/expires/revoked/last_used。
- **Dependencies**: Sprint 1 migration
- **Acceptance Criteria**:
  - 明文 key 只在创建响应中出现一次。
  - 旧 `AGENTOPS_API_KEY` 可作为 dev fallback。
- **Validation**:
  - Auth success/revoked/expired/scope tests。

### Task 2.2: 增加项目隔离检查

- **Location**: API deps、repositories
- **Description**: 所有 project-scoped 查询和写入使用统一 project guard。
- **Dependencies**: Task 2.1
- **Acceptance Criteria**:
  - 不同项目间 run/risk/eval/mcp 不可互读。
  - 测试覆盖跨项目拒绝。
- **Validation**:
  - `tests/test_auth_projects.py` 扩展。

### Task 2.3: 增加 AuditLog

- **Location**: `models.py`, `services/audit.py`, sensitive routes
- **Description**: 对 key、policy、MCP、raw content、approval 操作写审计。
- **Dependencies**: Sprint 1 migration
- **Acceptance Criteria**:
  - 审计包含 actor/action/resource/before/after/request metadata。
  - 提供只读 `/v1/audit-logs`。
- **Validation**:
  - Audit API tests。

### Task 2.4: Dashboard BFF 密钥收口

- **Location**: `dashboard/app/api/backend/[...path]/route.ts`, `dashboard/lib/api.ts`
- **Description**: 后端 API Key 只在服务端 proxy 使用，客户端只调用同源 BFF。
- **Dependencies**: Task 2.1
- **Acceptance Criteria**:
  - 浏览器 bundle 不包含后端 API Key。
  - 本地开发仍可无登录访问。
- **Validation**:
  - `npm run build`，检查 client env 使用。

## Sprint 3: MCP Gateway 生产化

**Goal**: 将 Gateway 从 demo echo/HTTP proxy 升级为可治理真实 MCP server 的运行时。  
**Demo/Validation**:

- 可注册 fake stdio MCP server 并真实列出/调用工具。
- 高风险工具调用被 pre-policy 阻断。
- 高风险工具输出被 post-policy 标记或阻断。

### Task 3.1: 抽象 Gateway transport

- **Location**: `src/agentops_guard/gateway/transports/*.py`
- **Description**: 定义 BaseTransport，并实现 streamable_http transport。
- **Dependencies**: None
- **Acceptance Criteria**:
  - 现有 HTTP gateway 测试保持通过。
  - transport error 返回结构化结果。
- **Validation**:
  - `uv run pytest tests/test_gateway.py`

### Task 3.2: 实现 stdio process manager

- **Location**: `src/agentops_guard/gateway/runtime/process_manager.py`, `transports/stdio.py`
- **Description**: 管理 stdio MCP 子进程的启动、请求、超时、stderr、关闭。
- **Dependencies**: Task 3.1
- **Acceptance Criteria**:
  - 支持配置 command/args/env/cwd。
  - 调用超时后进程可被清理或重启。
- **Validation**:
  - fake stdio MCP server integration test。

### Task 3.3: 统一 pre/post guard

- **Location**: `gateway/policy_guard.py`, `gateway/scanner_guard.py`
- **Description**: 将工具描述、参数、输出、resource、prompt 的扫描和策略统一封装。
- **Dependencies**: Task 3.1
- **Acceptance Criteria**:
  - 响应稳定包含 `policy_decision` 与 `risk`。
  - 阻断事件进入 RiskEvent/AuditLog。
- **Validation**:
  - 扩展 `tests/test_gateway_gui.py`。

### Task 3.4: 增加 MCP health 与 refresh job

- **Location**: mcp routes、job service、dashboard MCP page
- **Description**: 工具刷新异步化，记录 server health/status。
- **Dependencies**: Sprint 4 job 基础或轻量同步占位
- **Acceptance Criteria**:
  - Dashboard 可看到 server active/quarantined/error。
  - Refresh 失败不破坏已有工具缓存。
- **Validation**:
  - MCP manager E2E。

## Sprint 4: Replay/Eval 异步任务化

**Goal**: 将长任务从请求路径剥离，提供可查询、可重试、可审计的任务系统。  
**Demo/Validation**:

- 创建 eval run 返回 job id。
- Dashboard 轮询 job 状态并展示最终结果。
- 失败任务保留错误摘要与重试次数。

### Task 4.1: 新增 BackgroundJob 模型与服务

- **Location**: `models.py`, `services/jobs.py`, `routes_jobs.py`
- **Description**: DB-backed job queue，支持 pending/running/completed/failed。
- **Dependencies**: Sprint 1 migration
- **Acceptance Criteria**:
  - Job 创建、领取、完成、失败状态机可测试。
  - 支持 attempts 与 run_after。
- **Validation**:
  - Job service unit tests。

### Task 4.2: Eval 异步化

- **Location**: eval routes/service、worker
- **Description**: Eval suite run 改为创建 job，worker 执行后写 EvalRun。
- **Dependencies**: Task 4.1
- **Acceptance Criteria**:
  - 兼容现有同步 API 或提供 transition flag。
  - Dashboard 能展示执行中状态。
- **Validation**:
  - Eval API + E2E tests。

### Task 4.3: Replay 异步化

- **Location**: replay routes/service、worker
- **Description**: Replay 创建 job，完成后写 ReplayRun。
- **Dependencies**: Task 4.1
- **Acceptance Criteria**:
  - Replay 可查询 pending/running/completed。
  - 失败有 suggestions/error summary。
- **Validation**:
  - Replay API + Run Detail E2E。

### Task 4.4: Worker CLI

- **Location**: `src/agentops_guard/cli.py`, worker module
- **Description**: 增加 `agentops-guard worker` 命令。
- **Dependencies**: Task 4.1
- **Acceptance Criteria**:
  - 本地可启动 worker loop。
  - Docker Compose 可增加 worker 服务。
- **Validation**:
  - Manual smoke + integration test。

## Sprint 5: 可观测性与运维

**Goal**: 补齐生产运行所需健康检查、指标、日志、追踪与部署 gate。  
**Demo/Validation**:

- `/healthz`, `/readyz`, `/metrics` 可访问。
- 日志包含 request id 与 project id。
- Docker Compose 完整栈可 smoke。

### Task 5.1: 结构化日志与 request id

- **Location**: `backend/observability/logging.py`, FastAPI middleware, Gateway middleware
- **Description**: 统一 JSON log 和 request id 注入。
- **Dependencies**: Sprint 1 deps
- **Acceptance Criteria**:
  - 每个请求日志有 method/path/status/duration/request_id。
  - Gateway upstream 调用有 server/tool/status。
- **Validation**:
  - Middleware tests。

### Task 5.2: Metrics endpoint

- **Location**: `backend/observability/metrics.py`, `gateway` middleware
- **Description**: 暴露 Prometheus metrics。
- **Dependencies**: Task 5.1
- **Acceptance Criteria**:
  - API、policy、scanner、gateway、jobs 指标可采集。
- **Validation**:
  - `/metrics` contract test。

### Task 5.3: Readiness 与 migration gate

- **Location**: health routes、Docker Compose、alembic
- **Description**: readiness 检查 DB、migration version、可选 OPA/Gateway。
- **Dependencies**: Sprint 1 migration
- **Acceptance Criteria**:
  - DB 不可用时 readyz 返回非 2xx。
  - Compose 中 api 等待 migration 完成。
- **Validation**:
  - Docker smoke。

### Task 5.4: CI 工作流

- **Location**: `.github/workflows/ci.yml` 或项目实际 CI 配置
- **Description**: 固化 Python/Frontend/E2E/migration gate。
- **Dependencies**: 前序测试稳定
- **Acceptance Criteria**:
  - PR 自动运行 lint、tests、build、migration。
  - Coverage gate 不低于 80%。
- **Validation**:
  - CI green。

## Sprint 6: Dashboard 产品化

**Goal**: 将 Dashboard 从功能验证页面升级为安全运营控制台。  
**Demo/Validation**:

- 所有页面具备 loading/empty/error/retry。
- 列表具备分页过滤。
- 危险操作有确认、审计备注和结果反馈。

### Task 6.1: 统一 UI 状态组件

- **Location**: `dashboard/components/ui/*.tsx`
- **Description**: 增加 DataTable、EmptyState、ErrorState、LoadingSkeleton、ConfirmDialog。
- **Dependencies**: None
- **Acceptance Criteria**:
  - Runs/Risks/MCP/Eval 复用统一组件。
- **Validation**:
  - Vitest component tests。

### Task 6.2: Runs 与 Risks 查询体验

- **Location**: `dashboard/app/runs`, `dashboard/app/risks`, filters components
- **Description**: URL query 驱动筛选、排序、分页。
- **Dependencies**: Sprint 1 pagination
- **Acceptance Criteria**:
  - 刷新页面保留筛选条件。
  - risk 可跳转关联 run/event。
- **Validation**:
  - Playwright SPEC-RUN/SPEC-RISK。

### Task 6.3: Run Detail Inspector

- **Location**: `dashboard/app/runs/[id]/page.tsx`, `RunDagView`, EventInspector
- **Description**: 增加 DAG + timeline + event detail + content ref 查看。
- **Dependencies**: Backend content 权限
- **Acceptance Criteria**:
  - 点击 DAG 节点展示事件详情。
  - raw content 受权限和审计控制。
- **Validation**:
  - Run detail E2E。

### Task 6.4: MCP Manager 操作闭环

- **Location**: `dashboard/components/forms/McpManager.tsx`
- **Description**: 支持 refresh job、health、quarantine/restore、测试调用历史。
- **Dependencies**: Sprint 3, Sprint 4
- **Acceptance Criteria**:
  - 用户可看见工具风险、策略结果和上游错误。
- **Validation**:
  - SPEC-MCP E2E 扩展。

## Sprint 7: 文档与发布

**Goal**: 形成可交付、可维护、可升级的产品文档与发布流程。  
**Demo/Validation**:

- 新用户可按文档 15 分钟内跑通 local demo。
- 自托管用户可按 Compose 文档部署完整栈。
- 每次发布有 changelog 与 migration note。

### Task 7.1: 重写 README 快速开始

- **Location**: `README.md`
- **Description**: 区分 local SQLite、Docker Compose、production Postgres 三种路径。
- **Dependencies**: 部署脚本稳定
- **Acceptance Criteria**:
  - 命令可复制执行。
  - 明确默认 API Key 仅用于开发。
- **Validation**:
  - Fresh clone smoke。

### Task 7.2: SDK 与 Gateway Cookbook

- **Location**: `docs/sdk.md`, `docs/mcp-gateway.md` 或 `specs`
- **Description**: 提供 Python Agent 接入、MCP server 注册、策略调试示例。
- **Dependencies**: Sprint 3 SDK/Gateway 稳定
- **Acceptance Criteria**:
  - 包含最小示例和常见错误排查。
- **Validation**:
  - 示例脚本可运行。

### Task 7.3: API Changelog 与版本策略

- **Location**: `specs/api-contracts.md`, `CHANGELOG.md`
- **Description**: 记录接口变更、兼容策略和弃用周期。
- **Dependencies**: Sprint 1 API contract
- **Acceptance Criteria**:
  - 每个 breaking risk 有迁移说明。
- **Validation**:
  - Release checklist。

### Task 7.4: 发布检查清单

- **Location**: `docs/release-checklist.md`
- **Description**: 固化测试、migration、Docker build、security review、docs update。
- **Dependencies**: CI 稳定
- **Acceptance Criteria**:
  - 每次发布可按 checklist 执行。
- **Validation**:
  - Dry-run release。

## Testing Strategy

- 每个 Sprint 先补 contract tests，再重构实现。
- 后端从具体服务测试开始，再跑 API integration。
- Gateway 使用 fake upstream/fake stdio server，避免依赖真实外部服务。
- Dashboard 保持 Vitest 单测与 Playwright spec ID 对齐。
- 发布前必须完成 Docker Compose manual smoke。

## Potential Risks & Gotchas

- 当前仓库所在上层 git 状态显示大量未跟踪文件，建议在项目根目录初始化独立 git 或确认 workspace 边界，避免误提交。
- Alembic 从 placeholder 迁移到真实 schema 时可能影响已有 SQLite 文件，需要提供备份和重建说明。
- `dashboard/package.json` 使用 `latest` 依赖，不利于可复现构建，建议锁定主版本并依赖 lockfile。
- API Key 从 env fallback 迁移到数据库 key 时，要保留开发模式兼容，否则会破坏 quickstart。
- MCP stdio 上游需要严格进程管理，否则容易产生僵尸进程、卡死请求或泄露 stderr 中的敏感信息。
- Eval/Replay 异步化会改变 API 交互模型，需要为 Dashboard 和 CLI 提供过渡兼容层。

## Rollback Plan

- 路由拆分可通过保持原 `routes.py` 导出兼容 router 回滚。
- Migration 变更发布前备份数据库；失败时回滚容器镜像并恢复备份。
- API Key 数据库化保留 `AGENTOPS_API_KEY` dev fallback，出现问题可临时切回环境变量校验。
- Gateway transport 抽象保留当前 HTTP/echo 行为作为 fallback。
- 异步任务上线时保留同步执行 feature flag，Dashboard 根据能力探测选择路径。
