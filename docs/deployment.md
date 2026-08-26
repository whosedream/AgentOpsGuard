# Deployment

## Compose

- Run `docker compose up --build`.
- Run `uv run python scripts/compose_smoke.py` after the stack is healthy.

## Helm

- Chart path: `deploy/helm/agentops-guard`.
- Static asset validation: `uv run python scripts/validate_helm_assets.py`.
- Real render validation: `powershell -File scripts/helm_template_check.ps1`.
- Cross-platform render validation: `uv run python scripts/helm_template_check.py`.
  - The script prefers a local `helm` binary, then `%TEMP%\helm-v3.18.4\windows-amd64\helm.exe`, then `AGENTOPS_HELM_IMAGE`.
- External dependencies:
  - `AGENTOPS_DATABASE_URL`
  - `AGENTOPS_REDIS_URL`
- Externalized secrets:
  - `AGENTOPS_API_KEY`
  - `AGENTOPS_OPERATOR_API_KEY`
  - `AGENTOPS_CREDENTIAL_ENCRYPTION_KEY` in a dedicated Secret exposed only to the API process
- Example values:
  - `values.local-like.yaml`
  - `values.staging.yaml`
  - `values.prod.yaml`
- Install flow:
  - lint and render the chart in CI through the Helm container helper
  - run migration job before scaling API, Gateway, and Worker
  - route Dashboard through the chart services, not direct public URLs

For production, generate the Fernet key inside a managed secret store and sync it into a dedicated
Kubernetes Secret. Do not print the key or pass it as a command argument. For a local development
file that never writes the key to stdout:

```bash
umask 077
uv run python -c "from pathlib import Path; from cryptography.fernet import Fernet; Path('/secure/path/agentops-credential.key').write_bytes(Fernet.generate_key())"
kubectl create secret generic agentops-credential-encryption --from-file=AGENTOPS_CREDENTIAL_ENCRYPTION_KEY=/secure/path/agentops-credential.key
```

Set `credentialEncryption.existingSecret` to a Kubernetes Secret that contains the
`AGENTOPS_CREDENTIAL_ENCRYPTION_KEY` key. Do not add this value to the chart's shared application
Secret: Gateway, Worker, Dashboard, and Migration do not need decryption authority.
Remove the local staging file according to the deployment environment's secret-handling policy.
The Compose path is development-only and must not carry production provider credentials.

## OpenBao 凭据存储

生产环境可把 `credential_ref` 后端切到 OpenBao KV v2。SQL 表只保存固定 KV 路径与版本证明；
DeepSeek 密钥、绑定摘要都保存在 OpenBao。Agent、Gateway、Worker 和 Dashboard 不会获得 OpenBao
令牌，只有 API 中的受信执行组件能在授权通过后读取密钥并注入最终认证头。

Helm 配置示例（不包含任何令牌值）：

```yaml
credentialStore:
  backend: openbao
  openbaoUrl: https://openbao.internal
  openbaoExistingSecret: agentops-openbao-client
  openbaoTokenKey: AGENTOPS_OPENBAO_TOKEN
  openbaoKvMount: secret
```

`agentops-openbao-client` 必须由集群的 Secret 管理器预先创建；不要在 values、命令参数、URL、
日志或工单消息里填写令牌。OpenBao 策略只需允许 API 工作负载读写
`secret/data/agentops/*`，不要授予通用管理权限。API `/readyz` 在 OpenBao 模式下会检查其健康
状态。开发 Compose 仍默认使用 Fernet；若连接外部测试 OpenBao，只能通过受保护的运行环境注入
`AGENTOPS_OPENBAO_TOKEN`。

## OPA 策略服务

Compose 默认启动 OPA，并把 `policies/` 只读挂载到容器。API、Gateway 和 Worker 使用
`http://opa:8181`；API 与 Gateway 的就绪检查会验证 OPA 健康状态。策略判断按以下顺序合并：

1. 密钥外发、危险命令、未授权工具动作等本地硬规则先执行，OPA 不能放宽；
2. OPA 与项目策略包参与判断；
3. 多个结果取更严格的动作，并把策略来源与版本写入决策记录。

默认 `closed_for_high_risk`：OPA 故障时，低风险请求继续走本地规则，高风险请求转人工审批。
生产环境可改为 `closed` 以拒绝所有无法完成外部策略判断的请求。不要在 `AGENTOPS_OPA_URL`
中放用户名、口令或令牌。

Helm 默认不创建 OPA。需要内置 OPA 时设置 `opa.enabled=true`；如果组织已有 OPA，请保持内置
组件关闭，并通过工作负载配置注入内部 `AGENTOPS_OPA_URL`。更新 ConfigMap 中的策略后应滚动
重启 OPA Pod，或改用组织管理的 OPA bundle 发布流程。

## OpenTelemetry

Compose 默认启动 OpenTelemetry Collector，并通过 OTLP gRPC 接收 API、Gateway 和 Worker 的
链路数据。默认 Collector 只用 `debug` exporter 验证接入，生产环境应把
`deploy/otel-collector.yaml` 的 exporter 替换成组织的可观测平台。

采集字段只包括路由模板、耗时、状态码、策略动作、风险档位、MCP 传输类型等固定元数据；不采集
消息正文、URL 查询参数、HTTP 头、工具参数、模型输入输出或凭据。Helm 连接已有 Collector 时设置：

```yaml
telemetry:
  enabled: true
  otlpEndpoint: http://otel-collector.observability.svc:4317
  traceSampleRatio: 0.25
```

采样率只影响链路数据，不影响数据库中的审计记录、策略决策和风险事件。

## 本地语义扫描模型

第一版使用本机保存的 PyTorch/Transformers `safetensors` 权重。模型权重不得提交到 Git；管理员先把完整模型目录放到宿主机，再通过 `AGENTOPS_SEMANTIC_MODEL_DIR` 只读挂载到网关的 `/models/semantic-guard`。运行时启用 Hugging Face 和 Transformers 离线模式，不从网络临时下载文件。

当前已经接入 `shadow` 能力，但默认仍是 `disabled`；只有管理员明确配置后才会运行。启用后，网关记录模型判断结果，但不据此拦截请求。其他服务不会获得模型路径或模型文件。管理员完成本地模型校验后，设置 `AGENTOPS_SEMANTIC_SCANNER_MODE=shadow`、`AGENTOPS_SEMANTIC_MODEL_SHA256` 和本地模型目录即可开始观察结果。

本仓库当前固定权重摘要为 `0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0`，本地目录的完整文件清单见 `models/semantic-guard/manifest.json`。Compose 启动前设置：

```bash
export AGENTOPS_SEMANTIC_SCANNER_MODE=shadow
export AGENTOPS_SEMANTIC_MODEL_DIR=/home/hzj/projects/agentops-guard/models/semantic-guard
export AGENTOPS_SEMANTIC_MODEL_SHA256=0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0
```

不要设置 `enforce`。固定评测中该模型在 NotInject 上误报 `54/339`，尚未达到审批或隔离门槛；CPU 512-token p95 约 `505ms`，对时延敏感的部署应保持关闭，或先在实际 GPU/量化运行时重新测量。

当前通用 Python 镜像包含 Torch 和 Transformers，但只有 Gateway 会加载模型。实测首次加载约
`7.6s`、峰值内存约 `1GiB`；在 Helm 中启用 `shadow` 时，建议为 Gateway 预留至少
`1200Mi` 内存请求和 `1536Mi` 内存上限。Chart 的启动探针允许模型先完成加载，成功热身后
`/readyz` 不会重复运行推理。

受管凭据仍只通过 `credential_ref` 在受信执行器中使用，不会进入这个模型。对外部正文中的
未知秘密，格式规则只能尽量脱敏，无法给出绝对保证；若部署要求任何未知秘密也不得进入本地
分类器，请保持 `AGENTOPS_SEMANTIC_SCANNER_MODE=disabled`。
