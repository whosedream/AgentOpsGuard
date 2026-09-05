# Deployment

## Compose

- Run `docker compose up --build`.
- Run `uv run python scripts/compose_smoke.py` after the stack is healthy.
- Dashboard 只读挂载构建所需的 `app`、`components`、`lib` 和明确列出的配置文件，其
  `node_modules` 与 `.next` 使用独立可写卷；不得挂载整个 `dashboard/` 或恢复 `.:/app`，否则前端
  服务可能读取 `.env.local`、测试数据、根目录 `.env`、数据库、模型和评测产物。
- Compose 发布的 API、Gateway、Dashboard、PostgreSQL、Redis、OPA 和 Collector 端口全部只绑定
  `127.0.0.1`。需要从其他机器访问时应经过明确配置的入口代理，不能把开发口令服务直接暴露到
  局域网。

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
  - `runtimeSecret.existingSecret`: a pre-created Secret containing the database URL, Redis URL,
    API bootstrap keys, and Dashboard server key
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
  - route `/mcp` to the Gateway and Dashboard traffic through the Dashboard service

The chart has a dedicated `mcp` section. `publicUrl` must be the externally visible `/mcp` URL;
production requires HTTPS. `allowedHosts` and `allowedOrigins` are comma-separated exact host and
browser-origin allowlists, not credential fields. Change all three together when replacing the
example `agentops.local` host. The Ingress template routes `mcp.ingressPath` to the Gateway and the
ordinary site paths to the Dashboard:

```yaml
mcp:
  publicUrl: https://guard.example/mcp
  allowedHosts: guard.example
  allowedOrigins: https://guard.example
  ingressPath: /mcp
```

### 生产镜像来源门禁

`values.prod.yaml` 会把 `supplyChain.requireImageDigests` 打开。API、Gateway、Worker、发件箱
投递器、模型服务和迁移任务使用已审核的 Python 应用镜像摘要；Dashboard 使用单独构建的前端
镜像及摘要；启用内置 OPA 时还必须另外提供 OPA 镜像摘要。缺少任一必需摘要、摘要格式错误或仍
使用可变标签时，Helm 在生成部署清单阶段就会失败：

```yaml
image:
  repository: registry.example/agentops-guard
  digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

dashboardImage:
  repository: registry.example/agentops-guard-dashboard
  digest: sha256:123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0

opa:
  enabled: true
  image:
    repository: openpolicyagent/opa
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

摘要固定只能证明“部署的字节没有被标签悄悄替换”，不能证明构建者身份，也不能代替漏洞扫描。
因此生产 values 还会要求 `imageVerification.enabled=true`，并生成 Sigstore policy-controller
原生 `ClusterImagePolicy`。仓库范围必须至少精确到具体镜像仓库，签发方必须是无凭据 HTTPS URL，
签名者必须是完整且不含通配符的身份；缺一项、使用 `warn` 或填写过宽模式都会在 Helm 渲染时失败：

```yaml
imageVerification:
  trustRootRef: agentops-public-sigstore
  imageGlobs:
    - registry.example/security/agentops-guard@sha256:*
    - registry.example/security/agentops-guard-dashboard@sha256:*
  keyless:
    issuer: https://token.actions.githubusercontent.com
    subject: https://github.com/example/agentops-guard/.github/workflows/supply-chain.yml@refs/heads/main
```

控制器本身直接复用 Sigstore 官方 Helm chart；生产值、管理员托管的 `TrustRoot`、安装步骤、
命名空间 opt-in 和故障演练见 `deploy/admission/README.md`。本地真实 kind 集群已经证明无签名
匹配镜像拒绝、webhook 全停时拒绝、双副本恢复以及仓库不可达时拒绝，但还没有可达的私有仓库和
正确签名镜像，无法验证正确签名放行、错签名者、签名后变更和冒名仓库，因此镜像签名门槛尚未清除。

发布流水线会生成 CycloneDX 依赖 SBOM，并分别构建 Python 与 Dashboard 镜像。镜像只使用提交
SHA 标签发布；下载的 Buildx 可执行文件与 BuildKit daemon 镜像分别按摘要固定，并在仓库登录前
完成核对。BuildKit 为精确摘要附加 SLSA 来源证明；另行锁定可执行文件摘要的 Trivy 生成
CycloneDX 镜像 SBOM，并对同一摘要执行 HIGH/CRITICAL 可修复漏洞门禁。通过后 Cosign 才会用
GitHub OIDC 短期身份签署来源证明、SBOM 和镜像摘要，并立即按精确工作流路径、仓库和分支复验。
仓库已经固定 GitHub Actions、`uv 0.12.1`、Python 3.12 和
`pip-audit` 版本；检出代码后不保留访问凭据。CycloneDX 1.5 清单直接由 `uv.lock` 和已锁定的 Dashboard 安装结果生成，
去除生成时间并用各自锁文件摘要生成稳定编号。当前 Python 96 组件清单和 Dashboard 131 组件
清单可重复生成，且已进入固定发布验收。Google OSV `2.4.0` 已对两份当前锁文件完成真实在线
复扫，结果为 0 个受影响包；Windows 侧生产依赖 `npm audit` 也返回 0。聚合证据绑定扫描器与
锁文件摘要，依赖变化后发布检查会拒绝旧证据。构建/扫描 Job 没有 OIDC 签名权限；只有两套镜像
全部通过后，独立签名 Job 才得到短期身份。该 Job 不检出或执行项目代码，只接受摘要校验的工作流
制品和 Cosign 可执行文件。整个发布链只在默认分支运行，PR 没有推送或签名权限；扫描失败时可能
留下未签名的提交标签，但准入策略会拒绝它，也不会更新 `latest`。当前 WSL
的 `pip-audit` 仍无法连接 PyPI，GitHub 托管工作流也尚未实际通过；没有可用的已签名生产镜像，
因此完整托管流水线和真实准入正向验证仍是未完成的发布条件。

所有 Helm 工作负载默认要求镜像内声明非 root 用户，使用运行时默认系统调用过滤，禁止提权，
丢弃全部 Linux capabilities，并把根文件系统设为只读。需要临时文件的进程只得到独立的空 `/tmp`；
Dashboard 另有空的运行时缓存目录。私有仓库拉取凭据按 Python、Dashboard 和 OPA 镜像分别配置，
不会作为应用环境变量注入。模板已真实渲染，Dashboard 启动包也在普通用户、只读根目录容器中
返回 200；这些证据不等于已经在目标 Kubernetes 的准入控制和网络插件上验证。

### 生产网络隔离

生产 values 会开启命名空间级默认拒绝。Chart 只固定放行入口控制器到 Gateway `8001`、Dashboard
`3000`，Dashboard/Gateway 到 API `8000`，以及启用时到 OPA 和小模型服务的最小路径。小模型与
内置 OPA 不得到 DNS 或外部网络权限。

数据库、Redis、OIDC/JWKS、MCP 上游、OpenBao、对象锁存储和遥测地址取决于企业环境，必须按进程
填写标准 Kubernetes `NetworkPolicyEgressRule`。下面仅展示结构，不能照抄示例网段：

```yaml
networkPolicy:
  ingressController:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: ingress-nginx
    podSelector:
      matchLabels:
        app.kubernetes.io/name: ingress-nginx
  externalEgress:
    api:
      - to:
          - ipBlock:
              cidr: 10.20.1.0/24
        ports:
          - protocol: TCP
            port: 5432
    gateway:
      - to:
          - namespaceSelector:
              matchLabels:
                security.example/zone: approved-mcp
            podSelector:
              matchLabels:
                app.kubernetes.io/name: approved-upstream
        ports:
          - protocol: TCP
            port: 8443
```

API、Gateway、Worker、发件箱投递器和迁移任务的列表不能为空；启用审计封条出口时，它也必须独立
声明。`0.0.0.0/0`、`::/0`、空选择器、端口范围、未知进程和不明确端口会让 Helm 失败。标准
NetworkPolicy 不支持可移植的域名白名单；外部 SaaS 应使用稳定受管网段或单独审查的出口代理/CNI
扩展，不能把全互联网放开。

目标命名空间还要启用 `restricted` Pod Security Admission，并把版本固定为目标 Kubernetes 小版本。
完整配置合同和真实探针矩阵见 `specs/kubernetes-isolation-v1.md`。只有支持 NetworkPolicy 的 CNI 上
跑过正反网络探针后，才能清除真实 Kubernetes 隔离门槛。

Chart 为 API、Gateway、Worker、发件箱投递器、Dashboard、小模型、OPA 和迁移 Job 创建独立
ServiceAccount，但不创建任何 Role、ClusterRole 或绑定；这些账号和 Pod 都设置
`automountServiceAccountToken: false`。若企业平台预创建账号，可关闭 `serviceAccounts.create`，
但名称仍必须逐项配置。审计出口继续使用 `auditAnchorExporter.serviceAccountName` 指定的云工作负载
身份；通用 Kubernetes API Token 仍不自动挂载，需要的云身份投影由目标平台单独审查和注入。

The chart never renders runtime credential values. Provision `runtimeSecret.existingSecret` through
the cluster's secret manager before installing the release. Each workload imports named keys only:
Migration receives the database URL; Worker and the outbox dispatcher receive database and Redis
URLs; a single Gateway receives the database URL and its API key, while a multi-replica Gateway also
receives the Redis URL for shared capacity leases; Dashboard receives only its server-side API key.
The optional audit-anchor exporter receives a separate read-only database URL. Its official
OpenBao Proxy sidecar receives separate response-wrapped AppRole files and uses a short-lived token
that can read only the audit key's public material. The exporter process receives no OpenBao token,
API, Redis, credential-decryption, provider, or static cloud access key.
Do not pass any of these values with `helm --set`, values files, tickets, or chat messages.

The one-shot migration workload runs `agentops-guard-migrate`. It applies Alembic first and then
installs the reviewed default scanner rule pack into the default project. Re-running the same image
is idempotent; a database row that differs from the pack embedded in that image stops the migration
instead of silently accepting policy drift. Managed rules cannot be edited or deleted through the
ordinary scanner-rule API. Deploy a newly reviewed image and pack revision for policy changes.

`gatewayConcurrency.backend` defaults to `local` for one Gateway replica. The chart refuses to
render more than one Gateway replica unless the backend is `redis`; production values enable it.
Redis failure then stops new upstream calls with `503` instead of silently falling back to separate
per-process limits. Expired leases recover capacity after a crashed Gateway:

```yaml
replicaCount:
  gateway: 2
gatewayConcurrency:
  backend: redis
  leaseSeconds: 60
```

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
  openbaoAuthMethod: proxy
  openbaoExistingSecret: agentops-openbao-client
  openbaoAppRoleRoleIdKey: role-id
  openbaoAppRoleSecretIdKey: wrapped-secret-id
  openbaoAppRoleSecretIdResponseWrappingPath: auth/approle/role/agentops-api/secret-id
  openbaoKvMount: secret
```

生产 Chart 会启动官方 OpenBao Proxy sidecar，API 只访问本 Pod 的回环地址，不持有 OpenBao
令牌。预建 Secret
`agentops-openbao-client` 包含 `role-id` 和一次性的 `wrapped-secret-id`；它只挂载给 Proxy，不挂载
给 API。Proxy 负责解包、登录、续期和强制注入短期令牌。SecretID、包装令牌和短期令牌都不得进入
环境变量、values、命令参数、URL、日志或工单消息。API 使用
`deploy/openbao/agentops-api-policy.hcl`，只读写
`secret/data/agentops/*` 并按需使用指定 Transit 密钥，不具有通用管理权限。API `/readyz` 在
OpenBao 模式下会检查健康状态。开发 Compose 仍默认使用 Fernet；固定 OpenBao Token 仅保留给
本地开发，生产配置会拒绝它。

响应包装令牌只能使用一次。受信部署控制器必须在短期令牌需要重新认证或 Pod 重启前，生成新的
包装令牌并原子更新 `wrapped-secret-id`。发放 API 和审计出口身份时，应分别使用
`deploy/openbao/agentops-api-identity-delivery-policy.hcl` 和
`deploy/openbao/agentops-audit-export-identity-delivery-policy.hcl`；这两个身份只能读取各自的 RoleID
并生成各自的包装 SecretID，不能读取托管凭据、签名或管理其他 AppRole。本地真实测试已经验证
上述越权访问被拒绝，且 Proxy 会读取更新后的文件并重新认证；企业环境仍需验证实际 Secret
同步控制器、TLS 私有 CA、滚动发布和故障告警。私有 CA 可用
`credentialStore.openbaoCaExistingSecret` 和 `openbaoCaKey` 只读挂载，Chart 没有跳过证书校验的
开关。

`uv run python scripts/verify_openbao_raft_ha.py` 会在临时目录启动三个真实 OpenBao `2.6.1`
进程，使用 TLS 与 Integrated Storage，终止当前主节点，并通过官方快照接口恢复数据。临时测试
CA 会给每个节点签发两版不同的叶证书；检查按“备用节点优先、主节点最后”的顺序原子替换证书和
私钥，通过 OpenBao 支持的 SIGHUP 重新加载，并用真实 TLS 握手确认指纹变化、进程号不变。检查还
要求同一 `credential_ref` 和不可导出 Transit 密钥在换证、切主、恢复期间持续可用，并要求快照后
的写入在恢复后消失。该检查使用临时测试 CA 和一次性 Shamir 解封份额；它不替代企业 PKI 自动
签发、CA 信任轮换、双向 TLS、KMS/HSM 自动解封、五节点跨故障域部署或负载均衡器无感切换。

本机 OpenBao 运行时必须先通过 `scripts/install_openbao_current_runtime.py` 安装。它要求官方
归档、签名校验清单和两份 Sigstore 证明同时匹配固定摘要、准确发布工作流身份与签发方，之后才
原子安装 `bao`。`scripts/verify_openbao_release_signature.py` 会在固定发布验收中离线重验并做
单字节篡改反例。该流程只证明主机归档来源，生产容器镜像仍需单独验签和内容核对；固定值见
`specs/openbao-signed-runtime-provenance-v1.md`。

## OpenBao 审计封条

数据库内的前向哈希链能发现普通改写，但不能单独防住“历史记录和链头一起重算”。启用审计封条
后，API 会把当前链头交给 OpenBao Transit 的 Ed25519 密钥签名。私钥保持不可导出；API 只保存
签名和公钥。把 `GET /v1/audit-logs/checkpoints` 返回的公开证据定期复制到企业的只追加存储后，
数据库管理员即使重算整条链，也无法伪造旧封条。

先由 OpenBao 管理员建立 Transit 挂载和不可导出密钥，再给 API 工作负载应用最小权限策略
`deploy/openbao/agentops-audit-signing-policy.hcl`。管理员令牌不得写入命令参数、values、URL、日志或
工单；应由受信部署组件从 Secret/Vault 注入。Helm 只配置非秘密名称：

```yaml
auditCheckpoints:
  backend: openbao
  openbaoTransitMount: transit
  keyName: agentops-audit
```

签发需要 `audit:write`，读取和验签需要 `audit:read`。在线验签会用 OpenBao 中相同版本的公钥
核对数据库记录，避免数据库攻击者换成自己的公钥；`/readyz` 也会检查密钥确实是不可导出的
Ed25519 密钥。OpenBao 或密钥不可用时签发及在线来源核对返回固定 `503`，不会生成无签名的替代
记录。项目不把本数据库冒充外部只追加存储，生产部署仍必须把公开封条保存到独立系统，以发现
整库回滚或删除。

### S3 对象锁封条出口

可选的 `audit-anchor-exporter` 直接复用 Boto3，把已经通过数据库链、签名和 OpenBao 公钥来源核对
的公开封条写入 S3 兼容对象锁存储。写入使用固定对象名、SHA-256、条件创建、版本号和
`COMPLIANCE` 保留期，随后读取同一版本核对正文和保留状态。重复执行只验证已有版本，不覆盖
原对象。上传内容只有公开封条，不包含审计正文、消息、工具参数或凭据。

出口每轮还会列举该前缀下的所有对象版本。若外部已有数据库里不存在的封条、删除标记或同名多版本，
会立即失败退出，避免数据库整体回滚后只按旧库继续运行。该前缀必须由本环境独占，不能与其他系统共用。

对象锁只能用于启用了版本控制和 Object Lock 的桶。AWS 生产环境应使用云工作负载身份；Chart
没有 `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY` 或预签名 URL 入口。数据库 Secret 必须对应
只读账号，OpenBao Secret 应应用 `deploy/openbao/agentops-audit-export-policy.hcl`，只允许读取
Transit 公钥，不能签名。配置示例不包含任何凭据：

```yaml
auditAnchorExporter:
  enabled: true
  serviceAccountName: agentops-audit-export
  databaseExistingSecret: agentops-audit-readonly-db
  openbaoExistingSecret: agentops-openbao-audit-readonly
  openbaoAppRoleRoleIdKey: role-id
  openbaoAppRoleSecretIdKey: wrapped-secret-id
  openbaoAppRoleSecretIdResponseWrappingPath: auth/approle/role/agentops-audit-export/secret-id
  bucket: agentops-audit-lock
  prefix: agentops-audit-checkpoints
  region: us-east-1
  expectedBucketOwner: "123456789012"
  retentionDays: 2555
```

启用前必须先由存储管理员创建开启对象锁的桶并设置最小保留策略。仓库现在额外使用摘要和
Minisign 固定的 MinIO `RELEASE.2025-09-07T16-13-09Z` 真实验证版本控制、写入、重复运行、按版本
回读、管理员删除拒绝和保留期缩短拒绝。该社区二进制已停止维护，只是本地 S3 兼容性夹具，不是
生产选型或外部隔离证据。首次上线仍要在真实目标桶以 TLS 和工作负载身份重跑，并完成整库回滚
告警；详见 `specs/minio-object-lock-runtime-v1.md`。

## OPA 策略服务

Compose 默认使用 OPA `1.20.1-debug`，并把 `policies/` 只读挂载到容器。API、Gateway 和 Worker 使用
`http://opa:8181`；API 与 Gateway 的就绪检查会验证 OPA 健康状态。策略判断按以下顺序合并：

1. 密钥外发、危险命令、未授权工具动作等本地硬规则先执行，OPA 不能放宽；
2. OPA 与项目策略包参与判断；
3. 多个结果取更严格的动作，并把策略来源与版本写入决策记录。

默认 `closed_for_high_risk`：OPA 故障时，低风险请求继续走本地规则，高风险请求转人工审批。
生产环境可改为 `closed` 以拒绝所有无法完成外部策略判断的请求。不要在 `AGENTOPS_OPA_URL`
中放用户名、口令或令牌。

Helm 默认不创建 OPA。需要内置 OPA 时设置 `opa.enabled=true`；如果组织已有 OPA，请保持内置
组件关闭，并通过工作负载配置注入内部 `AGENTOPS_OPA_URL`。更新 ConfigMap 中的策略后应滚动
重启 OPA Pod。生产配置禁止这种未签名方式：必须先由独立发布流程使用不进入运行环境的私钥生成
签名 bundle，再把 `bundle.tar.gz` 和验证用的 `public.pem` 放入已有 Secret。部署只引用 Secret
名称，OPA 启动时验签，健康检查只有在 bundle 成功激活后才通过；策略被修改、漏签或公钥不匹配
都会阻止启动。还必须把该发布批准的精确策略版本写入
`opa.bundle.expectedPolicyRevision`；API、Gateway 和 Worker 收到不同版本时把 OPA 视为不可用，
避免旧的合法签名包被回滚使用。OPA 的匿名遥测已关闭，Pod 不允许出网。

```yaml
opa:
  enabled: true
  bundle:
    enabled: true
    existingSecret: agentops-opa-policy
    verificationKeyId: agentops-policy-v1
    scope: agentops.guard
    expectedPolicyRevision: agentops-guard-v1
```

该 Secret 固定包含 `bundle.tar.gz` 和 `public.pem` 两个键，不能包含签名私钥。仓库已用固定摘要的
OPA `1.8.0` 官方镜像验证容器隔离、本地签名包、真实决策和故障关闭；另用固定 SHA-256 的官方
`1.20.1` Linux/amd64 二进制启动两个真实实例，验证远程签名 v1/v2 热更新、两实例状态上报、篡改
拒绝、发布端故障时共同保留上一好版本，以及一个实例在断网期间重启后从持久化缓存恢复并在联网
后重新一致。安装和证据边界见 `specs/opa-remote-bundle-runtime-v1.md`。尚未取得按签名验证的
`1.20.1` 生产镜像，也未连接企业 TLS、工作负载身份、签名密钥托管或真实 Kubernetes 网络策略。

## OpenTelemetry

Compose 默认启动 OpenTelemetry Collector，并通过 OTLP gRPC 接收 API、Gateway 和 Worker 的
链路数据。默认 Collector 只用 `debug` exporter 验证接入，生产环境应把
`deploy/otel-collector.yaml` 的 exporter 替换成组织的可观测平台。
Compose 的开发默认版本已更新为 `0.160.0`，但可变标签不能作为生产来源证明；生产验收必须使用
已经验证签名者并按 SHA-256 摘要固定的镜像。Compose 同时强制 Collector 使用 UID/GID 10001、
只读根目录、全部权限丢弃、禁止提权、进程/CPU/内存上限，并只把 OTLP 与健康端口绑定到宿主机
回环地址；这些声明仍需在真实镜像运行后与 Docker 状态对账。
`AGENTOPS_OTEL_EXPORTER_OTLP_ENDPOINT` 只接受不含账号、密码、查询参数或片段的 HTTP(S) 基础
地址；认证资料必须由受信部署平台单独注入，不能塞进 URL。
应用不会读取通用的 `OTEL_RESOURCE_ATTRIBUTES` 或 `OTEL_SERVICE_NAME`，避免宿主环境把任意
元数据自动送出。若设置 `AGENTOPS_OTEL_SERVICE_NAME`，只能使用
`agentops-guard-<component>` 形式的固定低变化标识。

采集字段只包括路由模板、耗时、状态码、策略动作、风险档位、MCP 传输类型等固定元数据；不采集
消息正文、URL 查询参数、HTTP 头、工具参数、模型输入输出或凭据。Helm 连接已有 Collector 时设置：

```yaml
telemetry:
  enabled: true
  otlpEndpoint: http://otel-collector.observability.svc:4317
  traceSampleRatio: 0.25
```

采样率只影响链路数据，不影响数据库中的审计记录、策略决策和风险事件。
Windows 网络出口已从官方 GitHub 发布取得 Collector `0.160.0` Linux/amd64 归档、逐文件 SHA-256
和 Sigstore bundle。固定摘要的 Cosign `3.1.2` 在执行前先由 TUF 制品公钥独立验签，随后按精确
签名身份、签发方、透明日志证明及固定信任根验证自身和 Collector 发布包；发布检查还会把归档
改动一个字节并确认验签失败。仓库外安装
的固定摘要二进制已真实接收 OTLP，并验证下游关闭时写入
`file_storage`、Collector 终止/重启后向本地后端补发以及私密请求标记缺失。复现方法和证据边界见
`specs/otelcol-resilience-runtime-v1.md` 和 `specs/signed-runtime-provenance-v1.md`。Docker Hub/GHCR
仍超时，所以上述签名是发布归档证据，不是生产镜像、企业持久卷或企业后端证据。取得官方摘要镜像后运行
`uv run python scripts/verify_otel_collector.py --image '<official-repository>@sha256:<digest>'`；该入口
会核对版本、容器权限、真实 OTLP 文件导出和请求私密数据缺失。它通过也只证明本地文件出口，企业
后端仍需单独验收。发布报告会保留这一项未验证门槛。

## PostgreSQL 备份恢复验收

上线前必须用实际版本执行一次自定义格式备份和空库恢复，并复核迁移版本、审批执行封套、后台
任务和审计链。仓库提供 `uv run python scripts/verify_postgres_backup_restore.py` 作为隔离演练；它
使用两个临时 PostgreSQL 16 实例，并验证旧版已有审计会在迁移时补入哈希链；完成后删除实例且不
输出测试口令。该脚本证明备份可读，不替代
生产环境的加密、保留期、跨故障域复制、恢复时间和恢复点演练。

## 本地语义扫描模型

第一版使用本机保存的 PyTorch/Transformers `safetensors` 权重。模型权重不得提交到 Git；管理员
把完整模型目录挂载到独立 `semantic-scanner` 服务，Gateway 不挂载权重，也不在自身进程加载模型。
模型服务启用 Hugging Face 和 Transformers 离线模式，不从网络临时下载文件。

当前已经接入 `shadow` 能力，但默认仍是 `disabled`；只有管理员明确配置后才会运行。启用后，
网关只向内部模型服务发送本地脱敏且不超过 1,024 字符的外部正文。模型判断不能批准、放行或
降低硬规则风险；高风险事件只能把同一次运行中后续改写类动作升级为人工审批，不会因模型判断
直接批准或隔离本次内容。模型路径和摘要只进入模型服务。

本仓库当前固定权重摘要为 `0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0`，本地目录的完整文件清单见 `models/semantic-guard/manifest.json`。Compose 启动前设置：

```bash
export AGENTOPS_SEMANTIC_SCANNER_MODE=shadow
export AGENTOPS_SEMANTIC_MODEL_DIR=/home/hzj/projects/agentops-guard/models/semantic-guard
export AGENTOPS_SEMANTIC_MODEL_SHA256=0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0
```

不要设置 `enforce`。固定评测中该模型在 NotInject 上误报 `54/339`，尚未达到审批或隔离门槛；CPU 512-token p95 约 `505ms`，对时延敏感的部署应保持关闭，或先在实际 GPU/量化运行时重新测量。

Compose 只在 `semantic` profile 中启动模型服务；Helm 为它单独设置 CPU、内存、只读根文件
系统、只读权重挂载和网络策略。只有 Gateway 可以访问模型服务，模型服务没有出站网络。
Gateway 的 `/readyz` 会在启用模型后检查该服务是否已经完成权重热身。

受管凭据仍只通过 `credential_ref` 在受信执行器中使用，不会进入这个模型。对外部正文中的
未知秘密，格式规则只能尽量脱敏，无法给出绝对保证；若部署要求任何未知秘密也不得进入本地
分类器，请保持 `AGENTOPS_SEMANTIC_SCANNER_MODE=disabled`。

### OIDC hard limits

When OIDC is enabled, the API and Gateway reject bearer tokens larger than 16 KiB and tokens whose
signed `exp - iat` exceeds 15 minutes by default. Set `oidc.maxTokenBytes` and
`oidc.maxTokenLifetimeSeconds` in Helm only after reviewing the identity provider's measured token
size and lifetime. Workload `project_id`, `agent_id`, `sub`, and `scope` values are bounded to the
database and authorization schema; duplicate, empty, oversized, or control-character scopes are
rejected. These checks limit malformed-token resource use and prevent an identity-provider
misconfiguration from silently creating long-lived Agent access.
