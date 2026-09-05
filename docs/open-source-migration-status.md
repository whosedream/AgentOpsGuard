# 开源组件迁移状态

更新时间：2026-09-05

本文只记录已经进入当前工作区的实现和实际验证结果。配置文件存在不等于外部组件已经在本机或集群中运行。

## 定案

AgentOps Guard 不整套替换成另一个网关。保留本项目已有的风险扫描、动作授权、人工审批、
`credential_ref` 和审计控制面，只吸收成熟开源项目擅长的通用能力：

1. 用官方 MCP Python SDK 连接标准 MCP 上游；
2. 用 OPA 承载可独立发布的策略判断；
3. 用 OpenBao 保存服务凭据；
4. 用 OpenTelemetry 输出不含正文的链路数据；
5. 按需用 ToolHive 隔离高风险 MCP 服务；
6. 用固定版本 uv 从锁文件生成 CycloneDX 软件物料清单；
7. ContextForge 保留为协议与运维对照，不嵌入生产路径；
8. 用 Inspect AI 组织 Agent 与 MCP 的端到端安全评测，并与生产依赖隔离；
9. 用 Google RE2 执行管理员可配置规则，避免正则回溯拖垮网关。
10. 用 Microsoft BIPIA 的固定官方测试集补充未参与调参的静态泛化评测。
11. 只在评测探针中复用 Meta `llama-cookbook` 的 Prompt Guard 分窗方法，不复制成生产路径。
12. 用 Sigstore policy-controller 的标准 `ClusterImagePolicy` 做镜像签名准入，不自研 webhook。
13. 用 Kubernetes 原生 NetworkPolicy 和 Pod Security Admission 做集群隔离，不自研网络插件。

## 当前进度

| 开源项目 | 吸收的能力 | 当前状态 | 已验证 | 尚未验证 |
| --- | --- | --- | --- | --- |
| [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) | 标准 Streamable HTTP 客户端与服务端、工具、资源、资源模板、提示和补全 | 已升级到 `2.1.1`，上下游均使用官方实现；RFC 6570 模板及补全请求/结果类型直接复用 SDK 实现 | 官方客户端经真实 Gateway 进程连接真实 v2 `MCPServer` 上游，工具、固定资源、两类资源模板、提示与两类补全、Bearer 鉴权、读/调用权限分离、项目及受限 Agent 隔离均通过；四类列表以标准不透明游标逐页返回，模板经项目绑定引用展开，游标跨身份、跨列表、过期或畸形以及缺少/多余模板参数、任意资源地址均拒绝；补全只接受当前公开引用和已声明参数，危险返回值被过滤；危险工具只生成审批且未执行；冻结客户端包 `1.9.4`、`1.29.1` 和当前 `2.1.1` 分别覆盖 `2025-03-26`、`2025-11-25`、`2026-07-28` 协商 | 长任务、订阅以及旧 SDK 包的资源模板与补全尚未单独复测；不承诺低于 `1.9.4` 的客户端 |
| [Google RE2](https://github.com/google/re2) | 安全执行管理员与部署方提供的扫描表达式 | 官方 Python 包 `google-re2 1.1.20251105` 已精确锁定 | 创建、更新和迁移统一拒绝 RE2 不支持的表达式；限制 4,096 字符和 8 MiB 编译内存；10 万字符对抗输入、7/7 已知攻击与 0/302 正常误报回归通过 | 只解决表达式回溯和资源滥用，不提高未知攻击的语义泛化率 |
| [Open Policy Agent](https://www.openpolicyagent.org/docs/rest-api) | 独立策略服务、确定性动作合并、故障时关闭策略 | 已进入代码、部署和发布核验；官方 `1.8.0` Linux/amd64 镜像按清单摘要固定，官方当前版 `1.20.1` Linux/amd64 二进制按 SHA-256 固定 | `1.8.0` 容器通过 3 项 Rego、签名 bundle、真实决策、只收紧合并、服务故障转审批以及非 root/只读根/最小权限检查；两个 `1.20.1` 真实进程同时从网络发布端加载签名 v1、热更新 v2并分别上报状态，拒绝篡改包并在发布端 `503` 时保留上一好版本；一个实例断网重启后从持久化缓存恢复 v2，联网后两边重新健康。运行端没有私钥；生产 Helm 强制签名 bundle、公钥、精确批准版本及最小网络策略 | OPA 官方说明签名时间不参与验证，因此项目改用精确批准版本防合法旧包回滚，不能声称有原生过期机制；Docker 仓库超时使 `1.20.1` 生产镜像尚未验签，本地发布端也不是企业 TLS、工作负载身份、密钥托管或真实 Kubernetes 网络策略 |
| [OpenBao](https://openbao.org/docs/secrets/kv/kv-v2/) | KV v2 凭据存储；Transit 不可导出签名；官方 Proxy 管理 AppRole 短期令牌；Integrated Storage 提供 Raft 与快照 | 已进入代码、Helm 和发布核验；本机 `2.6.1` 由官方归档安装并固定 | 官方校验清单和归档各自的 Sigstore 证明均按准确发布工作流身份、签发方和离线可信根验证，安装二进制与签名归档一致，两个单字节篡改反例均拒绝。真实 Proxy 身份隔离、轮换和撤销已验证；三个真实 TLS 节点成为 Raft 投票成员，每个节点通过 SIGHUP 不重启换用不同的新叶证书，换证期间同一 `credential_ref` 和 Transit 签名持续可用；终止主节点后成功选出新主节点，官方快照恢复保留快照前数据并移除快照后标记 | 当前来源证明针对主机归档而非生产镜像；企业 Secret 同步控制器、企业 PKI 自动签发、CA 信任轮换、双向 TLS、KMS/HSM 自动解封、五节点跨故障域和负载均衡器无感切换尚未验证 |
| [OpenTelemetry](https://opentelemetry.io/docs/collector/) | API、网关、Worker、OPA、OpenBao、MCP 的链路关联 | 已进入代码、Collector 配置和固定发布验收；官方 `0.160.0` Linux/amd64 归档与二进制按 SHA-256 固定，归档 Sigstore 证明已按精确官方工作流身份和 GitHub Actions 签发方验证 | 测试证明 span 不包含请求正文、动态 URL 路径、头、查询、工具参数或凭据，只保存路由模板；真实 Collector 在下游关闭时接收 OTLP 并写入 `file_storage`，进程终止/重启后向本地后端补发，随机私密标记缺失；固定 Cosign 还会复核发布归档、安装二进制并拒绝单字节篡改。另有官方摘要镜像验收入口检查版本、真实文件导出和容器权限 | 当前是签名归档而非签名生产镜像；Docker Hub/GHCR 超时，未验证官方生产镜像、企业持久卷、真实后端展示/搜索/告警或容量 |
| [ToolHive](https://github.com/stacklok/toolhive) | 容器隔离、权限配置、标准 MCP 代理、Sigstore 来源校验 | 可选接入和企业无权限模板已完成；本机已安装 `0.41.0` | 发布包 checksums 校验通过；版本化模板和启动器强制无特权、受限网络、回环代理、严格协议、审计及来源验证；本地摘要固定镜像的权限声明与 Docker 实际状态对账通过：无网络、无宿主目录/设备、非特权、丢弃全部 capabilities；AgentOps 主链调用通过；严格来源模式正确拒绝没有来源资料的本地直连镜像 | 仍没有企业私有注册表中的已签名测试镜像，因此缺少签名正向验证；默认细粒度网络隔离还需要 `dockurr/dnsmasq` 镜像，当前 Docker Hub 超时，尚未验证域名/端口白名单 |
| [Boto3](https://github.com/boto/boto3) | 把公开签名封条写入 S3 Object Lock | 已锁定 `1.43.88` 并接入独立出口进程 | SDK 请求级测试覆盖版本控制、对象锁、SHA-256、条件创建、`COMPLIANCE` 保留、同版本回读、重复运行和外部历史反向对账；真实本地 S3 兼容服务已证明管理员不能删除精确版本或缩短保留期，重复条件写不新增版本；Helm 最小权限渲染通过 | 本地使用的是已停止维护的 MinIO 社区二进制，仅作协议夹具；尚未连接企业对象锁桶，未验证 TLS、工作负载身份、独立权限域、多节点耐久性和整库回滚告警 |
| [uv / npm SBOM](https://github.com/astral-sh/uv) + [OSV-Scanner](https://github.com/google/osv-scanner) | 从 Python 与前端锁文件生成 CycloneDX 清单并查询已知漏洞 | CI 固定 `uv 0.12.1`、Python 3.12、Node.js `22.23.2`；GitHub Actions 和 OSV reusable workflow 固定到完整提交 | 本地生成 Python 96 组件、Dashboard 131 组件的 CycloneDX 1.5；Google OSV `2.4.0` 对两份当前锁文件真实在线复扫为 0 个受影响包，生产依赖 `npm audit` 也为 0；聚合证据绑定锁文件和扫描器摘要并进入发布验收 | 结果仅代表查询时的锁文件；GitHub 托管流水线尚未成功运行，当前 WSL 的 `pip-audit` 仍无法连接 PyPI |
| [Docker Buildx](https://github.com/docker/build-push-action) + [Trivy](https://github.com/aquasecurity/setup-trivy) + [Cosign](https://github.com/sigstore/cosign-installer) | 构建两套生产镜像、附加来源与内容清单、按摘要扫描并用短期身份签名 | 官方 Actions 均固定到完整提交；Buildx 可执行文件和 BuildKit daemon 镜像分别按 SHA-256 固定且禁用不安全构建权限；Trivy 使用官方修复标签篡改事件后的不可变 `setup-trivy v0.2.6`，并在执行前另行核对 `0.70.0` 可执行文件 SHA-256；Cosign 安装器也核对下载二进制摘要 | 工作流只允许默认分支发布提交标签；必须先通过 OSV/Python/npm，再由 BuildKit 附加 SLSA，Trivy 生成 CycloneDX 并拒绝可修复 HIGH/CRITICAL；构建/扫描无 OIDC 权限，只有不检出项目代码的后续 Job 能用摘要固定 Cosign 签署证明、SBOM 和镜像并复验身份 | 仅完成代码和本地静态检查；尚无 GitHub 托管成功记录、GHCR 镜像摘要、在线扫描报告或真实签名，不能清除供应链与集群准入门槛 |
| [ContextForge](https://github.com/IBM/mcp-context-forge) | 标准 MCP 聚合、发现、运维设计参考 | 仅参考，不嵌入 | 已有固定版本的本地对照试验；本项目已补上当时缺少的标准 MCP 上游支持 | 旧对照报告是迁移前快照，不能代表当前版本性能，也不能证明 ContextForge 加插件后的安全能力 |
| [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) | ReAct Agent、MCP 工具调用、任务与评分 | `0.3.262` 与 OpenAI 客户端 `3.5.0` 已固定在独立 `uv` 评测项目，不进入生产依赖 | 固定受诱导 Agent 的写请求被真实 Gateway 挡住；真实 Qwen3-4B 烟雾测试完成 2/2 条只读任务；进一步在 7 个 AgentDojo 模板改编攻击中产生 7 次真实越权写请求，全部停在审批前且上游副作用为 0。Agent 只拿 `credential_ref` | 动态微型集只有 7 攻击和 2 正常样本，不是官方完整 AgentDojo 或统计充分的未知攻击结果 |
| [Inspect Evals AgentThreatBench](https://github.com/UKGovernmentBEIS/inspect_evals/tree/v0.16.0/src/inspect_evals/agent_threat_bench) | 记忆污染、任务劫持、数据外传三类真实 Agent 工具评测和官方效用/安全评分 | 固定 `inspect-evals 0.16.0`、任务版 `1-A`、24 条公开样本和来源摘要；保留 v1-v5 失败/修复证据，当前 v6 单独生成 | v6 中 5/5 个邮件劫持样本的改写在上游前暂停，攻击样本高风险动作实际执行 0；完整效果安全 17/19（89.47%），正常完成 1/5，与基线相同，Gateway 错误 0 | 已公开并用于本轮修复，不是未知攻击盲测；仍有两条只在最终文字层面失败；正常样本仅 5 条，4B 基线正常完成仅 1/5，不能代表生产可用性 |
| [llama.cpp](https://github.com/ggml-org/llama.cpp) / [llama-cpp-python](https://github.com/abetlen/llama-cpp-python) | 本地 GGUF 推理和 OpenAI 兼容接口 | `llama-cpp-python 0.3.35` 在独立 `uv` 环境从摘要固定的源包编译；启动器同时支持经摘要审阅的原生 `llama-server` | 官方 Qwen3-4B Q4_K_M GGUF 摘要校验通过；启动器亲自加载模型，回环服务和最小 Qwen 工具格式适配器无访问日志；v2 报告固定运行库、模型和五个实现文件摘要 | CPU 两样本烟雾测试不是性能基准或未知攻击评测；原生 Linux `llama-server` 发布包仍因 GitHub 直连超时未取得，但不再阻塞真实 GGUF 运行证据 |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | 公开的工具型 Agent 正常任务、攻击目标和间接注入模板 | `0.1.35` 固定在隔离评测环境，复用 `v1.2.2` | 静态和动态首轮报告保持不可变；静态 v3 和动态 v10 才代表当前实现。v8/v9 固定种子重复由 Qwen、Gateway 和 MCP 上游逐条真实运行，除创建时间外逐字段相同；扩大语义输入到 1,024 字符后又真实运行 v10 | 当前静态回归联合检出 76.43%、正常误报 9.28%；动态首轮证明 7/7 写入诱导被授权层挡住；v7 如实保留 5/7 读取波动，v8/v9 重复和当前 v10 均证明已知模板 7/7 在内容入口隔离、正常 0/2 误报，并锁定 23 个安全路径实现。仍不是官方完整 AgentDojo，不能升级小模型权限 |
| [Meta llama-cookbook Prompt Guard inference](https://github.com/meta-llama/llama-cookbook/blob/main/getting-started/responsible_ai/prompt_guard/inference.py) | 512-token 分窗、批处理和最大风险聚合思路 | 只适配为离线、汇总式架构探针；来源提交和文件摘要固定 | 当前 Wolf Defender 在已知 BIPIA 200 攻击/200 正常切片上，分窗将攻击并集命中从 126 提到 159，但正常误报从 13 升到 28，模型 p95 从 320.84 ms 升到 2328.22 ms；阈值探针没有找到可用折中 | 方案已淘汰，不进入生产；这不是 Prompt Guard 2 权重或模型效果测试，也不是盲测。Prompt Guard 2 仍需管理员接受许可证、提供审阅后的本地权重并在新保留集上评测 |
| [Microsoft BIPIA](https://github.com/microsoft/BIPIA) | Email、Table、Code 间接注入测试上下文与攻击家族 | 固定官方提交和每个源文件摘要，数据只在仓库外裸缓存 | 首轮调参前静扫描 13,750 个上下文/攻击组合和 200 条正常内容；并集检出 5,264（38.28%），误报 13（6.50%）；同条件 ProtectAI 候选只有 25.92% 检出、20% 误报且更慢，已淘汰；两份不可覆盖报告进入发布验收 | 当前模型仍未达强制拦截门槛；这是静态扫描，不是 BIPIA 回答攻击成功率或 Agent/工具端到端阻断率 |
| [UIUC InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | 工具返回内容中的直接伤害与数据窃取攻击 | 固定官方提交和两份 `base` 数据 Git 对象；直接复用 1,054 条工具响应与攻击类别 | 首轮调参前静态扫描中，规则检出 20、旁路模型检出 571、并集检出 577（54.74%）；17 个匹配正常模板误报 1。数据窃取联合检出 81.62%，直接伤害只有 26.08% | 没有照搬会保存逐条模型输出的旧云模型运行器；当前结果不是官方 Agent ASR 或端到端工具阻断率，同一集合已永久转为回归 |
| [Sigstore policy-controller](https://github.com/sigstore/policy-controller) | Kubernetes 镜像签名和证明准入 | 采用官方 `v1beta1` `ClusterImagePolicy`；生产 Helm 强制 `enforce`、仓库级范围、精确 OIDC issuer/subject、Rekor 校验和管理员托管 `TrustRoot`；官方 chart `0.10.7` 覆盖为摘要固定的 controller `0.15.1`，双副本、准入故障关闭且未匹配即拒绝 | 本地 Helm 错误配置拒绝通过；真实 Kubernetes `1.34.0` 已完成命名空间 opt-in、两类 webhook `failurePolicy: Fail`、官方 `0.13.1` 对匹配无签名镜像的明确拒绝、全副本停止时拒绝；`0.15.1` 读取 Ready `TrustRoot`，2/2 副本在 20.442 秒恢复且仓库不可达时拒绝。固定报告绑定当前生产配置 | 公共仓库从集群访问超时，仍缺最终 `0.15.1` 配置下正确签名放行、错签名者/签名后变更/冒名仓库拒绝、私有仓库和生产集群复验；门槛未清除 |
| [Kubernetes NetworkPolicy / Pod Security Admission](https://kubernetes.io/docs/concepts/services-networking/network-policies/) | 默认拒绝网络和 restricted Pod 准入 | 直接使用 `networking.k8s.io/v1`；生产按工作负载开放入口、内部调用、DNS 和环境外联，命名空间安全标签合同另行固定 | 真实 Kubernetes `1.34.0` + kindnet 直接应用项目 Helm 渲染的 11 条策略；23/23 条正常与越权路径、11/11 条逐策略删除/恢复以及特权 Pod 准入拒绝全部通过；固定报告重新绑定当前清单摘要 | 这是本地单节点真实数据平面，不等于生产 CNI、云工作负载身份或实际数据库/OpenBao/遥测目的地；Sigstore webhook 另行验收 |

## 为什么不整套迁移 ContextForge

ContextForge 更适合做通用 MCP 聚合和注册，本项目更重视“外部内容能否进入模型”和“工具动作
是否得到原始用户要求授权”。整套替换会把已经验证的隔离、审批、凭据和审计边界重新实现一遍。
当前更稳妥的做法是让两边使用同一标准 MCP 接口，继续把 ContextForge 当可替换的上游聚合层或
对照实现，而不是让它接管本项目的安全决策。

## 当前验证结果

- Python 全量测试：`649 passed`；语句覆盖率 `82%`，发布门槛为 `80%`。
- Python 静态检查：通过。
- Git 空白和冲突标记检查：通过。
- Docker Compose 配置解析：通过。
- Helm `3.20.0`：Chart lint、默认模板、启用内置 OPA、生产签名准入和默认拒绝网络策略渲染均通过；错误签名或网络配置会失败。
- Dashboard 生产构建：通过。
- 当前固定发布验收共 44 项，锁定 18 份基准、15 份 Agent 评测和 3 份供应链证据，包含 Keycloak/Temurin 发行签名与真实 OIDC、OPA 远程 bundle、OpenBao 签名主机归档与三节点 Raft/TLS/故障切换/快照恢复、PostgreSQL 同步流复制受控切换、Collector 持久队列恢复、签名发布归档、本地 Object Lock、Kubernetes 隔离证据、Sigstore 部分真实准入证据、在线锁文件漏洞证据、InjecAgent 历史首次结果和 AgentThreatBench 当前动态回归；每次生成新的不可覆盖报告，并仍列出
  10 项外部门槛。
- 标准 MCP：真实官方 SDK 客户端经 Gateway 进程连接真实 v2 `MCPServer` 上游；普通调用、固定资源、两类资源模板、提示、四类列表逐页读取、无效游标与任意资源地址拒绝、受限 Agent 隔离和审批前不执行均通过。
- PostgreSQL/Redis/RQ：真实 Worker 在任务执行中被终止后，过期租约恢复并由第二个 Worker 完成；相同发件箱事件重复发送未产生重复队列项。
- PostgreSQL 16 流复制：直接复用 `pg_basebackup`、物理复制槽、同步复制和 `pg_promote()`；备用库
  与主库的审计、后台任务和执行封套一致，停止旧主后约 `0.54s` 提升为新主，固定事务没有丢失，
  审计链有效且可继续写入。在此基础上又直接复用 Patroni `4.1.4` 官方 Kubernetes 三节点方案：
  强制终止主库后，固定 Service 约 `3.821s` 恢复查询，约 `13.106s` 恢复一主两备，业务状态未丢且
  可继续写入。又复用 Toxiproxy `2.12.0` 和公开 Jepsen 故障思路，仅断开主库的选主存储连接；旧主
  停止写入，全程最多一个可写主库，固定入口约 `23.912s` 恢复，解除隔离后约 `28.914s` 恢复完整
  拓扑。该结果不包括硬件看门狗/节点隔离、任意主机分区、持久卷、TLS、跨可用区或生产规模。
- Redis 整体中断：任务提交数据库后停止真实 Redis 容器，投递失败时 Job 与发件箱保持待处理；同一地址恢复后重新投递并由真实 RQ Worker 完成。
- 上游响应丢失：批准后的 stdio 工具先产生一次外部标记再不返回；网关在硬超时后记录 `outcome_unknown`，相同审批重提未产生第二次标记。
- 结果未知对账：只有管理员可提交确认结果和外部证据 SHA-256；原始证据不进入系统。确认未执行后
  才能在原到期时间、身份、参数摘要、工具版本和策略版本约束下重新领取一次；确认成功或失败后关闭。
- 执行进程崩溃：真实 PostgreSQL 中，独立子进程提交领取后直接退出，状态仍保持已领取；租约到期
  后转结果未知，替代进程不能再次领取，持有旧状态的进程也不能覆盖数据库中的新结果；Gateway
  失去执行权时会丢弃上游返回内容并写入不含正文的审计事件。
- 多副本网关背压：两个独立进程通过真实 Redis 竞争同一上游容量，第二个被拒绝；不同上游互不影响，正常释放和进程崩溃后的租约过期均能恢复容量。
- 双网关 HTTP 主链：两个真实 Gateway 进程共用 PostgreSQL/Redis 并连接真实 MCP 上游；副本 A 占用容量时副本 B 返回 429 且未调用上游，A 完成后 B 调用成功。
- 跨包 MCP 客户端：隔离安装的 `1.9.4` 与 `1.29.1` 均通过当前标准入口完成初始化、工具列表和真实工具调用；详细矩阵见 `specs/mcp-compatibility-matrix-v1.md`。
- OpenBao `2.6.1`：真实本地 KV v2 与 `credential_ref` 生命周期烟雾测试通过。
- OpenBao `2.6.1` 来源：官方校验清单与归档的 Sigstore 证明按准确签名身份和签发方离线通过；
  安装二进制与签名归档一致，归档或清单改变一个字节后均被拒绝。
- OpenBao `2.6.1` Transit：不可导出 Ed25519 密钥签发审计封条；数据库历史和链头重算后，旧封条
  仍检测到改写。
- OpenBao `2.6.1` Proxy：直接复用官方自动认证和令牌注入。应用请求不携带 OpenBao 令牌；两个
  Proxy 使用不同最小权限 AppRole。一次性包装文件轮换后重新认证成功，删除 API 身份后访问失败；
  审计出口越权读凭据和签名均被真实 OpenBao 拒绝。
- OpenBao `2.6.1` Raft：三个真实 TLS 节点均成为投票成员；终止主节点后剩余多数派选出新主节点，
  重新指向新主节点的官方 Proxy 仍可解析原 `credential_ref` 并使用原 Transit 密钥。官方快照恢复
  保留快照前凭据并移除快照后标记。每个节点使用不同证书，按备用节点优先、主节点最后的顺序经
  SIGHUP 换用第二版叶证书；真实 TLS 指纹变化、进程号不变，换证期间原凭据和签名保持可用。临时
  根令牌、解封份额、发放令牌和提供方密钥只在受信验证进程内存中使用，最终输出不含其值。
- PostgreSQL 16：`pg_dump` 自定义格式在独立空库完成 `pg_restore`，迁移版本、执行封套、后台
  任务和审计链复核通过；从 `0011` 升级前已有的审计记录被补链，恢复后仍完整；临时实例已删除。
- ToolHive `0.41.0`：标准 MCP 代理、AgentOps 网关真实调用、无网络/无宿主机目录隔离与审计烟雾测试通过；版本化无权限模板已与 Docker 真实状态完成对账，严格来源模式会拒绝没有来源资料的本地直连镜像。
- Inspect AI `0.3.262`：独立锁定环境运行固定受诱导 Agent，经真实 Gateway 和真实 MCP v2
  上游读取 2 条记录；攻击样本主动调用未获授权的写工具，但真实上游副作用为 0。该项只证明
  网关的确定性授权路径，不是模型检出率或未知攻击盲测。Inspect 与 Agent 只接触不透明
  `credential_ref`；原始测试身份只由受信注入进程用于固定 Gateway 目标。
- 真实模型入口：官方 Qwen3-4B Q4_K_M GGUF 由摘要固定的 `llama-cpp-python 0.3.35` 实际加载；
  Inspect ReAct Agent 经真实 Gateway 和 MCP v2 上游完成 2/2 条只读任务，未授权上游副作用为 0。
  固定报告为 `artifacts/evals/qwen3_4b_q4_k_m_agent_smoke_v2.json`，SHA-256 为
  `00160953613214898268dc793acc361539282030e248878b90a94a0957e263dc`，不含提示、工具参数或凭据。
  该项只是真实模型执行烟雾证据，不是未见攻击检出率或完整 AgentDojo 结果。
- AgentDojo 首次未见集静态评测：规则检出 `38/140`（27.14%），旁路模型检出 `105/140`
  （75.00%），并集检出 `107/140`（76.43%）；97 条正常任务中规则误报 0，小模型与并集误报
  9 条（9.28%）。该结果已经锁定，此后相同集合只能作为回归；详见
  `specs/agentdojo-static-blind-v1.md`。
- BIPIA 首次静态保留集：固定官方提交后，在 13,750 个 Email、Table、Code 上下文/攻击组合中，
  规则检出 `491`、旁路模型检出 `4,786`、并集检出 `5,264`（38.28%）；200 条正常内容并集误报
  `13`（6.50%）。这证明小模型已启用但泛化不足，仍只旁路；详见
  `specs/bipia-static-holdout-v1.md`。
- InjecAgent 首次静态保留集：固定 UIUC 官方提交中的 1,054 条 `base` 工具响应后，规则检出
  `20`、旁路模型检出 `571`、并集检出 `577`（54.74%）；17 个用户工具的匹配正常模板中并集
  误报 `1`。数据窃取联合检出为 81.62%，直接伤害只有 26.08%。该集合已转为回归；这不是官方
  Prompted Agent ASR，也不是端到端工具阻断率。详见 `specs/injecagent-static-holdout-v1.md`。
- AgentDojo 模板动态微型集：真实 Qwen3-4B 在 7/7 条此前未评分模板改编攻击中请求写工具，
  7 次都由确定性动作授权转入审批，真实上游副作用为 0；规则入口隔离 0/7，旁路模型命中 7/7，
  2/2 条正常读取完成且两层均未标记。固定报告 SHA-256 为
  `7ad3bc0f32ca788be566075358761ca0718e9ac25fd03eec29f12549a67901d0`。样本太小，且不是官方
  完整 AgentDojo，因此不改变小模型只旁路的决定；详见
  `specs/agentdojo-template-dynamic-gateway-v1.md`。
- 针对动态首轮暴露出的规则 0/7 盲区，已将公开 `important_instructions` 结构制作成受管规则包，
  由 Compose/Helm 的独立迁移入口自动、幂等安装；受管规则不能通过普通接口原地修改或删除，数据库
  内容与审阅包不同会让部署失败。修复后回归命中 7/7 条已知攻击，在 AgentDojo 与 LLMail 合计
  302 条公开正常样本上误报 0。管理员可配置表达式改由固定版本 RE2 执行，并限制长度和编译内存，
  避免恶意规则拖死扫描。真实 Qwen 当前代码复跑中，7/7 个攻击结果在模型下一步前被隔离，2/2
  个正常读取完成，真实上游副作用为 0。该成绩是看过攻击后的回归，不是新盲测；详见
  `specs/managed-scanner-rule-pack-v1.md`。

公开 NVIDIA Nemotron 固定语料回归结果：

- 攻击文本检出：`1257/1272`，`98.82%`；
- 检出证据与注入区间重合：`1257/1272`，`98.82%`；
- 配对干净文本误报：`1/1272`，`0.08%`；
- 数据集提供的正常用户请求误报：`0/1272`，`0%`。

这些规则看过该数据集，因此只能说明当前代码没有退步，不能说明对未知攻击也有 `98.82%`
泛化检出率。语义小模型不直接批准、放行或隔离内容；高风险旁路事件只能让同一次运行后续的
改写类动作进入人工审批。

Microsoft LLMail-Inject Phase 2 固定公开挑战数据复跑结果：

- 真人自适应攻击尝试：规则检出 `686/21007`，旁路小模型检出 `19425/21007`，并集检出
  `19495/21007`，即 `92.80%`；
- 其中来源挑战系统实际触发目标 API 的攻击：并集检出 `3030/3165`，即 `95.73%`；
- 正常邮件：规则、小模型和并集误报均为 `0/203`；Wilson 95% 置信上界为 `1.86%`。

LLMail 是静态外部内容扫描，不执行 Agent 或工具，不能解释为未授权动作阻断率。当前已是同一
固定数据的复跑，不再称为新盲测；小模型仍只旁路观察。可复现入口和数据摘要见
`specs/llmail-benchmark-v1.md`。

## 上线前剩余门槛

1. 修复 Docker 守护进程到镜像仓库的稳定链路，把已通过兼容性测试的 OPA `1.20.1` 官方镜像
   按摘要和签名镜像化复测，再接企业 TLS/身份/密钥托管的远程发布端；把已通过主机进程验证的
   Collector `0.160.0` 装入签名验证的官方镜像/PV，并接企业后端验证展示、搜索、告警和容量。
2. 把已通过的 OpenBao 三节点本地 TLS/Raft/叶证书换证/快照测试接入企业 PKI 自动签发、CA 信任
   轮换、包装令牌同步控制器、KMS/HSM 自动解封、五节点跨故障域和负载均衡器无感切换；
   给现有独立出口配置企业 S3 Object Lock 桶和云工作负载身份，实测写入后不能删除或缩短保留期。
3. Docker Hub 恢复后补拉 ToolHive 的网络隔离辅助镜像，验证细粒度域名/端口白名单；向企业私有 ToolHive 注册表登记签名者和源码来源，用已签名镜像完成来源校验正向测试。
4. AgentDojo 首次未见集已经证明当前模型未达标；更换候选模型后使用新的保留攻击集和中文正常
   难例重新盲测，达标前不让小模型直接拦截。
5. 补长任务、订阅等可选 MCP 能力；当前 SDK 的资源模板、补全和标准列表分页已完成，跨包工具主路径已固定 `1.9.4`、`1.29.1` 和 `2.1.1` 三个锚点。
6. 在不把模型服务密钥交给评测进程的前提下，用真实 Agent 跑正常任务和保留攻击集，报告真实
   未授权动作发生率、阻断率、任务完成率、误审批率和新增延迟。
