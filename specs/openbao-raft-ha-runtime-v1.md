# OpenBao Raft 高可用与恢复验收 v1

## 目标

确认项目不是只在单节点开发模式下调用 OpenBao，而是能在真实的持久化 Raft 集群中保持
`credential_ref` 和审计签名能力。验证直接复用 OpenBao `2.6.1` 自带的 Raft、TLS、Proxy 与快照
接口，不在项目中另写密钥库或选主算法。

## 固定场景

`scripts/verify_openbao_raft_ha.py` 在临时目录启动三个真实 OpenBao 进程：

1. 每个节点使用独立的 Raft 数据目录和端口；临时测试 CA 为三个节点分别签发两版不同的叶证书；
2. 初始化第一个节点，另外两个节点通过官方 Raft 加入接口成为投票成员；
3. 配置 KV v2、不可导出的 Ed25519 Transit 密钥、最小权限 AppRole 和官方 OpenBao Proxy；
4. 应用只访问 Proxy 的回环地址，只持有不透明 `credential_ref`，不接收 OpenBao Token；
5. 按备用节点优先、主节点最后的顺序原子替换证书与私钥，向节点发送 SIGHUP；通过真实 TLS 握手
   确认所有证书指纹变化、进程号不变，且原 `credential_ref` 与 Transit 签名全程可用；
6. 保存包含凭据和 Transit 密钥的 Raft 快照，再写入一个快照后的非敏感标记；
7. 终止当前主节点，等待剩余两个节点选出新主节点；部署方给 Proxy 更新一次性包装身份和目标地址；
8. 验证原 `credential_ref` 仍可解析、Transit 仍可签名、快照后的写入已复制；
9. 通过官方快照接口恢复，验证原凭据和 Transit 能力仍在，而快照后的标记消失。

所有根令牌、解封份额、发放令牌和提供方密钥只存在于受信验证进程内存；RoleID 与一次性包装值只
写入权限为 `0600` 的临时文件，测试退出时整个临时目录被删除。子进程输出被丢弃，最终结果只包含
布尔值、节点数、版本、二进制摘要和切换耗时。

## 通过标准

- 三个节点都成为 Raft 投票成员，集群可容忍一个主节点进程退出；
- 不信任临时证书的客户端连接失败，显式信任后连接成功；
- 三个节点都通过 SIGHUP 加载不同的新叶证书，TLS 指纹改变而节点进程号不变；
- 换证期间同一 `credential_ref` 和 Transit 签名能力持续可用；
- 主节点故障和快照恢复后，同一 `credential_ref` 均可解析；
- 主节点故障和快照恢复后，不可导出 Transit 密钥均可继续签名；
- 快照后的标记已复制到新主节点，恢复后又按快照内容消失；
- 应用从未收到 OpenBao Token，输出不包含任何凭据或模型内容。

## 尚未证明

这是单机回环网络上的三进程真实子系统测试，不等于企业生产环境。以下内容仍保留为外部门槛：

- 企业 PKI 自动签发、CA 信任轮换和双向 TLS；本测试只轮换同一临时测试 CA 签发的叶证书；
- KMS/HSM 自动解封，测试目前使用一次性 Shamir 解封份额；
- 五节点跨故障域部署、企业负载均衡器的无感切换和持续压力下故障注入；
- 生产镜像签名以及备份异地耐久性。主机正式发布归档的签名来源由独立固定检查覆盖。

参考：

- <https://openbao.org/docs/internals/integrated-storage/>
- <https://openbao.org/docs/configuration/storage/raft/>
- <https://openbao.org/docs/commands/operator/raft/>
- <https://openbao.org/docs/2.4.x/api/system/storage/raft/>
- <https://openbao.org/docs/2.5.x/configuration/listener/tcp/>
