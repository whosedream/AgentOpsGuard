# Patroni Kubernetes 自动切主验证 v1

## 结论

本项目不自研数据库选主。验证环境固定复用 Patroni `4.1.4` 和 PostgreSQL `16`，并从 Patroni
官方三节点 Kubernetes 示例中保留 StatefulSet、Kubernetes 选主存储、主库 Service、角色标签与
命名空间内权限。官方参考清单固定为
`17187a3f7e9acb8cdda6d970cca4787ea739acbe9b0d668fb087436a746e955c`。
Patroni 的 MIT 许可证原文随测试运行镜像定义保存在
`evals/patroni-runtime/PATRONI-LICENSE.txt`，构建后位于镜像的标准许可证目录。
控制面分区使用摘要固定的 Toxiproxy `2.12.0`，其 MIT 许可证也随镜像保留。故障不自创通用混沌
框架，而是采用公开 `wb14123/jepsen-postgres-ha` 的核心检查：分区期间最多只能有一个真实可写主库。

2026-09-05 的本机真实演练在 Kubernetes `1.34.0` 的一次性 kind 集群上达到一主两备。两个备库
先确认重放完业务提交，再强制终止主库 Pod。固定 Service 在约 `3.821s` 后恢复查询；约
`13.106s` 后，新主库完成选举，原主库以新 Pod 身份重新加入为备库，集群恢复一主两备。
AgentOps Guard 的审批执行、后台任务和审计记录在切换后保持一致，可以继续写入，审计链验证通过。

随后准备另一组已提交业务状态，通过每个数据库 Pod 内仅监听回环地址的 Toxiproxy，断开当前主库
到 Kubernetes DCS 的连接，但保持客户端和复制数据路径可用。旧主停止写入，新主自动选出；连续
取样未发现双主，最大可写主库数为 `1`。固定 Service 约 `23.912s` 恢复查询，解除隔离后约
`28.914s` 恢复一主两备；分区前状态未丢失，分区后写入和审计链复核通过。

固定证据为
`artifacts/verification/patroni-kubernetes-failover-live-v1.json`，SHA-256 为
`73fb27ddf34ef4eeb49b6ec85836c098db30666aa46c764d62f8e7359cbf302d`。发布检查会同时验证证据、
当前 Patroni 版本、镜像摘要、同步复制参数、三节点拓扑、固定 Service、最小权限和中断预算。

## 安全边界

- 数据库和复制密码只在受信验证进程内随机生成，通过标准输入写入临时 Kubernetes Secret；
- 模型、命令参数、报告和日志均不接收密码或数据库连接串；
- Patroni 只有当前命名空间内读取和更新 Pod、Endpoints、ConfigMap 的权限，没有集群级权限，
  也没有删除权限；
- Kubernetes 令牌改为显式投影，只挂入 Patroni 容器；Toxiproxy 容器看不到该令牌，控制口只在
  Pod 内部回环地址监听；
- Pod 使用 restricted 安全基线、非 root 用户、只读根文件系统、移除 Linux capabilities；
- 业务探针从 Kubernetes Secret 注入认证字段，并始终使用同一个 Service 名称。

## 没有证明的事项

这是单机临时集群的自动切主和 DCS 分区自降级证据，不是生产高可用验收。官方说明正常情况下
Patroni 会在租约更新失败时停库，但进程卡死或停库过慢仍需硬件/内核看门狗保证。本次没有使用
持久卷，没有验证节点级或任意网络分区、可用区故障、硬件看门狗、数据库 TLS、生产镜像签名以及
真实负载下的恢复目标。生产环境应
优先使用企业已有的托管 PostgreSQL；如自建 Patroni，仍需由平台团队补齐跨故障域存储、入口、
证书、隔离和灾难演练。
