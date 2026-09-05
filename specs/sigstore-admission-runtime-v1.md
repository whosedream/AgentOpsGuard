# Sigstore 镜像准入现场证据 v1

日期：2026-09-05

## 结论

项目已经在真实 Kubernetes `1.34.0` 集群中证明“命名空间启用后，无签名或验证基础设施故障时不
放行”，但尚未证明“正确签名能放行”。因此这是部分真实证据，发布门槛仍然保留。

## 复用与固定

- 直接复用 Sigstore 官方 policy-controller，不自研准入 webhook；
- 官方 Helm chart `0.10.7` 包 SHA-256：
  `c5c7f0c421fdeb3944cdfd6706cb51d40e872b4a37fbecba03f8d35547c1e513`；
- controller `0.15.1` 镜像索引摘要：
  `sha256:0492bb264fb1d9bdc8e3f343ef542cc85b7dd7c7fd8d9524b453c2bd31a1d128`；
- Linux/amd64 清单摘要：
  `sha256:0a5806a61e0482e56153ae2ce6f6707846ffe0f9e3cd4be58655fbf88b874a3c`；
- 生产配置使用双副本、`failurePolicy: Fail`、`no-match-policy: deny`，关闭运行时联网更新信任根；
- 管理员创建只包含公开验证材料的 `TrustRoot`，项目策略只引用其名字，不接收私钥或仓库凭据。

## 已证明

1. 命名空间只有明确加上 `policy.sigstore.dev/include=true` 才进入准入范围；
2. 两类 webhook 都使用 `failurePolicy: Fail`；
3. 官方 controller `0.13.1` 对符合项目仓库范围、但没有签名的摘要明确返回“没有签名”并拒绝；
4. controller `0.15.1` 能读取管理员托管且 Ready 的 `TrustRoot`，项目
   `ClusterImagePolicy` 同样达到 Ready；
5. 两个 controller 副本都停止后，新建 Pod 因 webhook 不可达而被拒绝；
6. 恢复到 2/2 Ready 用时 20.442 秒，重启数为 0；
7. controller 无法访问公共镜像仓库时，请求超时并拒绝，没有绕过验证放行。

固定报告位于 `artifacts/verification/sigstore-admission-partial-v1.json`，SHA-256 为
`9631ae56a5201c837e7a1e4993e928f21fae5253f1a2285a35f17857175899df`。报告不包含凭据、镜像拉取
口令或业务正文；`scripts/verify_sigstore_admission_artifact.py` 会同时核对报告摘要与当前生产配置。

## 尚未证明

- `0.15.1` 在可达私有仓库中放行正确签名镜像；
- 拒绝错误签名者、签名后内容变化和名称相似的冒名仓库；
- 真实生产 CNI、镜像仓库、证书、代理和多节点控制面；
- 托管信任根的企业更新、回滚、吊销和灾备流程。

清除发布门槛时，必须在预生产环境按最终镜像、最终身份和最终仓库重新跑正反测试，不能用本地
kind 结果代替。
