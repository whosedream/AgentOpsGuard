# OpenBao 签名运行时来源验收 v1

## 目标

确保三节点和 Proxy 验收使用的不是“名字也叫 `bao`”的未知文件，而是 OpenBao 官方发布流程签署的
`2.6.1` Linux/amd64 归档中的原始二进制。

## 固定发布件

- 版本：`2.6.1`
- 提交：`ba7ad8861d0578cd4da4f7b9e5a6756d30484f8f`
- 归档：`openbao_2.6.1_linux_amd64.tar.gz`
- 归档 SHA-256：`ca8d836eb3a5c80407e45e762300b64e7138c419e78826955f2e4ba4ce6d8a6b`
- `bao` SHA-256：`736b8ecf354fda6b2af62e4ae064f12fe6c52d7db8425b9c6de22f286a5485ec`
- 签名身份：`https://github.com/openbao/openbao/.github/workflows/release.yml@refs/heads/release/2.6.x`
- 签发方：`https://token.actions.githubusercontent.com`

签名身份和签发方来自 OpenBao 官方安装说明。验收使用项目已经固定并验证来源的 Cosign `3.1.2`
和离线 Sigstore 可信根，不接受宽泛身份正则。

## 安装与验证

`scripts/install_openbao_current_runtime.py` 要求调用者提供官方归档、`checksums.txt`、校验清单的
Sigstore bundle 和归档自身的 Sigstore bundle。安装器依次执行：

1. 核对四个输入、Cosign 和可信根的固定摘要与大小；
2. 按准确身份和签发方离线验证校验清单；
3. 要求清单恰好一次把固定归档名绑定到固定摘要；
4. 独立验证归档自身签名；
5. 拒绝链接、特殊文件、额外路径和超出上限的归档成员；
6. 提取 `bao` 到同一文件系统的临时文件，核对二进制摘要和完整版本输出后原子替换；
7. 把公开归档和证明以只读方式保存在 Git 工作区外。

`scripts/verify_openbao_release_signature.py` 在每次发布时离线重验以上证据，确认安装二进制仍与
签名归档一致，并分别将归档和清单修改一个字节，要求 Cosign 拒绝。三节点运行脚本也直接核对
该二进制摘要，不能绕过来源检查单独运行未知 `bao`。

## 尚未证明

- 生产容器镜像的签名和镜像内容与该归档一致；
- 私有仓库镜像复制、准入策略和实际发布流水线成功；
- 未来版本升级的兼容、回滚和滚动升级行为。

参考：

- <https://openbao.org/docs/install/>
- <https://github.com/openbao/openbao/releases/tag/v2.6.1>
