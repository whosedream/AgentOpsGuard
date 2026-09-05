# Keycloak OIDC 真实本地联调 v1

## 目的

证明 AgentOps Guard 不只是用测试密钥做 JWT 单元测试，而是能从真实身份服务取得工作负载令牌、
读取实时公钥并完成身份绑定。同时把“客户端已停用”和“停用前令牌立即失效”分开验证，避免误报
撤销能力。

## 固定运行时

- Keycloak `26.7.3` 官方 Linux 归档，SHA-256
  `77657f30b7e90d70f727712ce1c967f430fd6a5e9f458d32d8c6df0635345f47`；
- Eclipse Temurin JRE `21.0.12.1+1` 官方 Linux 归档，SHA-256
  `2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500`；
- Keycloak detached signature SHA-256
  `128903d42c4b10e189cc922a89b3671ab60b8dbcd4f6b90091bc21751e54b7e6`，签名者指纹
  `861AB50E8CC6611FB6BC01A6B8F12EA26FD6EEBA`；
- Temurin detached signature SHA-256
  `269a886dc5f1fc39bf640cc0a1a39473932a3f40f49492dcb81b0d09bc5822d6`，签名者指纹
  `3B04D753C9050D9A5D343F39843C48A565F8F04B`；
- 安装位置在 `~/.local/share/agentops-guard/keycloak/26.7.3-signed-v1`，发行缓存和运行时均不进入 Git。

`scripts/install_keycloak_oidc_runtime.py` 在解包前检查归档、签名和官方公钥摘要，在独立临时
GPG keyring 中核对唯一主键指纹和 detached signature；拒绝绝对路径、`..`、越界链接、设备
文件、setuid/setgid 位、异常成员数和过大内容。安装在同一文件系统的临时目录完成版本验证后原子
改名；目标已存在时拒绝覆盖。

`scripts/verify_keycloak_oidc_release_signature.py` 每次离线重验两份签名，并分别把发行归档修改一个
字节，确认签名验证失败。它不记录 GPG 输出或归档内容。Keycloak 官网当前把该 Keycloak Bot key
的用途列为 Maven artifact；因此本证据只说明下载归档确实由同一官方公开 key 签名，不能替代
容器镜像签名、构建证明或私有仓库准入。

## 真实检查

`scripts/verify_keycloak_oidc.py` 每次创建独立临时数据库和随机管理员口令/客户端密钥，只在受信
验证进程内部使用。Keycloak 只监听回环地址，标准输出和错误输出均不采集。检查包括：

1. 从真实发现文档取得 issuer 和 JWKS；
2. 用 client credentials 签发 60 秒工作负载令牌；
3. 本项目验证签名、issuer、audience 和有效期，并绑定 project、Agent 与 scopes；
4. 错 issuer、错 audience、篡改签名和真实等待过期的一秒令牌必须拒绝；
5. 新建更高优先级 RSA 密钥，确认新 `kid` 生效且新旧令牌都能验签；
6. 停用客户端后不能再签发令牌；
7. 明确确认停用前令牌在过期前仍被离线验签接受。

应用入口另限制令牌最大 16 KiB、签发到过期最长 15 分钟，并按数据库字段限制 subject、project、
Agent 和 scope 的长度与数量。超大令牌在请求 JWKS 前拒绝，重复、空、过多或含控制字符的 scope
不能进入授权判断。

最终输出只有布尔检查、公开版本和边界说明，不含口令、客户端密钥、令牌、claims、请求正文或
Keycloak 日志。临时数据库和秘密文件在停止进程后删除。

## 不能据此声称

该检查使用 Keycloak development mode、H2 和本机 HTTP，不代表企业人员目录、联邦登录、TLS、
生产数据库、高可用、入口网关可信转发或即时令牌撤销已完成。生产 OIDC 门槛保持打开；后续必须
在目标租户和入口环境中复跑，并选择“可接受短令牌窗口”或“受信在线内省/吊销”方案。
