# AgentOps Guard 与 ContextForge 对照试验 v1

## 目的

用同一个无副作用 MCP 服务比较两套网关的协议兼容、策略行为、延迟、审计字段和部署成本。试验不评价界面，也不把 ContextForge 的默认行为误写成安全缺陷；它默认解决 MCP 聚合和治理，自研网关解决本项目特有的内容隔离、动作授权和审批。

## 固定条件

- ContextForge：`mcp-contextforge-gateway==1.0.7`
- PyPI 源码包 SHA-256：`ee68d3fa609aa7b97da68ca22c9e89a8c5e61395cf9efbea1f0df8015fcc6b55`
- 数据库：两套网关各自使用全新的 SQLite 文件。
- 语义小模型：关闭。否则测到的是模型推理时间，不是网关开销。
- ContextForge 限流：仅在延迟测试时关闭；默认每分钟限制会让 100 次连续请求返回 429。
- 测试工具：只读回显、结构化回显、固定间接注入文本、模拟写入。模拟写入不会修改真实数据。
- 凭据：启动脚本只在进程内随机生成开发用密钥，不写文件、不打印、不放入命令行参数。

## 公平边界

参考服务同时开放两个入口：

1. 标准 MCP Streamable HTTP `/mcp`，供 ContextForge 使用。
2. 兼容 REST `/tools/list`、`/tools/call`，供当前 AgentOps Guard 使用。

第二个入口是为了让现有实现能参加策略和延迟测试，不代表它已经支持标准 MCP。协议结论必须单独看标准 `initialize`、工具、资源和提示模板结果。

## 运行方法

在独立临时环境安装 ContextForge，不改项目依赖：

```bash
uv venv /tmp/agentops-contextforge-v1
uv pip install --python /tmp/agentops-contextforge-v1/bin/python mcp-contextforge-gateway==1.0.7
```

用该环境分别运行 `scripts/gateway_comparison_reference.py` 和 `scripts/run_contextforge_comparison.py`。ContextForge 启动后，向 `/v1/gateways` 注册参考服务的 `http://127.0.0.1:19090/mcp`，传输类型为 `STREAMABLEHTTP`。

AgentOps Guard 使用全新开发数据库，注册两个指向 `http://127.0.0.1:19090` 的服务：一个 `external` 用于测试未审查外部工具审批；一个 `internal` 用于让只读调用到达上游，从而测试返回内容隔离和基准延迟。

最后运行：

由受信测试运行器在进程环境中注入 `AGENTOPS_BENCHMARK_API_KEY`。脚本不接受命令行密钥，
也不把该值写入报告。

```bash
uv run python scripts/benchmark_gateway_comparison.py \
  --agentops-db /tmp/agentops-comparison.db \
  --contextforge-db /tmp/contextforge-comparison.db \
  --output artifacts/benchmarks/gateway_comparison_contextforge_v1.json
```

## 成功标准

- 同一组 4 个工具均可被发现并调用，结构化返回不丢失。
- 协议能力必须报告工具、资源、提示模板和标准初始化，不只报告 HTTP 200。
- 间接注入正文不得通过 AgentOps Guard 返回给 Agent。
- 未绑定可信用户要求的写操作不得经过 AgentOps Guard 到达上游。
- 延迟报告 100 次热调用的 p50、p95，并单列直接调用参考服务的基线。
- 部署数据记录全新 SQLite 数据库的冷启动时间、稳定后常驻内存和环境包数量。
- 报告只保留布尔行为、计数、字段名和版本信息，不保存调用正文、URL 参数或凭据。

## 解释限制

这是单机、单进程、SQLite、短文本的受控试验，不代表生产吞吐、集群稳定性或长期维护成本。ContextForge 插件策略未在本轮配置，因此只能得出“默认配置不会提供本项目的审批和内容隔离”，不能得出“无法接入这些能力”。

> 2026-08-24 状态说明：本试验和既有报告记录的是标准 MCP 上游迁移前的历史快照。
> 当前 AgentOps Guard 已通过官方 MCP Python SDK 接入标准 Streamable HTTP 上游，原兼容 REST
> 接口已明确命名为 `legacy_http`。需要重新比较当前性能时必须新建报告，不得沿用本文件对应的
> 旧延迟和协议结论。
