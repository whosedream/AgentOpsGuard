# Mission: Agent 测试系统

## Goal
创建一个基于 MiMo API 的 Agent 测试系统，端到端测试 AgentOps Guard 的防护能力。

## Evaluator
pytest + Playwright:
```
cd "D:\CodeField\AgentOps Guard" && python -m pytest tests/ --cov=src/agentops_guard --cov-report=term-missing --cov-fail-under=80 -x
cd "D:\CodeField\AgentOps Guard\dashboard" && npx playwright test
```

## Acceptance Criteria
- [ ] MiMo API 集成：能调用 MiMo 模型生成 Agent 行为
- [ ] 攻击用例库 ≥ 20 个用例（提示注入、凭据泄露、危险命令、工具劫持）
- [ ] 端到端测试：MiMo Agent → Gateway → Scanner/策略引擎 → 验证结果
- [ ] 评估报告：拦截率、误报率、漏报率统计
- [ ] Eval 系统集成：通过 API 创建 EvalSuite 并运行 EvalRun
- [ ] pytest 覆盖率 ≥ 80%
- [ ] Playwright E2E 覆盖核心流程
- [ ] Docker Compose 一键启动 7 个服务

## Spec
.omc/specs/deep-interview-agent-test-system.md
