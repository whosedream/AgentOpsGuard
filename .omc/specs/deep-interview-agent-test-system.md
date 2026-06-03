# Deep Interview Spec: Agent 测试系统

## Metadata
- Interview ID: autoresearch-agent-test
- Rounds: 3
- Final Ambiguity Score: 18%
- Type: brownfield
- Generated: 2026-06-03
- Threshold: 0.2
- Threshold Source: default
- Status: PASSED

## Clarity Breakdown
| Dimension | Score | Weight | Weighted |
|-----------|-------|--------|----------|
| Goal Clarity | 0.95 | 35% | 0.33 |
| Constraint Clarity | 0.80 | 25% | 0.20 |
| Success Criteria | 0.85 | 25% | 0.21 |
| Context Clarity | 0.90 | 15% | 0.14 |
| **Total Clarity** | | | **0.82** |
| **Ambiguity** | | | **18%** |

## Topology
| Component | Status | Description |
|-----------|--------|-------------|
| Agent 驱动层 | active | 用 MiMo API 作为 LLM 驱动，模拟 Agent 发起工具调用 |
| 攻击用例库 | active | 批量已知攻击用例（提示注入、凭据泄露、危险命令等） |
| 端到端测试链路 | active | MiMo Agent → Gateway → Scanner/策略引擎 → 结果验证 |
| 评估指标 | active | 拦截率、误报率、漏报率，输出结构化报告 |
| CI 集成 | active | pytest（80% 覆盖率）+ Playwright E2E |

## Goal
创建一个基于 MiMo API 的 Agent 测试系统，端到端测试 AgentOps Guard 的防护能力：
1. MiMo 作为 Agent 驱动，模拟真实 Agent 发起工具调用
2. 准备批量攻击用例（提示注入、凭据泄露、危险命令、工具劫持等）
3. 测试 Gateway 的拦截/放行/脱敏/审批全链路
4. 统计拦截率、误报率、漏报率，输出报告
5. 复用 Guard 已有 Eval 系统验证策略有效性
6. 满足 CI 要求：pytest 80% 覆盖率 + Playwright E2E

## Constraints
- 使用 MiMo API（base_url: https://api.xiaomimimo.com/v1, model: mimo-v2.5-pro）
- 端到端测试需要 Docker Compose 7 个服务全部运行
- 后端测试覆盖率 ≥ 80%
- 前端 Playwright E2E 覆盖核心流程
- 复用已有的 25 个 pytest 测试文件，不破坏现有测试
- 复用 Guard 的 Eval 系统（EvalSuite + EvalRun）

## Non-Goals
- 不测试 MiMo 模型本身的推理能力（只把它当 Agent 驱动）
- 不做 LLM 语义检测（当前 Scanner 是正则驱动）
- 不做性能压测（只验证功能正确性）
- 不修改 Guard 核心逻辑（只添加测试层）

## Acceptance Criteria
- [ ] MiMo API 集成：能调用 MiMo 模型生成 Agent 行为（工具调用、攻击尝试）
- [ ] 攻击用例库 ≥ 20 个用例，覆盖提示注入、凭据泄露、危险命令、工具劫持
- [ ] 端到端测试：MiMo Agent 发起请求 → Gateway 拦截/放行 → 验证结果
- [ ] 评估报告：自动生成拦截率、误报率、漏报率统计
- [ ] Eval 系统集成：能通过 API 创建 EvalSuite 并运行 EvalRun
- [ ] pytest 覆盖率 ≥ 80%，所有新测试通过
- [ ] Playwright E2E 覆盖核心页面导航和 RBAC
- [ ] Docker Compose 一键启动全部 7 个服务

## Assumptions Exposed & Resolved
| Assumption | Challenge | Resolution |
|------------|-----------|------------|
| 正则检测太弱 | 需要 LLM 语义检测 | 当前只测正则能力，插件架构预留扩展口 |
| MiMo 能生成攻击用例 | 模型可能不够强 | 先用预定义用例，MiMo 作为可选增强 |
| Eval 系统够用 | 只验证 label/decision | 先复用已有能力，不够再扩展 |

## Technical Context
已有基础设施：
- 25 个 pytest 测试文件，使用 TestClient + monkeypatch + httpx.MockTransport
- Playwright E2E：mock-stack.mjs 模拟后端，4 个 RBAC 测试
- Eval 系统：EvalSuite + EvalRun，支持 risk_labels/policy_decisions/forbidden_tools 验证
- Gateway：tools_call 前置策略 → 执行 → 后置扫描 → 条件再评估
- Scanner：7 条内置正则 + 插件架构
- 策略引擎：三层（OPA → PolicyPack → 内置规则）

新增组件：
- MiMo 客户端：封装 API 调用，生成 Agent 行为
- 攻击用例库：YAML/JSON 格式，覆盖多类攻击
- 测试编排：pytest fixture 编排端到端流程
- 报告生成：统计拦截率等指标

## Ontology (Key Entities)
| Entity | Type | Fields | Relationships |
|--------|------|--------|---------------|
| MiMoAgent | core | api_key, model, base_url | generates AgentActions |
| AttackCase | core | name, input, tool, expected_labels, expected_action | belongs_to CaseLibrary |
| CaseLibrary | core | name, cases[] | used_by TestRun |
| TestRun | core | agent, cases[], results[] | produces Report |
| Report | core | total, passed, failed, interception_rate, false_positive_rate | generated_by TestRun |
| EvalSuite | existing | name, cases[] | run by EvalRun |
| EvalRun | existing | suite_id, results[] | validates PolicyEngine |

## Evaluator
```
cd "D:\CodeField\AgentOps Guard" && python -m pytest tests/ --cov=src/agentops_guard --cov-report=term-missing --cov-fail-under=80 -x
```
Plus Playwright E2E:
```
cd "D:\CodeField\AgentOps Guard\dashboard" && npx playwright test
```
