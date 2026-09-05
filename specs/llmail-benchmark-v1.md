# LLMail-Inject Phase 2 基准 v1

## 目的

用 Microsoft LLMail-Inject Phase 2 的公开挑战数据检验当前外部内容扫描能力。该数据来自真人
参与的自适应提示注入挑战，比项目内生成样本更接近主动绕过防护的攻击。

固定来源：

- 数据集：`microsoft/llmail-inject-challenge`
- revision：`1063bdf01ec8762b812d5e06ee768a06faa5a6f7`
- 攻击文件：`labelled_unique_submissions_phase2.json`
- 正常文件：`emails_for_fp_tests.json`
- 许可证：MIT

运行入口必须先核对两个文件的 SHA-256，不允许按浮动版本下载后直接比较结果。

## 样本和标签

攻击集只选择 `attack_attempt` 为布尔值 `true` 或字符串 `"True"` 的记录，共 `21,007`
条。按官方 `reason` 分成：

- `api_triggered`：`3,165` 条，来源挑战系统中实际触发了目标 API；
- `judge`：`17,842` 条，由来源数据集的判断器标为攻击尝试。

正常集为数据集提供的 `203` 封邮件。零误报仍要报告 Wilson 95% 区间，不能写成已证明线上
误报率为零。

## 评测方式

所有文本模拟为不可信 `mcp_tool_result`。每条分别运行：

1. 当前确定性扫描和内置策略；
2. 固定本地小模型、固定阈值 `0.90` 的旁路评分；
3. 两者取并集的发现结果。

旁路模型不得改变策略动作。报告分别输出规则、小模型和并集的检出数、正常误报、官方原因
切片、Wilson 95% 区间和延迟。不得输出攻击正文、正常邮件正文、逐条结果或逐条模型分数。

## 运行

将固定 revision 的两个数据文件放入
`~/.cache/huggingface/agentops-guard-benchmarks/llmail-inject-phase2/` 后执行：

```bash
uv run python scripts/run_llmail_benchmark.py --workers 6
```

默认输出为 `artifacts/benchmarks/llmail_inject_phase2_v1.json`，该目录不提交原始数据和本地
报告。

## 证据边界

这是静态外部内容扫描，不执行 Agent 或工具，也不等于未授权动作阻断率。当前复跑发生在数据
已经被项目使用之后，因此是可复现回归，不是新的盲测。第一次使用该数据时可以保留当时冻结
的实现摘要和结果证明“当时未参与调参”，但之后不能继续称同一数据为未知攻击。

## 2026-09-04 固定复跑结果

当前代码、固定模型和阈值 `0.90` 使用 6 个 CPU 进程完成 `21,210` 条评测：

- 全部攻击：规则 `686/21007`，旁路模型 `19425/21007`，并集 `19495/21007`
  （`92.80%`，Wilson 95% 区间 `92.45%–93.14%`）；
- `api_triggered`：并集 `3030/3165`（`95.73%`，Wilson 95% 区间
  `94.97%–96.38%`）；
- `judge`：并集 `16465/17842`（`92.28%`）；
- 正常邮件：规则、模型和并集均为 `0/203`；零误报的 Wilson 95% 上界为 `1.86%`。

6 个 CPU 进程并行竞争资源时，攻击样本的顺序扫描耗时 p50/p95 为
`171.41/259.44ms`；正常邮件为 `100.20/124.90ms`。该数据用于离线吞吐记录，不代表单请求
线上延迟。完整本地报告为 `artifacts/benchmarks/llmail_inject_phase2_v1.json`，报告未提交原始
文本或逐条结果。
