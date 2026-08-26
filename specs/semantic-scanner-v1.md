# Semantic Scanner v1

## 目标

在现有确定性扫描之后增加一个本地小模型，用来发现规则没有覆盖的提示注入。第一版只以
`shadow` 模式上线：记录模型判断，但不改变现有风险分数、标签、脱敏结果或网关动作。

本版本固定使用：

- 模型：`patronus-studio/wolf-defender-prompt-injection-small`
- revision：`eff31df5c97ca127b7b55da255a160f88a625c97`
- 许可证：Apache-2.0
- 初始高分阈值：`0.90`

revision 是模型来源标识，不等同于本地文件校验。部署时还必须提供本地权重文件的
SHA-256。代码同时固定 `manifest.json` 的摘要，并逐项核对权重、配置、分词器和特殊 token
文件；只换其中任意一个文件都会在模型加载前失败。目录中如果出现清单外的运行文件（例如
`added_tokens.json`），也必须拒绝加载，避免 Transformers 自动读取未评测的附加配置。

## 运行边界

模型只能从绝对本地目录加载。运行时禁止联网下载，加载参数必须是
`local_files_only=True` 和 `trust_remote_code=False`。本地目录内的主权重文件固定为
`model.safetensors`，启动时必须在创建模型实例之前核对
`AGENTOPS_SEMANTIC_MODEL_SHA256`。路径不存在、不是绝对目录、权重不存在或摘要不一致都要
立即报错，不能换用网络模型、缓存中的另一个版本或规则扫描作为静默回退。

配置名称：

- `AGENTOPS_SEMANTIC_SCANNER_MODE`：`disabled`、`shadow` 或 `enforce`；应用默认
  `disabled`。当前版本的配置边界会拒绝 `enforce`；只有重新评测通过并修改该门禁后才能启用。
- `AGENTOPS_SEMANTIC_MODEL_PATH`：本地模型目录。
- `AGENTOPS_SEMANTIC_MODEL_SHA256`：该目录中 `model.safetensors` 的小写十六进制
  SHA-256。
- `AGENTOPS_SEMANTIC_SCANNER_THRESHOLD`：默认 `0.90`。

同一进程中，相同路径和摘要只创建一个模型后端。不得在每次扫描时重新读权重。

## 扫描范围

只扫描以下外部来源：

- `mcp_tool_result`
- `mcp_resource`
- `mcp_prompt`
- `external`

明确跳过 `user_input`、`mcp_tool_arguments`、`mcp_tool_description` 和 `eval`。工具列表可能
一次带回大量说明，逐条跑模型会放大为拒绝服务；工具说明继续由确定性规则扫描。未知来源也
跳过；新增来源必须先明确其信任边界，再加入允许列表。

长文本不能只看开头。为了避免一条超长外部内容占满内存，进入 tokenizer 前最多保留固定的
`512` 个字符，均匀覆盖头部、中部和尾部；模型按 2048 token 上限做带重叠滑窗，极端分词
情况下最多取 `2` 个窗口，每批只推理 `1` 个窗口，最后取最高恶意概率。单元测试确认尾部仍
被覆盖，并用假 tokenizer 核对窗口总数和批大小。

同一进程只允许一个语义推理占用模型。并发请求不排队等待：`shadow` 记录固定的不可用事件后
继续沿用确定性扫描结果；未来的 `enforce` 必须快速失败，避免并发外部内容耗尽网关线程和
模型内存。

## 密钥和可观察性边界

模型输入必须是 `redact_text` 处理后的副本。已知 API key、token、密码等不得以原文进入
tokenizer、模型、异常、日志、指标标签、审计描述或 `SemanticAssessment`。原始
`ScanRequest` 只供既有确定性扫描使用，不能传给模型后端。

受管凭据仍由 `credential_ref` 和受信执行器保证，根本不会进入扫描正文。预处理还会替换常见
的 `password=...`、`token=...`、Bearer 和 URL 用户密码格式，但字符串规则不可能判断任意
普通文字是不是未知秘密。因此，如果部署要求“任何外部正文都必须被证明不含未知秘密”，就
必须保持语义扫描为 `disabled`；只有接受本地模型会读取已脱敏外部正文的部署才可启用
`shadow`。这条限制不能用“模型在本机”来掩盖。

外部来源中可解码、可读的 Base64 文本由确定性扫描器标为 `base64_obfuscation`；解码后的明文
不交给语义模型，证据也只保存固定占位符。

模型后端只接收脱敏文本，不接收 `ScanRequest`、凭据引用、URL 参数或其他上下文对象。日志
只允许记录固定错误码、模型固定标识、模式和耗时，不记录输入、token、窗口内容或模型
logits。

## 返回合同

`ScanResponse` 增加内部字段 `semantic_assessment`，类型为：

```text
SemanticAssessment(status, mode, label, score, model)
```

- `status`：`ok` 或 `error`。
- `mode`：本次运行的模式。
- `label`：有结果时为 `benign` 或 `prompt_injection`，否则为 `None`。
- `score`：内部概率，跳过或出错时为 `None`。
- `model`：固定为
  `patronus-studio/wolf-defender-prompt-injection-small@eff31df5c97ca127b7b55da255a160f88a625c97`。

模式关闭或来源不在允许列表时，`semantic_assessment` 为 `None`，且不创建模型后端。

该字段必须用 Pydantic 的 `Field(exclude=True)` 排除在 API、网关上游消息和持久化原文之外，
避免把精确阈值反馈给攻击者。测试可以直接读取内存中的字段。

## 模式行为

### `shadow`

- 高分和低分都只填写 `semantic_assessment`。
- 不改变原有 `risk_score`、`risk_labels`、`evidence_spans`、`sanitized_text`、severity 或
  网关动作。
- 受控模型错误返回 `status="error"`，并通过内部字段和固定错误指标可见；不得静默消失。
- 影子命中写入风险事件时只保存固定分数 `0.8`，不得保存模型精确概率。

### `enforce`

本次部署不启用该模式，但先固定其安全合同：

- 分数低于 `0.90` 时不改变原有扫描结果。
- 分数大于等于 `0.90` 时增加 `semantic_prompt_injection`，severity 为 `high`，风险分数
  至少为固定值 `0.80`。不要把模型精确分数复制成对外风险分数。
- 语义 finding 隔离整段外部内容；证据 snippet 只能是固定占位符，不能包含模型输入或原文。
- 模型加载或推理失败时抛出 `SemanticScannerUnavailable`，让请求中止；不得返回上游正文，
  不得伪造 finding 后继续，也不得回退为放行。

## 验收标准

1. 假后端证明仅四种外部来源进入模型，工具说明及受信或评测来源不进入模型。
2. 假后端收到的是已脱敏副本；密钥不出现在后端输入、日志或返回对象中。
3. `shadow` 的高分判断不改变旧扫描结果，且精确判断不出现在序列化响应中。
4. `enforce` 只有高分才产生 `semantic_prompt_injection`；低分保持旧结果。
5. `shadow` 错误可观察，`enforce` 错误快速失败。
6. 同一扫描器多次调用只加载一次模型。
7. 超过单窗口的文本末尾仍能被扫描。
8. 本地路径或 SHA-256 不符时，在后端加载前快速失败。
9. 单元测试不安装或调用真实 `torch`、`transformers`，真实模型效果和延迟另行作为集成评测
   报告，不能拿假后端测试冒充模型检出率。
10. 冻结题文件摘要和 `24` 条攻击、`18` 条正常样本结构由单元测试固定；真实模型可用下列命令
    重跑，报告不含样本文本或逐条分数：

```bash
uv run python scripts/evaluate_semantic_guard.py
```

## 2026-08-14 固定评测结论

模型 revision、阈值 `0.90` 和冻结题在运行前已经固定。冻结题文件 SHA-256 为
`7f7c19af25523a25d9690372943ede94a73a915301c6a913b543fe7c2291fad0`，权重 SHA-256 为
`0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0`。

- 冻结题：攻击检出 `20/24`，正常误报 `5/18`。
- NotInject：误报 `54/339`。
- Nemotron：模型单独检出 `1104/1272`，配对干净文本误报 `45/1272`；与现有规则合并后，
  检出从 `1257/1272` 增至 `1260/1272`，配对误报从 `1/1272` 增至 `46/1272`。
- Ryzen 5 5600、PyTorch float32、CPU 单线程、512 tokens：p50 `487.367ms`，p95
  `504.647ms`。
- RTX 4070 SUPER、同一权重和 512 tokens：本地补充测速 p50 `16.526ms`，p95
  `21.188ms`；该结果只证明当前 WSL GPU 的推理速度，不改变误报结论。

因此本版本只允许 `disabled` 或 `shadow`。不能用这组冻结题调高阈值后继续把结果称为盲测；
若更换模型、阈值或规则，应建立新的冻结题版本再评测。
