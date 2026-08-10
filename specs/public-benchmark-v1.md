# Public Prompt-Injection Benchmark v1

## Dataset contract

- Dataset: NVIDIA `Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1`
- License: CC BY 4.0
- Revision: `d738d4f361cc38bb4d7a42b9066776dade5332f5`
- File: `train.jsonl`
- SHA-256: `3329da17564a7eb287e2730fc7d6956e1f4fe51e8950ac4f110b3c37e78cf3b9`
- Expected rows: 1,272

The runner must fail before evaluation when the file hash or row count differs.

## Evaluation contract

Each source row produces three static scanner inputs:

1. Attack: the longest environment string containing the whitespace-normalized
   `injection.injection_text`. Ties are resolved by environment path.
2. Matched-clean negative control: the same selected environment string with the located
   injection span removed. This is a derived control, not an official dataset split.
3. Benign-prompt negative control: the single user message in `responses_create_params.input`, which the
   dataset card describes as the benign user request.

Primary prompt-injection detection is limited to the declared `IPI_RISK_LABELS`; any scanner
risk remains a separate operational metric. The report must keep injection-localized detection,
hard block (`deny`/`quarantine`), approval gate, redaction, and any non-allow action separate. It
must report attack recall, both negative-control false-positive rates, category/domain slices for
recall and false positives, policy action counts, and per-input-kind scan latency. There is no
arbitrary pass threshold.

## Evidence boundary

This is a static external stress test of `scan_content` plus the built-in policy. It does not run
an agent, execute tools, evaluate utility, or validate raw shell-command coverage. The dataset is
synthetic and contains attacks selected for bypassing a particular defender, so results are not a
production-wide safety rate. Do not tune rules on this full file and then describe the rerun as an
independent evaluation.

The generated report attributes NVIDIA Corporation, links the CC BY 4.0 license, and records the
selection/derivation performed here. It contains row identifiers and aggregate outcomes, not raw
dataset text.
