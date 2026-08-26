from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.schemas import PolicyContext, ScanRequest
from agentops_guard.backend.services.policy import evaluate_builtin_policy
from agentops_guard.backend.services.scanner import scan_content


DATASET_NAME = "nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1"
DATASET_REVISION = "d738d4f361cc38bb4d7a42b9066776dade5332f5"
DATASET_SHA256 = "3329da17564a7eb287e2730fc7d6956e1f4fe51e8950ac4f110b3c37e78cf3b9"
DATASET_ROWS = 1272
DATASET_URL = (
    "https://huggingface.co/datasets/nvidia/"
    "Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1/resolve/"
    f"{DATASET_REVISION}/train.jsonl?download=true"
)
DEFAULT_DATASET_PATH = (
    Path.home() / ".cache/huggingface/agentops-guard-benchmarks/nemotron_agentic_ipi_v1_train.jsonl"
)
DEFAULT_OUTPUT_PATH = Path("artifacts/benchmarks/nemotron_agentic_ipi_v1.json")
IPI_RISK_LABELS = {
    "base64_obfuscation",
    "credential_exfiltration",
    "data_exfiltration",
    "hidden_html",
    "instruction_override",
    "markdown_link_trap",
    "system_prompt_override",
    "tool_hijacking",
}


@dataclass(frozen=True)
class BenchmarkCase:
    dataset_id: int
    category: str
    domain: str
    attack_context: str
    injection_start: int
    injection_end: int
    matched_clean_context: str
    benign_prompt: str


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_strings(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from iter_strings(item, (*path, str(key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_strings(item, (*path, str(index)))


def load_cases(
    path: Path,
    *,
    expected_sha256: str = DATASET_SHA256,
    expected_rows: int = DATASET_ROWS,
) -> list[BenchmarkCase]:
    actual_sha256 = file_sha256(path)
    if actual_sha256 != expected_sha256:
        raise ValueError(
            f"dataset SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )

    cases: list[BenchmarkCase] = []
    with path.open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            row = json.loads(line)
            injection_text = " ".join(row["injection"]["injection_text"].split())
            candidates = [
                (environment_path, text)
                for environment_path, text in iter_strings(row["environment"])
                if injection_text in " ".join(text.split())
            ]
            if not candidates:
                raise ValueError(f"row {line_number} has no injected environment string")
            candidates.sort(key=lambda item: (-len(item[1]), item[0]))
            attack_context = candidates[0][1]
            injection_pattern = re.compile(
                r"\s+".join(re.escape(part) for part in injection_text.split())
            )
            injection_match = injection_pattern.search(attack_context)
            if injection_match is None:
                raise ValueError(f"row {line_number} injection span could not be located")

            user_messages = [
                message["content"]
                for message in row["responses_create_params"]["input"]
                if message.get("role") == "user"
            ]
            if len(user_messages) != 1 or not isinstance(user_messages[0], str):
                raise ValueError(f"row {line_number} must contain exactly one text user message")

            cases.append(
                BenchmarkCase(
                    dataset_id=int(row["id"]),
                    category=str(row["attack_category"]),
                    domain=str(row["domain"]),
                    attack_context=attack_context,
                    injection_start=injection_match.start(),
                    injection_end=injection_match.end(),
                    matched_clean_context=(
                        attack_context[: injection_match.start()]
                        + attack_context[injection_match.end() :]
                    ),
                    benign_prompt=user_messages[0],
                )
            )

    if len(cases) != expected_rows:
        raise ValueError(f"dataset row mismatch: expected {expected_rows}, got {len(cases)}")
    return cases


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * quantile) - 1]


def run_benchmark(cases: list[BenchmarkCase]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for case in cases:
        for sample_kind, content, content_source, trust in (
            ("attack", case.attack_context, "mcp_tool_result", "untrusted"),
            (
                "matched_clean",
                case.matched_clean_context,
                "mcp_tool_result",
                "untrusted",
            ),
            ("benign_prompt", case.benign_prompt, "user_input", "trusted"),
        ):
            started = time.perf_counter_ns()
            scan = scan_content(
                ScanRequest(
                    content=content,
                    source=content_source,
                    metadata={"trust": trust},
                )
            )
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            decision = evaluate_builtin_policy(
                PolicyContext(
                    risk_score=scan.risk_score,
                    risk_labels=scan.risk_labels,
                    data={
                        "labels": scan.risk_labels,
                        "content_source": content_source,
                        "trust": trust,
                    },
                )
            )
            ipi_labels = sorted(set(scan.risk_labels) & IPI_RISK_LABELS)
            injection_localized = sample_kind == "attack" and any(
                evidence.label in IPI_RISK_LABELS
                and evidence.start < case.injection_end
                and evidence.end > case.injection_start
                for evidence in scan.evidence_spans
            )
            results.append(
                {
                    "dataset_id": case.dataset_id,
                    "sample_kind": sample_kind,
                    "content_source": content_source,
                    "trust": trust,
                    "category": case.category,
                    "domain": case.domain,
                    "detected_ipi": bool(ipi_labels),
                    "detected_any_risk": bool(scan.risk_labels),
                    "injection_localized": injection_localized,
                    "risk_score": scan.risk_score,
                    "risk_labels": scan.risk_labels,
                    "ipi_risk_labels": ipi_labels,
                    "policy_action": decision.action,
                    "latency_ms": round(elapsed_ms, 6),
                }
            )

    attacks = [result for result in results if result["sample_kind"] == "attack"]
    matched_clean = [result for result in results if result["sample_kind"] == "matched_clean"]
    benign_prompts = [result for result in results if result["sample_kind"] == "benign_prompt"]
    attack_detected = sum(result["detected_ipi"] for result in attacks)
    attack_localized = sum(result["injection_localized"] for result in attacks)
    matched_clean_detected = sum(result["detected_ipi"] for result in matched_clean)
    benign_prompt_detected = sum(result["detected_ipi"] for result in benign_prompts)
    attack_recall = attack_detected / len(attacks)
    injection_localized_recall = attack_localized / len(attacks)
    matched_clean_fpr = matched_clean_detected / len(matched_clean)
    benign_prompt_fpr = benign_prompt_detected / len(benign_prompts)

    slices: dict[str, dict[str, dict[str, float | int]]] = {}
    for field in ("category", "domain"):
        grouped: dict[str, defaultdict[str, list[dict[str, Any]]]] = {
            "attack": defaultdict(list),
            "matched_clean": defaultdict(list),
            "benign_prompt": defaultdict(list),
        }
        for result in results:
            grouped[result["sample_kind"]][result[field]].append(result)
        names = sorted(
            set(grouped["attack"]) | set(grouped["matched_clean"]) | set(grouped["benign_prompt"])
        )
        slices[field] = {
            name: {
                "attack_count": len(grouped["attack"][name]),
                "attack_detected": sum(
                    result["detected_ipi"] for result in grouped["attack"][name]
                ),
                "attack_recall": sum(result["detected_ipi"] for result in grouped["attack"][name])
                / len(grouped["attack"][name]),
                "attack_localized": sum(
                    result["injection_localized"] for result in grouped["attack"][name]
                ),
                "localized_recall": sum(
                    result["injection_localized"] for result in grouped["attack"][name]
                )
                / len(grouped["attack"][name]),
                "matched_clean_fpr": sum(
                    result["detected_ipi"] for result in grouped["matched_clean"][name]
                )
                / len(grouped["matched_clean"][name]),
                "benign_prompt_fpr": sum(
                    result["detected_ipi"] for result in grouped["benign_prompt"][name]
                )
                / len(grouped["benign_prompt"][name]),
            }
            for name in names
        }

    attack_actions = Counter(result["policy_action"] for result in attacks)
    matched_clean_actions = Counter(result["policy_action"] for result in matched_clean)
    benign_prompt_actions = Counter(result["policy_action"] for result in benign_prompts)
    latency_ms_by_sample = {
        sample_kind: {
            "p50": percentile(
                [
                    result["latency_ms"]
                    for result in results
                    if result["sample_kind"] == sample_kind
                ],
                0.50,
            ),
            "p95": percentile(
                [
                    result["latency_ms"]
                    for result in results
                    if result["sample_kind"] == sample_kind
                ],
                0.95,
            ),
        }
        for sample_kind in ("attack", "matched_clean", "benign_prompt")
    }
    summary = {
        "source_rows": len(cases),
        "attack_samples": len(attacks),
        "matched_clean_samples": len(matched_clean),
        "benign_prompt_samples": len(benign_prompts),
        "attack_ipi_detected": attack_detected,
        "attack_recall": attack_recall,
        "attack_injection_localized": attack_localized,
        "injection_localized_recall": injection_localized_recall,
        "matched_clean_ipi_detected": matched_clean_detected,
        "matched_clean_false_positive_rate": matched_clean_fpr,
        "benign_prompt_ipi_detected": benign_prompt_detected,
        "benign_prompt_false_positive_rate": benign_prompt_fpr,
        "balanced_accuracy_matched_clean": (attack_recall + 1 - matched_clean_fpr) / 2,
        "balanced_accuracy_benign_prompt": (attack_recall + 1 - benign_prompt_fpr) / 2,
        "attack_any_risk_rate": sum(result["detected_any_risk"] for result in attacks)
        / len(attacks),
        "matched_clean_any_risk_rate": sum(result["detected_any_risk"] for result in matched_clean)
        / len(matched_clean),
        "benign_prompt_any_risk_rate": sum(result["detected_any_risk"] for result in benign_prompts)
        / len(benign_prompts),
        "attack_hard_block_rate": sum(
            action in {"deny", "quarantine"} for action in (r["policy_action"] for r in attacks)
        )
        / len(attacks),
        "attack_approval_gate_rate": attack_actions["require_approval"] / len(attacks),
        "attack_redact_rate": attack_actions["redact"] / len(attacks),
        "attack_non_allow_rate": sum(result["policy_action"] != "allow" for result in attacks)
        / len(attacks),
        "matched_clean_non_allow_rate": sum(
            result["policy_action"] != "allow" for result in matched_clean
        )
        / len(matched_clean),
        "benign_prompt_non_allow_rate": sum(
            result["policy_action"] != "allow" for result in benign_prompts
        )
        / len(benign_prompts),
        "attack_policy_actions": dict(sorted(attack_actions.items())),
        "matched_clean_policy_actions": dict(sorted(matched_clean_actions.items())),
        "benign_prompt_policy_actions": dict(sorted(benign_prompt_actions.items())),
        "latency_ms_by_sample": latency_ms_by_sample,
        "slices": slices,
    }
    return {"summary": summary, "results": results}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args()

    cases = load_cases(args.dataset)
    report = run_benchmark(cases)
    repository_root = Path(__file__).resolve().parents[3]
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        cwd=repository_root,
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
            cwd=repository_root,
        ).stdout
    )
    implementation_paths = [
        "pyproject.toml",
        "src/agentops_guard/backend/config.py",
        "src/agentops_guard/backend/services/content.py",
        "src/agentops_guard/backend/services/policy.py",
        "src/agentops_guard/backend/services/scanner.py",
        "src/agentops_guard/backend/services/semantic_scanner.py",
        "src/agentops_guard/benchmarks/nemotron_ipi.py",
        "uv.lock",
    ]
    report["metadata"] = {
        "created_at": datetime.now(UTC).isoformat(),
        "git_commit": commit,
        "git_dirty": dirty,
        "scope": "static scan_content plus evaluate_builtin_policy",
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "scanner_plugins": get_settings().scanner_plugins,
        },
        "implementation_sha256": {
            relative_path: file_sha256(repository_root / relative_path)
            for relative_path in implementation_paths
        },
        "evaluation": {
            "ipi_risk_labels": sorted(IPI_RISK_LABELS),
            "primary_attack_metric": "IPI-labelled finding anywhere in injected environment context",
            "localized_metric": "IPI-labelled evidence span overlaps the injected text span",
            "interpretation": (
                "Regression result on a dataset inspected during rule development; "
                "not an independent generalization estimate."
            ),
            "negative_controls": [
                "derived matched environment string with the injected span removed",
                "dataset-provided benign user prompt",
            ],
        },
        "dataset": {
            "name": DATASET_NAME,
            "creator": "NVIDIA Corporation",
            "revision": DATASET_REVISION,
            "url": DATASET_URL,
            "sha256": DATASET_SHA256,
            "rows": DATASET_ROWS,
            "license": "CC BY 4.0",
            "license_url": "https://creativecommons.org/licenses/by/4.0/",
            "changes": (
                "Selected one injected environment string per row, derived a matched-clean "
                "control by removing the injection span, and emitted per-row aggregate results "
                "without copying raw dataset text."
            ),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = report["summary"]
    print(f"dataset rows: {summary['source_rows']}")
    print(
        f"attack recall: {summary['attack_recall']:.2%} "
        f"({summary['attack_ipi_detected']}/{summary['attack_samples']})"
    )
    print(
        f"injection-localized recall: {summary['injection_localized_recall']:.2%} "
        f"({summary['attack_injection_localized']}/{summary['attack_samples']})"
    )
    print(
        f"matched-clean FPR: {summary['matched_clean_false_positive_rate']:.2%} "
        f"({summary['matched_clean_ipi_detected']}/{summary['matched_clean_samples']})"
    )
    print(
        f"benign-prompt FPR: {summary['benign_prompt_false_positive_rate']:.2%} "
        f"({summary['benign_prompt_ipi_detected']}/{summary['benign_prompt_samples']})"
    )
    for sample_kind, latency in summary["latency_ms_by_sample"].items():
        print(f"{sample_kind} p50/p95 latency: {latency['p50']:.3f}/{latency['p95']:.3f} ms")
    print(f"report: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
