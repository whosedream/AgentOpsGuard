import hashlib
import json
from pathlib import Path

import pytest

from agentops_guard.benchmarks.llmail_inject import (
    BenchmarkSample,
    EvaluationResult,
    load_samples,
    summarize_results,
    wilson_interval,
)


def write_json(path: Path, value: object) -> str:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_load_samples_verifies_hashes_and_official_selection(tmp_path: Path):
    attack_path = tmp_path / "attacks.json"
    benign_path = tmp_path / "benign.json"
    attack_hash = write_json(
        attack_path,
        {
            "api attack": {"attack_attempt": True, "reason": "api_triggered"},
            "judge attack": {"attack_attempt": "True", "reason": "judge"},
            "unclear": {"attack_attempt": "Unclear", "reason": "judge"},
        },
    )
    benign_hash = write_json(benign_path, ["normal email"])

    samples = load_samples(
        attack_path,
        benign_path,
        expected_attack_sha256=attack_hash,
        expected_benign_sha256=benign_hash,
        expected_attack_rows=2,
        expected_benign_rows=1,
    )

    assert samples == [
        BenchmarkSample("attack", "api attack", "api_triggered"),
        BenchmarkSample("attack", "judge attack", "judge"),
        BenchmarkSample("benign", "normal email"),
    ]


def test_load_samples_rejects_changed_dataset(tmp_path: Path):
    attack_path = tmp_path / "attacks.json"
    benign_path = tmp_path / "benign.json"
    write_json(attack_path, {})
    benign_hash = write_json(benign_path, [])

    with pytest.raises(ValueError, match="attack dataset SHA-256 mismatch"):
        load_samples(
            attack_path,
            benign_path,
            expected_attack_sha256="0" * 64,
            expected_benign_sha256=benign_hash,
            expected_attack_rows=0,
            expected_benign_rows=0,
        )


def result(
    kind: str,
    reason: str | None,
    regex_flagged: bool,
    model_flagged: bool,
    action: str,
) -> EvaluationResult:
    return EvaluationResult(
        kind=kind,
        official_reason=reason,
        regex_flagged=regex_flagged,
        any_rule_risk=regex_flagged,
        model_flagged=model_flagged,
        policy_action=action,
        regex_latency_ms=1.0,
        model_latency_ms=9.0,
    )


def test_summary_separates_rules_shadow_model_reasons_and_benign():
    summary = summarize_results(
        [
            result("attack", "api_triggered", True, False, "require_approval"),
            result("attack", "judge", False, True, "allow"),
            result("benign", None, False, False, "allow"),
        ]
    )

    assert summary["attack"]["regex_flagged"] == 1
    assert summary["attack"]["model_flagged"] == 1
    assert summary["attack"]["combined_flagged"] == 2
    assert summary["attack_by_official_reason"]["api_triggered"]["rows"] == 1
    assert summary["attack_by_official_reason"]["judge"]["rows"] == 1
    assert summary["benign"]["combined_flagged"] == 0
    assert summary["attack"]["rule_policy_actions"] == {
        "allow": 1,
        "require_approval": 1,
    }


def test_zero_false_positives_reports_nonzero_uncertainty():
    lower, upper = wilson_interval(0, 203)

    assert lower == 0
    assert upper == pytest.approx(0.018572)
