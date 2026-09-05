import json
from pathlib import Path
from runpy import run_path

import pytest

from agentops_guard.benchmarks.bipia import (
    BipiaSourceError,
    _attacks,
    _json_lines,
    build_samples_from_payloads,
    load_source_lock,
    summarize_bipia_results,
)
from agentops_guard.benchmarks.llmail_inject import EvaluationResult


def _result(
    kind: str,
    reason: str,
    *,
    regex_flagged: bool = False,
    model_flagged: bool = False,
) -> EvaluationResult:
    return EvaluationResult(
        kind=kind,
        official_reason=reason,
        regex_flagged=regex_flagged,
        any_rule_risk=regex_flagged,
        model_flagged=model_flagged,
        policy_action="require_approval" if regex_flagged else "allow",
        regex_latency_ms=1.0,
        model_latency_ms=2.0,
    )


def test_build_samples_reproduces_end_insertion_without_retaining_cases():
    contexts = {
        "email": [{"context": "email context"}],
        "table": [{"context": "table context"}],
        "code": [{"context": ["line one", "line two"]}],
    }
    text_attacks = {"text_family": ["text attack"]}
    code_attacks = {"code_family": ["code attack"]}

    samples, inventory = build_samples_from_payloads(
        contexts, text_attacks, code_attacks
    )
    repeated_samples, repeated_inventory = build_samples_from_payloads(
        contexts, text_attacks, code_attacks
    )

    assert samples == repeated_samples
    assert inventory == repeated_inventory
    assert inventory["attack_rows_by_task"] == {"code": 1, "email": 1, "table": 1}
    assert inventory["benign_rows_by_task"] == {"code": 1, "email": 1, "table": 1}
    assert inventory["selected_corpus_sha256"] == (
        "a011c7485b8d668e53841f736033a2ed4385166c150309d20e5d1690401844f6"
    )
    assert [sample.content for sample in samples if sample.kind == "attack"] == [
        "email context\ntext attack",
        "table context\ntext attack",
        "line one\nline two\ncode attack",
    ]


def test_bipia_parsers_reject_changed_inventories():
    assert load_source_lock()["commit"] == "a004b69ec0dd446e0afd461d98cb5e96e120a5d0"
    with pytest.raises(BipiaSourceError, match="row inventory"):
        _json_lines(b'{"context":"one"}\n', expected_rows=2)
    with pytest.raises(BipiaSourceError, match="attack inventory"):
        _attacks(
            json.dumps({"family": ["only one"]}).encode(),
            expected_families=1,
            expected_variants=5,
        )


def test_summary_keeps_rule_model_union_and_task_slices_separate():
    summary = summarize_bipia_results(
        [
            _result("attack", "email:family", regex_flagged=True),
            _result("attack", "table:family", model_flagged=True),
            _result("attack", "code:family"),
            _result("benign", "email:benign"),
            _result("benign", "table:benign", model_flagged=True),
            _result("benign", "code:benign"),
        ]
    )

    assert summary["attack"]["regex_flagged"] == 1
    assert summary["attack"]["model_flagged"] == 1
    assert summary["attack"]["combined_flagged"] == 2
    assert summary["by_task"]["email"]["attack"]["combined_flagged"] == 1
    assert summary["by_task"]["table"]["benign"]["combined_flagged"] == 1
    assert summary["attack_by_family"]["code:family"]["combined_flagged"] == 0


def test_bipia_lock_compatibility_allows_only_the_reviewed_security_patch():
    root = Path(__file__).resolve().parents[1]
    verifier = run_path(str(root / "scripts" / "verify_bipia_static_artifact.py"))
    check = verifier["_assert_compatible_uv_lock"]
    baseline = "d08d64e32dfc4a83c4ee849bae165a5688f53b8102da10ab9e4aa01f69735554"
    current = "937de3efc0fa94e4e8c5288ea840af0148a5fddfe0d334277f5bc4d6b9040137"

    check(baseline=baseline, current=current)
    with pytest.raises(RuntimeError, match="contract changed"):
        check(baseline=baseline, current="0" * 64)
