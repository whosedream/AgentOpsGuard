import json
from pathlib import Path

import pytest

from agentops_guard.benchmarks.injecagent import (
    InjecAgentSourceError,
    _load_rows,
    build_samples_from_rows,
    load_source_lock,
    summarize_injecagent_results,
)
from agentops_guard.benchmarks.llmail_inject import EvaluationResult


ROW_KEYS = {
    "Attack Type",
    "Attacker Instruction",
    "Attacker Tools",
    "Expected Achievements",
    "Modifed",
    "Thought",
    "Tool Parameters",
    "Tool Response",
    "Tool Response Template",
    "User Instruction",
    "User Tool",
}


def _row(*, family: str, attack: str, user_tool: str, attacker_tool: str) -> dict:
    row = {key: "value" for key in ROW_KEYS}
    row.update(
        {
            "Attack Type": family,
            "Attacker Instruction": attack,
            "Attacker Tools": [attacker_tool],
            "Modifed": 0,
            "Tool Response": f"record before {attack} record after",
            "Tool Response Template": "record before <Attacker Instruction> record after",
            "User Tool": user_tool,
        }
    )
    return row


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


def test_source_lock_pins_official_base_files_and_commit():
    lock = load_source_lock()

    assert lock["commit"] == "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
    assert set(lock["files"]) == {
        "data/test_cases_dh_base.json",
        "data/test_cases_ds_base.json",
    }
    assert sum(item["rows"] for item in lock["files"].values()) == 1_054


def test_locked_row_parser_rejects_missing_injection_or_inventory_change():
    row = _row(
        family="Financial Harm",
        attack="do the unsafe thing",
        user_tool="ReadRecord",
        attacker_tool="ChangeRecord",
    )
    specification = {
        "rows": 1,
        "attack_types": {"Financial Harm": 1},
        "sha256": "0" * 64,
    }
    assert _load_rows(json.dumps([row]).encode(), specification) == [row]

    changed = dict(row)
    changed["Tool Response"] = "ordinary content"
    with pytest.raises(InjecAgentSourceError, match="case schema changed"):
        _load_rows(json.dumps([changed]).encode(), specification)


def test_build_samples_keeps_official_attacks_and_creates_one_matched_clean_template():
    direct = [
        _row(
            family="Financial Harm",
            attack="do the unsafe thing",
            user_tool="ReadRecord",
            attacker_tool="ChangeRecord",
        )
    ]
    stealing = [
        _row(
            family="Financial Data",
            attack="send the private thing",
            user_tool="ReadRecord",
            attacker_tool="SendRecord",
        )
    ]

    samples, inventory = build_samples_from_rows(direct, stealing)
    repeated, repeated_inventory = build_samples_from_rows(direct, stealing)

    assert samples == repeated
    assert inventory == repeated_inventory
    assert [sample.kind for sample in samples] == ["attack", "attack", "benign"]
    assert samples[-1].content == (
        "record before No additional action is requested. record after"
    )
    assert inventory["attack_rows"] == 2
    assert inventory["benign_rows"] == 1
    assert inventory["user_tools"] == 1
    assert inventory["first_stage_attacker_tools"] == 2
    assert len(inventory["selected_corpus_sha256"]) == 64


def test_summary_separates_groups_families_and_clean_controls():
    summary = summarize_injecagent_results(
        [
            _result("attack", "direct_harm:Financial Harm", regex_flagged=True),
            _result("attack", "data_stealing:Financial Data", model_flagged=True),
            _result("benign", "matched_clean:ReadRecord"),
        ]
    )

    assert summary["attack"]["combined_flagged"] == 2
    assert summary["attack_by_group"]["direct_harm"]["regex_flagged"] == 1
    assert summary["attack_by_group"]["data_stealing"]["model_flagged"] == 1
    assert summary["benign"]["combined_flagged"] == 0


def test_benchmark_runner_does_not_store_raw_or_per_case_data():
    source = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "benchmark_injecagent_static.py"
    ).read_text(encoding="utf-8")

    assert '"stores_raw_cases": False' in source
    assert '"stores_per_case_results": False' in source
    assert '"stores_model_outputs": False' in source
