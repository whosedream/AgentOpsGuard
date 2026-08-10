import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from run_large_scale_test import TestResult as RunnerResult  # noqa: E402
from run_large_scale_test import generate_report  # noqa: E402


def result(case_id: str, *, is_attack: bool, action: str, scored: bool) -> RunnerResult:
    return RunnerResult(
        case_id=case_id,
        category="test",
        is_attack=is_attack,
        content_preview=case_id,
        risk_score=0.0,
        risk_labels=[],
        policy_action=action,
        detected=False,
        hard_blocked=action == "deny",
        approval_gated=False,
        redacted=False,
        source="mutation" if scored else "llm",
        scored=scored,
    )


def test_unreviewed_llm_candidates_are_excluded_from_scored_metrics():
    report = generate_report(
        [
            result("attack", is_attack=True, action="allow", scored=True),
            result("benign", is_attack=False, action="allow", scored=True),
            result("llm", is_attack=True, action="deny", scored=False),
        ]
    )

    assert "Total candidates:     3" in report
    assert "Scored attacks:     1" in report
    assert "LLM candidates (unreviewed): 1" in report
    action_section = report.split("POLICY ACTION DISTRIBUTION", maxsplit=1)[1]
    assert "  deny" not in action_section
