from agentops_guard.backend.schemas import PolicyContext
from agentops_guard.backend.services.policy import evaluate_policy


def test_policy_denies_dangerous_command():
    decision = evaluate_policy(
        PolicyContext(
            actor={"agent_id": "coding-agent"},
            tool={"name": "shell.execute", "command": "rm -rf /"},
        )
    )
    assert decision.action == "deny"
    assert decision.reason_code == "dangerous_command"


def test_policy_denies_data_exfiltration():
    decision = evaluate_policy(
        PolicyContext(
            tool={"name": "http.post"},
            risk_score=0.95,
            risk_labels=["credential_exfiltration"],
            data={"labels": ["credential_exfiltration"]},
        )
    )
    assert decision.action == "deny"
    assert decision.reason_code == "data_exfiltration"


def test_policy_requires_approval_for_high_risk_tool():
    decision = evaluate_policy(PolicyContext(tool={"name": "filesystem.write"}))
    assert decision.action == "require_approval"
