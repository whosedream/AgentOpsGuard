from uuid import uuid4

from fastapi.testclient import TestClient

from agentops_guard.backend.main import app
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.models import PolicyDecision
from agentops_guard.backend.services.policy import BUILTIN_POLICY_VERSION


client = TestClient(app)
headers = {"X-AgentOps-Api-Key": "dev-agentops-key"}


def test_project_config_policy_pack_approval_and_suppression_flow():
    created = client.post(
        "/v1/projects",
        headers=headers,
        json={
            "id": "v07_control",
            "name": "v0.7 Control",
            "retention_days": 14,
            "policy_fail_mode": "closed_for_high_risk",
            "metadata": {"owner": "platform"},
        },
    )
    assert created.status_code in {200, 409}

    updated = client.patch(
        "/v1/projects/v07_control",
        headers=headers,
        json={"store_raw_content": True, "retention_days": 21, "metadata": {"tier": "prod"}},
    )
    assert updated.status_code == 200
    assert updated.json()["store_raw_content"] is True
    assert updated.json()["retention_days"] == 21

    pack = client.post(
        "/v1/policy-packs",
        headers=headers,
        json={
            "project_id": "v07_control",
            "name": "approval gates",
            "version": "0.7.0",
            "rules": [
                {
                    "id": "shell-approval",
                    "action": "require_approval",
                    "reason_code": "custom_shell_approval",
                    "severity": "high",
                    "when": {"tool_name": "shell.execute", "min_risk_score": 0.5},
                }
            ],
        },
    )
    assert pack.status_code == 200

    run = client.post(
        "/v1/runs", headers=headers, json={"project_id": "v07_control", "name": "approval seed"}
    )
    assert run.status_code == 200
    decision = client.post(
        "/v1/policies/evaluate",
        headers=headers,
        json={
            "project_id": "v07_control",
            "run_id": run.json()["id"],
            "actor": {"agent_id": "coding-agent"},
            "tool": {"name": "shell.execute"},
            "risk_score": 0.6,
        },
    )
    assert decision.status_code == 200
    assert decision.json()["action"] == "require_approval"
    assert decision.json()["reason_code"] == "custom_shell_approval"
    assert decision.json()["builtin_policy_version"] == BUILTIN_POLICY_VERSION
    assert decision.json()["policy_pack_revisions"][-1]["id"] == pack.json()["id"]
    db = SessionLocal()
    try:
        stored_decision = db.get(PolicyDecision, decision.json()["id"])
        assert stored_decision is not None
        assert stored_decision.builtin_policy_version == BUILTIN_POLICY_VERSION
        assert stored_decision.policy_pack_revisions[-1]["version"] == "0.7.0"
    finally:
        db.close()

    approvals = client.get("/v1/approvals?project_id=v07_control&status=pending", headers=headers)
    assert approvals.status_code == 200
    assert approvals.json()
    reviewed = client.post(
        f"/v1/approvals/{approvals.json()[0]['id']}/review",
        headers=headers,
        json={"status": "approved"},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "approved"
    assert reviewed.json()["resolved_by"] == "operator"
    duplicate = client.post(
        f"/v1/approvals/{approvals.json()[0]['id']}/review",
        headers=headers,
        json={"status": "denied"},
    )
    assert duplicate.status_code == 409

    suppression = client.post(
        f"/v1/runs/{run.json()['id']}/suppressions",
        headers=headers,
        json={"project_id": "v07_control", "reason": "known benign demo", "created_by": "test"},
    )
    assert suppression.status_code == 200
    assert suppression.json()["status"] == "active"
    resolved = client.patch(
        f"/v1/suppressions/{suppression.json()['id']}",
        headers=headers,
        json={"status": "resolved"},
    )
    assert resolved.status_code == 200

    status = client.get("/v1/control-plane/status?project_id=v07_control", headers=headers)
    assert status.status_code == 200
    body = status.json()
    assert body["project"]["id"] == "v07_control"
    assert body["active_policy_packs"] >= 1


def test_project_scan_rule_extends_scanner():
    rule = client.post(
        "/v1/scanner/rules",
        headers=headers,
        json={
            "project_id": "v07_scan",
            "label": "wire_transfer_instruction",
            "pattern": "wire money to account",
            "severity": "high",
            "score": 0.82,
        },
    )
    assert rule.status_code == 200

    scan = client.post(
        "/v1/scanner/scan",
        headers=headers,
        json={
            "project_id": "v07_scan",
            "content": "Please wire money to account 123",
            "source": "test",
        },
    )
    assert scan.status_code == 200
    assert "wire_transfer_instruction" in scan.json()["risk_labels"]
    assert scan.json()["risk_score"] == 0.82

    invalid = client.post(
        "/v1/scanner/rules",
        headers=headers,
        json={"project_id": "v07_scan", "label": "bad", "pattern": "(", "severity": "high"},
    )
    assert invalid.status_code == 422

    unsupported = client.post(
        "/v1/scanner/rules",
        headers=headers,
        json={
            "project_id": "v07_scan",
            "label": "unsafe-engine-feature",
            "pattern": r"(?<=prefix)secret",
            "severity": "high",
        },
    )
    assert unsupported.status_code == 422

    unsupported_update = client.patch(
        f"/v1/scanner/rules/{rule.json()['id']}",
        headers=headers,
        json={"pattern": r"(a)\1"},
    )
    assert unsupported_update.status_code == 422


def test_control_plane_redacts_detectable_secrets_before_storage():
    canary = "sk-abcdefghijklmnopqrstuvwxyz123456"
    project_id = f"redaction_{uuid4().hex}"
    created = client.post(
        "/v1/projects",
        headers=headers,
        json={"id": project_id, "metadata": {"token": canary}},
    )
    assert created.status_code == 200
    assert canary not in created.text

    updated = client.patch(
        f"/v1/projects/{project_id}",
        headers=headers,
        json={"metadata": {"nested": {"token": canary}}},
    )
    assert updated.status_code == 200
    assert canary not in updated.text

    run = client.post(
        "/v1/runs",
        headers=headers,
        json={"project_id": project_id, "name": "redaction check"},
    )
    assert run.status_code == 200

    approval = client.post(
        "/v1/approvals",
        headers=headers,
        json={
            "project_id": project_id,
            "run_id": run.json()["id"],
            "requester": {"token": canary},
            "risk_labels": [canary],
            "context": {"arguments": {"token": canary}},
        },
    )
    assert approval.status_code == 200
    assert canary not in approval.text

    suppression = client.post(
        f"/v1/runs/{run.json()['id']}/suppressions",
        headers=headers,
        json={"project_id": project_id, "reason": canary, "created_by": canary},
    )
    assert suppression.status_code == 200
    assert canary not in suppression.text
