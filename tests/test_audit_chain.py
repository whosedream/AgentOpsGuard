import json
from uuid import uuid4

from fastapi.testclient import TestClient

from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.main import app
from agentops_guard.backend.models import AuditLog
from agentops_guard.backend.services.audit import record_audit, verify_audit_chain
from agentops_guard.backend.services.projects import ensure_project


def test_audit_hash_chain_detects_historical_mutation():
    project_id = f"audit_chain_{uuid4().hex}"
    db = SessionLocal()
    try:
        ensure_project(db, project_id)
        first = record_audit(
            db,
            project_id=project_id,
            action="approval.approved",
            resource_type="approval",
            after={"status": "approved"},
        )
        record_audit(
            db,
            project_id=project_id,
            action="execution.succeeded",
            resource_type="execution",
            after={"status": "succeeded"},
        )
        db.commit()
        first_id = first.id
    finally:
        db.close()

    db = SessionLocal()
    try:
        assert verify_audit_chain(db, project_id).valid is True
        first = db.get(AuditLog, first_id)
        assert first is not None
        first.after = {"status": "denied"}
        db.commit()
        result = verify_audit_chain(db, project_id)
        assert result.valid is False
        assert result.broken_entry_id == first_id
    finally:
        db.close()

    response = TestClient(app).get(
        "/v1/audit-logs/integrity",
        params={"project_id": project_id},
        headers={"X-AgentOps-Api-Key": "dev-agentops-key"},
    )
    assert response.status_code == 200
    assert response.json()["valid"] is False


def test_audit_record_redacts_detectable_secrets_before_storage():
    canary = "sk-abcdefghijklmnopqrstuvwxyz123456"
    project_id = f"audit_redaction_{uuid4().hex}"
    db = SessionLocal()
    try:
        row = record_audit(
            db,
            project_id=project_id,
            action="test.redaction",
            resource_type="test",
            resource_id=canary,
            actor_id=canary,
            after={canary: {"token": canary}},
            metadata={"error": canary},
        )
        db.flush()

        serialized = json.dumps(
            {
                "resource_id": row.resource_id,
                "actor_id": row.actor_id,
                "after": row.after,
                "metadata": row.metadata_json,
            }
        )
        assert canary not in serialized
        db.rollback()
    finally:
        db.close()


def test_audit_preserves_valid_internal_links_that_resemble_phone_numbers():
    decision_id = "policy_abcd13800138000abcdefabc"
    project_id = f"audit_internal_link_{uuid4().hex}"
    db = SessionLocal()
    try:
        row = record_audit(
            db,
            project_id=project_id,
            action="mcp_tool.upstream_error",
            resource_type="mcp_tool",
            metadata={
                "policy_decision_id": decision_id,
                "untrusted_text": decision_id,
            },
        )
        db.flush()

        assert row.metadata_json["policy_decision_id"] == decision_id
        assert row.metadata_json["untrusted_text"] != decision_id
        assert "[REDACTED:phone]" in row.metadata_json["untrusted_text"]
        db.rollback()
    finally:
        db.close()
