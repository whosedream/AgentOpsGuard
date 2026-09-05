import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from agentops_guard.backend.models import AuditLog
from agentops_guard.backend.services.audit import verify_audit_chain


def _upgrade(db_path: Path, revision: str) -> None:
    env = {**os.environ, "AGENTOPS_DATABASE_URL": f"sqlite:///{db_path.as_posix()}"}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", revision],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


def test_alembic_upgrade_from_identity_schema_creates_bound_credentials(
    tmp_path: Path,
):
    db_path = tmp_path / "migration.sqlite3"
    _upgrade(db_path, "0004_identity_rbac")
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    assert "service_credentials" not in inspect(engine).get_table_names()

    _upgrade(db_path, "head")
    inspector = inspect(engine)
    mcp_server_columns = {column["name"] for column in inspector.get_columns("mcp_servers")}
    assert "runtime_provider" in mcp_server_columns
    mcp_tool_columns = {column["name"] for column in inspector.get_columns("mcp_tools")}
    assert "current_revision_id" in mcp_tool_columns
    assert "mcp_tool_revisions" in inspector.get_table_names()
    assert "execution_requests" in inspector.get_table_names()
    execution_columns = {column["name"] for column in inspector.get_columns("execution_requests")}
    assert "lease_expires_at" in execution_columns
    assert {
        "reconciliation_resolution",
        "reconciliation_evidence_sha256",
        "reconciled_by",
        "reconciled_at",
    } <= execution_columns
    assert "outbox_events" in inspector.get_table_names()
    background_job_columns = {column["name"] for column in inspector.get_columns("background_jobs")}
    assert {"lease_owner", "lease_expires_at"} <= background_job_columns
    assert "audit_chain_heads" in inspector.get_table_names()
    assert "audit_checkpoints" in inspector.get_table_names()
    audit_columns = {column["name"] for column in inspector.get_columns("audit_logs")}
    assert {"previous_hash", "entry_hash"} <= audit_columns
    approval_columns = {column["name"] for column in inspector.get_columns("approval_requests")}
    assert "execution_request_id" in approval_columns
    api_key_columns = {column["name"] for column in inspector.get_columns("api_keys")}
    assert "agent_id" in api_key_columns
    policy_decision_columns = {
        column["name"] for column in inspector.get_columns("policy_decisions")
    }
    assert {
        "builtin_policy_version",
        "policy_pack_revisions",
        "opa_bundle_revision",
    } <= policy_decision_columns
    columns = {column["name"] for column in inspector.get_columns("service_credentials")}
    assert columns == {
        "credential_ref",
        "project_id",
        "name",
        "encrypted_secret",
        "binding_ciphertext",
        "provider",
        "tool",
        "origin",
        "injection_field",
        "credential_scope",
        "allowed_actor_ids",
        "status",
        "version",
        "last_used_at",
        "revoked_at",
        "created_at",
        "updated_at",
    }
    assert inspector.get_pk_constraint("service_credentials")["constrained_columns"] == [
        "credential_ref"
    ]
    assert {
        (foreign_key["constrained_columns"][0], foreign_key["referred_table"])
        for foreign_key in inspector.get_foreign_keys("service_credentials")
    } == {("project_id", "projects")}
    assert {index["name"] for index in inspector.get_indexes("service_credentials")} == {
        "ix_service_credentials_project_id",
        "ix_service_credentials_status",
    }
    with engine.connect() as connection:
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert version == "0016_execution_reconciliation"


def test_audit_chain_migration_seals_existing_history(tmp_path: Path):
    db_path = tmp_path / "legacy-audit.sqlite3"
    _upgrade(db_path, "0011_transactional_outbox")
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO audit_logs "
                "(id, project_id, actor_type, actor_id, action, resource_type, resource_id, "
                '"before", "after", metadata_json, created_at) VALUES '
                "(:id, :project_id, :actor_type, NULL, :action, :resource_type, NULL, "
                ":before, :after, :metadata, :created_at)"
            ),
            [
                {
                    "id": "audit_legacy_1",
                    "project_id": "legacy_project",
                    "actor_type": "api_key",
                    "action": "approval.approved",
                    "resource_type": "approval",
                    "before": None,
                    "after": '{"status":"approved","label":"é"}',
                    "metadata": "{}",
                    "created_at": "2026-01-01 00:00:00.000001",
                },
                {
                    "id": "audit_legacy_2",
                    "project_id": "legacy_project",
                    "actor_type": "api_key",
                    "action": "execution.succeeded",
                    "resource_type": "execution",
                    "before": None,
                    "after": '{"status":"succeeded"}',
                    "metadata": '{"attempt":1}',
                    "created_at": "2026-01-01 00:00:00.000002",
                },
            ],
        )

    _upgrade(db_path, "head")

    with Session(engine) as session:
        rows = (
            session.query(AuditLog)
            .filter(AuditLog.project_id == "legacy_project")
            .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            .all()
        )
        assert len(rows) == 2
        assert rows[0].previous_hash is None
        assert rows[0].entry_hash is not None
        assert rows[1].previous_hash == rows[0].entry_hash
        assert verify_audit_chain(session, "legacy_project").valid is True
