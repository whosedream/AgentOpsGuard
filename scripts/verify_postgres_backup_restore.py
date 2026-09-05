from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from uuid import uuid4


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {command[0]} {command[1]}")
    return result


def _start_postgres(name: str, password: str, port: int) -> None:
    _run(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            name,
            "--tmpfs",
            "/var/lib/postgresql/data:rw,noexec,nosuid,size=512m",
            "-e",
            "POSTGRES_DB=agentops",
            "-e",
            "POSTGRES_USER=agentops",
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-p",
            f"127.0.0.1:{port}:5432",
            "postgres:16",
        ],
        check=False,
    )


def _wait_for_postgres(database_url: str) -> None:
    import psycopg

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(database_url, connect_timeout=1):
                return
        except psycopg.OperationalError:
            time.sleep(0.2)
    raise RuntimeError("PostgreSQL did not become ready")


def _app_environment(database_url: str) -> dict[str, str]:
    return {
        **os.environ,
        "AGENTOPS_DATABASE_URL": database_url,
        "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP": "false",
    }


def _migrate(database_url: str, revision: str = "head") -> None:
    _run(
        [sys.executable, "-m", "alembic", "upgrade", revision],
        env=_app_environment(database_url),
        check=False,
    )


def _child(mode: str, database_url: str, project_id: str) -> dict[str, object]:
    result = _run(
        [sys.executable, __file__, f"--{mode}", project_id],
        env=_app_environment(database_url),
        text=True,
        check=False,
    )
    return json.loads(result.stdout)


def _seed(project_id: str) -> None:
    from agentops_guard.backend.database import SessionLocal
    from agentops_guard.backend.models import BackgroundJob, ExecutionRequest
    from agentops_guard.backend.services.audit import record_audit
    from agentops_guard.backend.services.mcp_tool_revisions import content_digest
    from agentops_guard.backend.services.projects import ensure_project

    db = SessionLocal()
    try:
        ensure_project(db, project_id)
        record_audit(
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
        suffix = project_id.rsplit("_", 1)[-1]
        db.add(
            BackgroundJob(
                id=f"backup_job_{suffix[:20]}",
                project_id=project_id,
                kind="eval",
                status="pending",
                payload={"dataset_id": "backup-restore-verification"},
            )
        )
        subject = {"agent_id": "backup-agent"}
        policy_snapshot = {"builtin_policy_version": "backup-restore-v1"}
        db.add(
            ExecutionRequest(
                id=f"backup_exec_{suffix[:20]}",
                project_id=project_id,
                decision_id=f"backup_decision_{suffix[:20]}",
                approval_id=f"backup_approval_{suffix[:20]}",
                subject=subject,
                actor_digest=content_digest(subject),
                server_id="backup-server",
                tool_name="records.update",
                tool_revision_id=f"backup_revision_{suffix[:20]}",
                tool_revision_digest=content_digest({"revision": suffix}),
                arguments_digest=content_digest({"record_id": "backup-record"}),
                policy_snapshot=policy_snapshot,
                policy_snapshot_digest=content_digest(policy_snapshot),
                status="approved",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        db.commit()
        print(json.dumps({"seeded": True}, separators=(",", ":")))
    finally:
        db.close()


def _verify(project_id: str) -> None:
    from agentops_guard.backend.database import SessionLocal
    from agentops_guard.backend.models import AuditLog, BackgroundJob, ExecutionRequest
    from agentops_guard.backend.services.audit import verify_audit_chain
    from agentops_guard.backend.services.migrations import migration_status

    db = SessionLocal()
    try:
        status = migration_status(db)
        audits = db.query(AuditLog).filter(AuditLog.project_id == project_id).count()
        jobs = db.query(BackgroundJob).filter(BackgroundJob.project_id == project_id).count()
        executions = (
            db.query(ExecutionRequest).filter(ExecutionRequest.project_id == project_id).count()
        )
        chain_valid = verify_audit_chain(db, project_id).valid
        result = {
            "migration_status": status.status,
            "audit_entries": audits,
            "background_jobs": jobs,
            "execution_requests": executions,
            "audit_chain_valid": chain_valid,
        }
        if result != {
            "migration_status": "ok",
            "audit_entries": 2,
            "background_jobs": 1,
            "execution_requests": 1,
            "audit_chain_valid": True,
        }:
            raise RuntimeError("restored data verification failed")
        print(json.dumps(result, separators=(",", ":")))
    finally:
        db.close()


def _seed_legacy(project_id: str) -> None:
    from sqlalchemy import text

    from agentops_guard.backend.database import engine

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO audit_logs "
                "(id, project_id, actor_type, actor_id, action, resource_type, resource_id, "
                '"before", "after", metadata_json, created_at) VALUES '
                "(:id, :project_id, :actor_type, NULL, :action, :resource_type, NULL, "
                "NULL, CAST(:after AS JSON), CAST(:metadata AS JSON), :created_at)"
            ),
            [
                {
                    "id": f"legacy_audit_1_{project_id[-12:]}",
                    "project_id": project_id,
                    "actor_type": "api_key",
                    "action": "approval.approved",
                    "resource_type": "approval",
                    "after": '{"status":"approved"}',
                    "metadata": "{}",
                    "created_at": datetime(2026, 1, 1, tzinfo=UTC),
                },
                {
                    "id": f"legacy_audit_2_{project_id[-12:]}",
                    "project_id": project_id,
                    "actor_type": "api_key",
                    "action": "execution.succeeded",
                    "resource_type": "execution",
                    "after": '{"status":"succeeded"}',
                    "metadata": '{"attempt":1}',
                    "created_at": datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC),
                },
            ],
        )
    print(json.dumps({"legacy_seeded": True}, separators=(",", ":")))


def _verify_legacy(project_id: str) -> None:
    from agentops_guard.backend.database import SessionLocal
    from agentops_guard.backend.models import AuditLog
    from agentops_guard.backend.services.audit import verify_audit_chain

    db = SessionLocal()
    try:
        rows = (
            db.query(AuditLog)
            .filter(AuditLog.project_id == project_id)
            .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            .all()
        )
        result = {
            "legacy_entries": len(rows),
            "all_entries_sealed": all(row.entry_hash is not None for row in rows),
            "audit_chain_valid": verify_audit_chain(db, project_id).valid,
        }
        if result != {
            "legacy_entries": 2,
            "all_entries_sealed": True,
            "audit_chain_valid": True,
        }:
            raise RuntimeError("legacy audit migration verification failed")
        print(json.dumps(result, separators=(",", ":")))
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed")
    parser.add_argument("--verify")
    parser.add_argument("--seed-legacy")
    parser.add_argument("--verify-legacy")
    args = parser.parse_args()
    if args.seed:
        _seed(args.seed)
        return
    if args.verify:
        _verify(args.verify)
        return
    if args.seed_legacy:
        _seed_legacy(args.seed_legacy)
        return
    if args.verify_legacy:
        _verify_legacy(args.verify_legacy)
        return

    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        raise RuntimeError("Docker is not available")
    suffix = uuid4().hex[:12]
    source_name = f"agentops-pg-backup-source-{suffix}"
    target_name = f"agentops-pg-backup-target-{suffix}"
    password = secrets.token_urlsafe(32)
    source_port = _free_port()
    target_port = _free_port()
    source_url = f"postgresql+psycopg://agentops:{password}@127.0.0.1:{source_port}/agentops"
    target_url = f"postgresql+psycopg://agentops:{password}@127.0.0.1:{target_port}/agentops"
    psycopg_source_url = source_url.replace("postgresql+psycopg://", "postgresql://", 1)
    psycopg_target_url = target_url.replace("postgresql+psycopg://", "postgresql://", 1)
    project_id = f"backup_restore_{suffix}"
    legacy_project_id = f"legacy_audit_{suffix}"
    try:
        _start_postgres(source_name, password, source_port)
        _start_postgres(target_name, password, target_port)
        _wait_for_postgres(psycopg_source_url)
        _wait_for_postgres(psycopg_target_url)
        _migrate(source_url, "0011_transactional_outbox")
        _child("seed-legacy", source_url, legacy_project_id)
        _migrate(source_url)
        source_legacy_evidence = _child("verify-legacy", source_url, legacy_project_id)
        _child("seed", source_url, project_id)
        source_evidence = _child("verify", source_url, project_id)

        dump = _run(
            ["docker", "exec", source_name, "pg_dump", "-U", "agentops", "-Fc", "agentops"],
            check=False,
        ).stdout
        if not dump:
            raise RuntimeError("PostgreSQL backup was empty")
        restore = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                target_name,
                "pg_restore",
                "-U",
                "agentops",
                "--no-owner",
                "--no-privileges",
                "-d",
                "agentops",
            ],
            input=dump,
            capture_output=True,
        )
        if restore.returncode != 0:
            raise RuntimeError("PostgreSQL restore failed")
        restored_evidence = _child("verify", target_url, project_id)
        restored_legacy_evidence = _child("verify-legacy", target_url, legacy_project_id)
    finally:
        subprocess.run(
            ["docker", "rm", "-f", source_name, target_name],
            capture_output=True,
            check=False,
        )

    print(
        json.dumps(
            {
                "postgres_image": "postgres:16",
                "backup_format": "pg_dump_custom",
                "source": source_evidence,
                "restored": restored_evidence,
                "legacy_audit_upgrade_source": source_legacy_evidence,
                "legacy_audit_upgrade_restored": restored_legacy_evidence,
                "temporary_containers_removed": True,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
