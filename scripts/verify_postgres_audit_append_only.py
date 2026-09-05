from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import json
import multiprocessing
import os
import socket
import subprocess
import sys
import time
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _safe_environment() -> dict[str, str]:
    environment = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}
    for name in ("LANG", "LC_ALL", "UV_CACHE_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(command: list[str], *, environment: dict[str, str] | None = None) -> None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment or _safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=90,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {command[0]} {command[1]}")


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


def _expect_immutable(engine, statement: str, parameters: dict[str, object] | None = None) -> bool:
    try:
        with engine.begin() as connection:
            connection.execute(text(statement), parameters or {})
    except DBAPIError as exc:
        return getattr(exc.orig, "sqlstate", None) == "55000"
    return False


def main() -> None:
    if subprocess.run(
        ["docker", "info"],
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode:
        raise RuntimeError("Docker is not available")

    suffix = uuid4().hex[:12]
    container_name = f"agentops-pg-audit-append-only-{suffix}"
    project_id = f"audit_append_only_{suffix}"
    port = _free_port()
    sqlalchemy_url = f"postgresql+psycopg://postgres@127.0.0.1:{port}/agentops"
    psycopg_url = sqlalchemy_url.replace("postgresql+psycopg://", "postgresql://", 1)
    environment = {
        **_safe_environment(),
        "AGENTOPS_DATABASE_URL": sqlalchemy_url,
        "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP": "false",
    }
    try:
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--pull",
                "never",
                "--name",
                container_name,
                "--tmpfs",
                "/var/lib/postgresql/data:rw,noexec,nosuid,size=512m",
                "-e",
                "POSTGRES_DB=agentops",
                "-e",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                "-p",
                f"127.0.0.1:{port}:5432",
                "postgres:16",
            ]
        )
        _wait_for_postgres(psycopg_url)
        _run([sys.executable, "-m", "alembic", "upgrade", "head"], environment=environment)

        engine = create_engine(sqlalchemy_url)
        from agentops_guard.backend.models import ExecutionRequest
        from agentops_guard.backend.services.audit import record_audit
        from agentops_guard.backend.services.execution_requests import (
            ExecutionClaimConflict,
            OutcomeResolutionConflict,
            mark_execution_result,
            match_and_claim_execution,
            reconcile_execution_leases,
            resolve_unknown_outcome,
        )
        from agentops_guard.backend.services.mcp_tool_revisions import content_digest

        with Session(engine) as session:
            audit = record_audit(
                session,
                project_id=project_id,
                action="verification.append",
                resource_type="release_evidence",
                after={"status": "recorded"},
            )
            session.commit()
            audit_id = audit.id

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO audit_checkpoints "
                    "(id, project_id, entry_id, entry_hash, checked_entries, payload_digest, "
                    "signer, key_name, key_version, signature, public_key_pem, issued_at, created_at) "
                    "VALUES (:id, :project_id, :entry_id, :entry_hash, 1, :payload_digest, "
                    "'verification', 'verification', 1, 'verification', 'verification', now(), now())"
                ),
                {
                    "id": f"checkpoint_{suffix}",
                    "project_id": project_id,
                    "entry_id": audit_id,
                    "entry_hash": "a" * 64,
                    "payload_digest": "b" * 64,
                },
            )

        subject = {"agent_id": "reconciliation-test-agent"}
        policy_snapshot = {"builtin_policy_version": "reconciliation-test"}

        def execution_row(row_id: str) -> ExecutionRequest:
            return ExecutionRequest(
                id=row_id,
                project_id=project_id,
                decision_id=f"decision_{row_id}",
                approval_id=f"approval_{row_id}",
                subject=subject,
                actor_digest=content_digest(subject),
                server_id=f"server_{suffix}",
                tool_name="records.update",
                tool_revision_id=f"toolrev_{suffix}",
                tool_revision_digest=content_digest({"revision": suffix}),
                arguments_digest=content_digest({"record_id": suffix}),
                policy_snapshot=policy_snapshot,
                policy_snapshot_digest=content_digest(policy_snapshot),
                risk_labels=[],
                status="outcome_unknown",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )

        concurrent_execution_id = f"exec_reconcile_race_{suffix}"
        retry_execution_id = f"exec_reconcile_retry_{suffix}"
        with Session(engine) as session:
            session.add(execution_row(concurrent_execution_id))
            session.add(execution_row(retry_execution_id))
            session.commit()

        def reconcile_once(resolution: str) -> str:
            with Session(engine) as session:
                row = session.get(ExecutionRequest, concurrent_execution_id)
                assert row is not None
                try:
                    resolve_unknown_outcome(
                        session,
                        row,
                        resolution=resolution,
                        evidence_sha256=content_digest({"case": resolution}),
                        reconciled_by=f"operator-{resolution}",
                    )
                    session.commit()
                    return "resolved"
                except OutcomeResolutionConflict:
                    session.rollback()
                    return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            reconciliation_outcomes = list(
                pool.map(reconcile_once, ("confirmed_succeeded", "confirmed_failed"))
            )

        with Session(engine) as session:
            retry_row = session.get(ExecutionRequest, retry_execution_id)
            assert retry_row is not None
            resolve_unknown_outcome(
                session,
                retry_row,
                resolution="confirmed_not_executed",
                evidence_sha256=content_digest({"case": "confirmed_not_executed"}),
                reconciled_by="operator-retry",
            )
            session.commit()
            session.refresh(retry_row)
            retry_reopened = (
                retry_row.status == "approved"
                and retry_row.reconciliation_resolution == "confirmed_not_executed"
                and retry_row.reconciliation_evidence_sha256 is not None
            )

        stale_execution_id = f"exec_stale_result_{suffix}"
        with Session(engine, expire_on_commit=False) as first, Session(engine) as second:
            stale_row = execution_row(stale_execution_id)
            stale_row.status = "execution_claimed"
            stale_row.claimed_by = "crashed-worker"
            first.add(stale_row)
            first.commit()
            changed = (
                second.query(ExecutionRequest)
                .filter(
                    ExecutionRequest.id == stale_execution_id,
                    ExecutionRequest.status == "execution_claimed",
                )
                .update(
                    {ExecutionRequest.status: "outcome_unknown"},
                    synchronize_session=False,
                )
            )
            second.commit()
            if changed != 1:
                raise RuntimeError("failed to create stale execution result race")
            try:
                mark_execution_result(first, stale_row, {"content": []})
            except ExecutionClaimConflict:
                stale_result_rejected = True
                first.rollback()
            else:
                stale_result_rejected = False

        crash_execution_id = f"exec_crash_after_claim_{suffix}"
        crash_arguments = {"record_id": f"crash-{suffix}"}
        with Session(engine) as session:
            crash_row = execution_row(crash_execution_id)
            crash_row.status = "approved"
            crash_row.arguments_digest = content_digest(crash_arguments)
            session.add(crash_row)
            session.commit()

        def claim_and_crash() -> None:
            child_engine = create_engine(sqlalchemy_url)
            with Session(child_engine) as session:
                result = match_and_claim_execution(
                    session,
                    project_id=project_id,
                    run_id=None,
                    subject=subject,
                    server_id=f"server_{suffix}",
                    tool_name="records.update",
                    tool_revision_id=f"toolrev_{suffix}",
                    tool_revision_digest=content_digest({"revision": suffix}),
                    arguments=crash_arguments,
                    policy_snapshot=policy_snapshot,
                    claimant="crashing-gateway",
                    idempotency_key=None,
                    lease_seconds=0.2,
                )
                if result.kind != "claimed":
                    os._exit(2)
                session.commit()
            os._exit(0)

        process = multiprocessing.get_context("fork").Process(target=claim_and_crash)
        process.start()
        process.join(timeout=10)
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
            raise RuntimeError("crash-after-claim child did not exit")
        claim_survived_process_exit = process.exitcode == 0
        with Session(engine) as session:
            stored = session.get(ExecutionRequest, crash_execution_id)
            claim_survived_process_exit = (
                claim_survived_process_exit
                and stored is not None
                and stored.status == "execution_claimed"
            )
        time.sleep(0.3)
        with Session(engine) as session:
            recovered = reconcile_execution_leases(session)
            session.commit()
            stored = session.get(ExecutionRequest, crash_execution_id)
            crash_became_unknown = (
                recovered == 1 and stored is not None and stored.status == "outcome_unknown"
            )
            repeated = match_and_claim_execution(
                session,
                project_id=project_id,
                run_id=None,
                subject=subject,
                server_id=f"server_{suffix}",
                tool_name="records.update",
                tool_revision_id=f"toolrev_{suffix}",
                tool_revision_digest=content_digest({"revision": suffix}),
                arguments=crash_arguments,
                policy_snapshot=policy_snapshot,
                claimant="replacement-gateway",
                idempotency_key=None,
            )
            crash_retry_rejected = repeated.kind == "terminal"

        evidence = {
            "audit_insert_allowed": True,
            "audit_update_rejected": _expect_immutable(
                engine,
                "UPDATE audit_logs SET action = 'forged' WHERE id = :id",
                {"id": audit_id},
            ),
            "audit_delete_rejected": _expect_immutable(
                engine,
                "DELETE FROM audit_logs WHERE id = :id",
                {"id": audit_id},
            ),
            "audit_truncate_rejected": _expect_immutable(engine, "TRUNCATE audit_logs"),
            "checkpoint_update_rejected": _expect_immutable(
                engine,
                "UPDATE audit_checkpoints SET signature = 'forged' WHERE id = :id",
                {"id": f"checkpoint_{suffix}"},
            ),
            "checkpoint_delete_rejected": _expect_immutable(
                engine,
                "DELETE FROM audit_checkpoints WHERE id = :id",
                {"id": f"checkpoint_{suffix}"},
            ),
            "checkpoint_truncate_rejected": _expect_immutable(engine, "TRUNCATE audit_checkpoints"),
            "outcome_reconciliation_single_winner": sorted(reconciliation_outcomes)
            == ["conflict", "resolved"],
            "confirmed_not_executed_reopened": retry_reopened,
            "stale_claim_result_rejected": stale_result_rejected,
            "claim_survived_process_exit": claim_survived_process_exit,
            "crash_became_outcome_unknown": crash_became_unknown,
            "crash_retry_rejected": crash_retry_rejected,
        }
        engine.dispose()
        if not all(evidence.values()):
            raise RuntimeError("PostgreSQL append-only audit verification failed")
        print(json.dumps(evidence, separators=(",", ":")))
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )


if __name__ == "__main__":
    main()
