#!/usr/bin/env python3
"""Exercise PostgreSQL physical streaming replication and controlled failover."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

import psycopg
from psycopg import OperationalError, sql


ROOT = Path(__file__).resolve().parents[1]
POSTGRES_IMAGE_DIGEST = "sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b"
POSTGRES_IMAGE = f"postgres@{POSTGRES_IMAGE_DIGEST}"


def _safe_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "TMPDIR": "/tmp",
        "CI": "1",
    }
    for name in ("LANG", "LC_ALL", "UV_CACHE_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _run(
    command: list[str],
    *,
    step: str,
    environment: dict[str, str] | None = None,
    timeout: float = 120,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment or _safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"PostgreSQL failover verification failed during {step}")
    return completed


def _write_private_text(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value.encode("utf-8"))
    finally:
        os.close(descriptor)


def _local_image_id() -> str:
    result = _run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES_IMAGE],
        step="local image inspection",
        timeout=20,
    )
    image_id = result.stdout.decode("ascii").strip()
    if image_id != POSTGRES_IMAGE_DIGEST:
        raise RuntimeError("PostgreSQL failover verification found an unexpected image identifier")
    return image_id


def _network_subnet(network_name: str) -> str:
    result = _run(
        [
            "docker",
            "network",
            "inspect",
            "--format",
            "{{(index .IPAM.Config 0).Subnet}}",
            network_name,
        ],
        step="isolated network inspection",
    )
    subnet = result.stdout.decode("ascii").strip()
    if not subnet or any(character not in "0123456789./:" for character in subnet):
        raise RuntimeError("PostgreSQL failover verification found an invalid network subnet")
    return subnet


def _wait_for_database(database_url: str, *, recovery: bool | None = None) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(database_url, connect_timeout=1) as connection:
                if recovery is None:
                    return
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_is_in_recovery()")
                    if bool(cursor.fetchone()[0]) is recovery:
                        return
        except OperationalError:
            pass
        time.sleep(0.2)
    raise RuntimeError("PostgreSQL failover verification timed out waiting for database state")


def _wait_for_synchronous_replica(database_url: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with psycopg.connect(database_url, connect_timeout=2) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT state, sync_state FROM pg_stat_replication "
                    "WHERE application_name = 'agentops_standby'"
                )
                row = cursor.fetchone()
                if row == ("streaming", "sync"):
                    return
        time.sleep(0.2)
    raise RuntimeError("PostgreSQL replica did not become synchronous")


def _wait_for_replay(database_url: str, primary_lsn: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with psycopg.connect(database_url, connect_timeout=2) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_last_wal_replay_lsn()::text, "
                    "pg_last_wal_replay_lsn() >= %s::pg_lsn",
                    (primary_lsn,),
                )
                row = cursor.fetchone()
                if row is not None and row[0] is not None and row[1] is True:
                    return
        time.sleep(0.2)
    raise RuntimeError("PostgreSQL standby did not replay the verified transaction")


def _child_environment(database_url: str) -> dict[str, str]:
    environment = _safe_environment()
    environment.update(
        {
            "AGENTOPS_ENV": "test",
            "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP": "false",
            "AGENTOPS_DATABASE_URL": database_url,
            "AGENTOPS_SEMANTIC_SCANNER_MODE": "disabled",
            "AGENTOPS_OPA_URL": "",
            "AGENTOPS_OTEL_ENABLED": "false",
        }
    )
    return environment


def _run_child(
    script: Path,
    mode: str,
    project_id: str,
    database_url: str,
) -> dict[str, object]:
    result = _run(
        [sys.executable, str(script), mode, project_id],
        step=f"application state {mode.removeprefix('--')}",
        environment=_child_environment(database_url),
        timeout=60,
    )
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("PostgreSQL application-state verifier returned invalid output") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("PostgreSQL application-state verifier returned invalid output")
    return payload


def _append_after_failover(project_id: str) -> None:
    from agentops_guard.backend.database import SessionLocal
    from agentops_guard.backend.models import BackgroundJob
    from agentops_guard.backend.services.audit import record_audit

    suffix = project_id.rsplit("_", 1)[-1]
    database = SessionLocal()
    try:
        record_audit(
            database,
            project_id=project_id,
            action="database.failover_verified",
            resource_type="database",
            after={"status": "promoted"},
        )
        database.add(
            BackgroundJob(
                id=f"failover_job_{suffix[:20]}",
                project_id=project_id,
                kind="eval",
                status="pending",
                payload={"dataset_id": "post-failover-verification"},
            )
        )
        database.commit()
        print(json.dumps({"post_failover_write": True}, separators=(",", ":")))
    finally:
        database.close()


def _verify_after_failover(project_id: str) -> None:
    from agentops_guard.backend.database import SessionLocal
    from agentops_guard.backend.models import AuditLog, BackgroundJob, ExecutionRequest
    from agentops_guard.backend.services.audit import verify_audit_chain
    from agentops_guard.backend.services.migrations import migration_status

    database = SessionLocal()
    try:
        audits = database.query(AuditLog).filter(AuditLog.project_id == project_id).count()
        jobs = database.query(BackgroundJob).filter(BackgroundJob.project_id == project_id).count()
        executions = (
            database.query(ExecutionRequest)
            .filter(ExecutionRequest.project_id == project_id)
            .count()
        )
        result = {
            "migration_status": migration_status(database).status,
            "audit_entries": audits,
            "background_jobs": jobs,
            "execution_requests": executions,
            "audit_chain_valid": verify_audit_chain(database, project_id).valid,
        }
        if result != {
            "migration_status": "ok",
            "audit_entries": 3,
            "background_jobs": 2,
            "execution_requests": 1,
            "audit_chain_valid": True,
        }:
            raise RuntimeError("PostgreSQL application state changed during failover")
        print(json.dumps(result, separators=(",", ":")))
    finally:
        database.close()


def _remove_resources(
    *,
    containers: tuple[str, ...],
    volumes: tuple[str, ...],
    network: str,
) -> None:
    subprocess.run(
        ["docker", "rm", "--force", *containers],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    subprocess.run(
        ["docker", "volume", "rm", "--force", *volumes],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    subprocess.run(
        ["docker", "network", "rm", network],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    checks = (
        [["docker", "inspect", container] for container in containers]
        + [["docker", "volume", "inspect", volume] for volume in volumes]
        + [["docker", "network", "inspect", network]]
    )
    if any(
        subprocess.run(
            command,
            cwd=ROOT,
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        ).returncode
        == 0
        for command in checks
    ):
        raise RuntimeError("PostgreSQL failover verification cleanup failed")


def _main_verification() -> None:
    _run(["docker", "info"], step="Docker readiness", timeout=20)
    image_id = _local_image_id()
    suffix = uuid4().hex[:12]
    primary_name = f"agentops-pg-primary-{suffix}"
    standby_name = f"agentops-pg-standby-{suffix}"
    primary_volume = f"agentops-pg-primary-data-{suffix}"
    standby_volume = f"agentops-pg-standby-data-{suffix}"
    network_name = f"agentops-pg-failover-{suffix}"
    primary_port = _free_port()
    standby_port = _free_port()
    database_password = secrets.token_hex(32)
    replication_password = secrets.token_hex(32)
    primary_url = (
        f"postgresql+psycopg://agentops:{database_password}"
        f"@127.0.0.1:{primary_port}/agentops"
    )
    standby_url = (
        f"postgresql+psycopg://agentops:{database_password}"
        f"@127.0.0.1:{standby_port}/agentops"
    )
    primary_psycopg_url = primary_url.replace("postgresql+psycopg://", "postgresql://", 1)
    standby_psycopg_url = standby_url.replace("postgresql+psycopg://", "postgresql://", 1)
    project_id = f"streaming_failover_{suffix}"
    containers = (primary_name, standby_name)
    volumes = (primary_volume, standby_volume)
    cleanup_error: Exception | None = None
    succeeded = False

    with tempfile.TemporaryDirectory(prefix="agentops-postgres-failover-") as temp_dir:
        temp_path = Path(temp_dir)
        primary_environment_file = temp_path / "primary.env"
        replication_environment_file = temp_path / "replication.env"
        hba_file = temp_path / "pg_hba.conf"
        _write_private_text(
            primary_environment_file,
            "POSTGRES_DB=agentops\n"
            "POSTGRES_USER=agentops\n"
            f"POSTGRES_PASSWORD={database_password}\n"
            "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256\n",
        )
        _write_private_text(
            replication_environment_file,
            f"PGPASSWORD={replication_password}\n"
            f"POSTGRES_REPLICATION_PASSWORD={replication_password}\n",
        )
        try:
            _run(
                ["docker", "network", "create", network_name],
                step="isolated network creation",
            )
            subnet = _network_subnet(network_name)
            hba_file.write_text(
                "local all all trust\n"
                f"host replication replicator {subnet} scram-sha-256\n"
                f"host all all {subnet} scram-sha-256\n",
                encoding="utf-8",
            )
            hba_file.chmod(0o644)
            for volume in volumes:
                _run(["docker", "volume", "create", volume], step="data volume creation")

            common_server_options = [
                "-c",
                "hba_file=/etc/postgresql/agentops-pg-hba.conf",
                "-c",
                "wal_level=replica",
                "-c",
                "max_wal_senders=5",
                "-c",
                "max_replication_slots=5",
                "-c",
                "wal_keep_size=64MB",
                "-c",
                "hot_standby=on",
                "-c",
                "password_encryption=scram-sha-256",
            ]
            _run(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--pull",
                    "never",
                    "--name",
                    primary_name,
                    "--network",
                    network_name,
                    "--network-alias",
                    "primary",
                    "--publish",
                    f"127.0.0.1:{primary_port}:5432",
                    "--env-file",
                    str(primary_environment_file),
                    "--mount",
                    f"type=volume,src={primary_volume},dst=/var/lib/postgresql/data",
                    "--mount",
                    f"type=bind,src={hba_file},dst=/etc/postgresql/agentops-pg-hba.conf,readonly",
                    image_id,
                    *common_server_options,
                ],
                step="primary startup",
            )
            _wait_for_database(primary_psycopg_url, recovery=False)

            _run(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                step="database migration",
                environment=_child_environment(primary_url),
                timeout=90,
            )
            with psycopg.connect(primary_psycopg_url, autocommit=True) as primary:
                with primary.cursor() as cursor:
                    cursor.execute(
                        sql.SQL("CREATE ROLE {} WITH REPLICATION LOGIN PASSWORD {}").format(
                            sql.Identifier("replicator"),
                            sql.Literal(replication_password),
                        )
                    )
                    cursor.execute("SHOW server_version")
                    postgres_version = str(cursor.fetchone()[0])

            _run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull",
                    "never",
                    "--network",
                    network_name,
                    "--env-file",
                    str(replication_environment_file),
                    "--mount",
                    f"type=volume,src={standby_volume},dst=/var/lib/postgresql/data",
                    image_id,
                    "pg_basebackup",
                    "--host=primary",
                    "--port=5432",
                    "--username=replicator",
                    "--pgdata=/var/lib/postgresql/data",
                    "--wal-method=stream",
                    "--create-slot",
                    "--slot=agentops_standby",
                    "--checkpoint=fast",
                    "--manifest-checksums=SHA256",
                ],
                step="pg_basebackup",
                timeout=180,
            )
            _run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull",
                    "never",
                    "--env-file",
                    str(replication_environment_file),
                    "--mount",
                    f"type=volume,src={standby_volume},dst=/var/lib/postgresql/data",
                    image_id,
                    "sh",
                    "-ceu",
                    "umask 077; "
                    "printf 'primary:5432:*:replicator:%s\\n' "
                    '"$POSTGRES_REPLICATION_PASSWORD" '
                    "> /var/lib/postgresql/data/agentops-replication.pgpass; "
                    "touch /var/lib/postgresql/data/standby.signal; "
                    "printf \"\\nprimary_conninfo = 'host=primary port=5432 user=replicator "
                    "application_name=agentops_standby "
                    "passfile=/var/lib/postgresql/data/agentops-replication.pgpass'\\n"
                    "primary_slot_name = 'agentops_standby'\\n\" "
                    ">> /var/lib/postgresql/data/postgresql.auto.conf; "
                    "chown postgres:postgres "
                    "/var/lib/postgresql/data/agentops-replication.pgpass "
                    "/var/lib/postgresql/data/standby.signal "
                    "/var/lib/postgresql/data/postgresql.auto.conf; "
                    "chmod 600 /var/lib/postgresql/data/agentops-replication.pgpass "
                    "/var/lib/postgresql/data/postgresql.auto.conf",
                ],
                step="standby recovery configuration",
            )
            _run(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--pull",
                    "never",
                    "--name",
                    standby_name,
                    "--network",
                    network_name,
                    "--network-alias",
                    "standby",
                    "--publish",
                    f"127.0.0.1:{standby_port}:5432",
                    "--mount",
                    f"type=volume,src={standby_volume},dst=/var/lib/postgresql/data",
                    "--mount",
                    f"type=bind,src={hba_file},dst=/etc/postgresql/agentops-pg-hba.conf,readonly",
                    image_id,
                    *common_server_options,
                ],
                step="standby startup",
            )
            _wait_for_database(standby_psycopg_url, recovery=True)

            with psycopg.connect(primary_psycopg_url, autocommit=True) as primary:
                with primary.cursor() as cursor:
                    cursor.execute(
                        "ALTER SYSTEM SET synchronous_standby_names "
                        "TO 'FIRST 1 (agentops_standby)'"
                    )
                    cursor.execute("ALTER SYSTEM SET synchronous_commit TO 'remote_apply'")
                    cursor.execute("SELECT pg_reload_conf()")
            _wait_for_synchronous_replica(primary_psycopg_url)

            state_script = ROOT / "scripts" / "verify_postgres_backup_restore.py"
            primary_seed = _run_child(state_script, "--seed", project_id, primary_url)
            primary_state = _run_child(state_script, "--verify", project_id, primary_url)
            standby_state = _run_child(state_script, "--verify", project_id, standby_url)
            if primary_seed != {"seeded": True} or primary_state != standby_state:
                raise RuntimeError("PostgreSQL standby did not match primary application state")

            with psycopg.connect(primary_psycopg_url) as primary:
                with primary.cursor() as cursor:
                    cursor.execute("SELECT pg_current_wal_lsn()::text")
                    primary_lsn = str(cursor.fetchone()[0])
            _wait_for_replay(standby_psycopg_url, primary_lsn)

            failover_started = time.monotonic()
            _run(
                ["docker", "stop", "--time", "3", primary_name],
                step="primary termination",
                timeout=15,
            )
            with psycopg.connect(standby_psycopg_url, autocommit=True) as standby:
                with standby.cursor() as cursor:
                    cursor.execute("SELECT pg_promote(true, 30)")
                    if cursor.fetchone()[0] is not True:
                        raise RuntimeError("PostgreSQL standby promotion was rejected")
            _wait_for_database(standby_psycopg_url, recovery=False)
            failover_ms = round((time.monotonic() - failover_started) * 1000)

            with psycopg.connect(standby_psycopg_url, autocommit=True) as promoted:
                with promoted.cursor() as cursor:
                    cursor.execute("ALTER SYSTEM SET synchronous_standby_names TO ''")
                    cursor.execute("SELECT pg_reload_conf()")
                    cursor.execute("SHOW synchronous_standby_names")
                    if cursor.fetchone()[0] != "":
                        raise RuntimeError(
                            "PostgreSQL synchronous policy did not update after promotion"
                        )

            old_primary_unreachable = False
            try:
                with psycopg.connect(primary_psycopg_url, connect_timeout=1):
                    pass
            except OperationalError:
                old_primary_unreachable = True
            if not old_primary_unreachable:
                raise RuntimeError("PostgreSQL old primary remained reachable after termination")

            promoted_state = _run_child(state_script, "--verify", project_id, standby_url)
            if promoted_state != standby_state:
                raise RuntimeError("PostgreSQL application state changed during promotion")
            post_write = _run_child(Path(__file__), "--append", project_id, standby_url)
            final_state = _run_child(Path(__file__), "--verify", project_id, standby_url)
            if post_write != {"post_failover_write": True}:
                raise RuntimeError("PostgreSQL post-failover application write failed")

            succeeded = True
            print(
                json.dumps(
                    {
                        "postgres_version": postgres_version,
                        "postgres_image_id": image_id,
                        "replication_mode": "physical_streaming",
                        "standby_bootstrap": "pg_basebackup",
                        "synchronous_commit": "remote_apply",
                        "standby_sync_state": "sync",
                        "standby_read_only_before_promotion": True,
                        "seeded_state_matched_before_failover": primary_state == standby_state,
                        "primary_lsn_replayed_before_failover": True,
                        "verified_committed_state_loss_count": 0,
                        "old_primary_stopped_before_promotion": True,
                        "old_primary_unreachable": old_primary_unreachable,
                        "standby_promoted": True,
                        "synchronous_policy_reconfigured_after_promotion": True,
                        "application_state_survived_failover": promoted_state == standby_state,
                        "post_failover_write_succeeded": post_write["post_failover_write"],
                        "audit_chain_valid_after_failover": final_state["audit_chain_valid"],
                        "background_jobs_after_failover": final_state["background_jobs"],
                        "execution_requests_after_failover": final_state["execution_requests"],
                        "failover_ms": failover_ms,
                        "automatic_failure_detection_verified": False,
                        "automatic_fencing_verified": False,
                        "transparent_endpoint_failover_verified": False,
                        "database_tls_verified": False,
                        "cross_zone_verified": False,
                        "privacy": {
                            "captures_database_credentials": False,
                            "captures_database_urls": False,
                            "captures_application_content": False,
                        },
                    },
                    separators=(",", ":"),
                )
            )
        finally:
            try:
                _remove_resources(
                    containers=containers,
                    volumes=volumes,
                    network=network_name,
                )
            except Exception as exc:
                cleanup_error = exc

    if cleanup_error is not None:
        raise cleanup_error
    if not succeeded:
        raise RuntimeError("PostgreSQL streaming failover verification did not complete")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--append")
    parser.add_argument("--verify")
    arguments = parser.parse_args()
    if arguments.append:
        _append_after_failover(arguments.append)
        return
    if arguments.verify:
        _verify_after_failover(arguments.verify)
        return
    _main_verification()


if __name__ == "__main__":
    main()
