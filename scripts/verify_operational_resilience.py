#!/usr/bin/env python3
"""Exercise the current PostgreSQL/Redis/RQ/Gateway recovery checks together."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

from psycopg import OperationalError, connect
from redis import Redis
from redis.exceptions import RedisError


ROOT = Path(__file__).resolve().parents[1]
CHECK_SCRIPTS = (
    "scripts/verify_postgres_worker_crash_recovery.py",
    "scripts/verify_rq_redis_worker_recovery.py",
    "scripts/verify_redis_gateway_concurrency.py",
    "scripts/verify_gateway_multi_replica_capacity.py",
    "scripts/verify_redis_outage_recovery.py",
)
SAFE_CHILD_FAILURES = (
    "Redis did not recover",
    "Redis outage did not preserve the pending database job",
    "outbox retry timestamp is invalid",
    "pending outbox event was not delivered after Redis recovery",
    "recovery worker did not finish",
    "recovery worker failed",
    "job did not complete after Redis recovery",
    "AssertionError",
)
SENSITIVE_ENV_SUFFIXES = ("_KEY", "_PASSWORD", "_SECRET", "_TOKEN", "_URL")


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
    environment: dict[str, str] | None = None,
    timeout: float = 180,
) -> None:
    effective_environment = environment or _safe_environment()
    with tempfile.TemporaryFile() as stderr_file:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=effective_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr_file,
            timeout=timeout,
            check=False,
        )
        stderr_file.seek(0)
        stderr = stderr_file.read(65_536).decode("utf-8", errors="replace")
    if completed.returncode != 0:
        script = next(
            (Path(argument).name for argument in command if argument.endswith(".py")),
            Path(command[0]).name,
        )
        reason = next((message for message in SAFE_CHILD_FAILURES if message in stderr), None)
        if reason is None:
            for name, value in effective_environment.items():
                if value and name.endswith(SENSITIVE_ENV_SUFFIXES):
                    stderr = stderr.replace(value, "<redacted>")
            stderr = re.sub(r"(?:postgresql(?:\+psycopg)?|redis|https?)://\S+", "<redacted-url>", stderr)
            lines = [line.strip() for line in stderr.splitlines() if line.strip()]
            reason = lines[-1][:240] if lines else None
        suffix = f" ({reason})" if reason else ""
        raise RuntimeError(f"operational resilience command failed: {script}{suffix}")


def _local_image_id(reference: str) -> str:
    completed = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    image_id = completed.stdout.strip()
    if completed.returncode != 0 or not image_id.startswith("sha256:"):
        raise RuntimeError(f"required local test image is unavailable: {reference}")
    return image_id


def _wait_for_postgres(database_url: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with connect(database_url, connect_timeout=1):
                return
        except OperationalError:
            time.sleep(0.2)
    raise RuntimeError("temporary PostgreSQL did not become ready")


def _wait_for_redis(redis_url: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        connection = Redis.from_url(redis_url)
        try:
            if connection.ping():
                return
        except RedisError:
            pass
        finally:
            connection.close()
        time.sleep(0.1)
    raise RuntimeError("temporary Redis did not become ready")


def _remove_containers(container_names: tuple[str, ...]) -> None:
    subprocess.run(
        ["docker", "rm", "--force", "--volumes", *container_names],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    for container_name in container_names:
        inspect = subprocess.run(
            ["docker", "inspect", container_name],
            cwd=ROOT,
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if inspect.returncode == 0:
            raise RuntimeError("temporary verification container cleanup failed")


def main() -> int:
    _run(["docker", "info"], timeout=20)
    postgres_image = _local_image_id("postgres:16")
    redis_image = _local_image_id("redis:7")
    suffix = uuid4().hex[:12]
    postgres_name = f"agentops-resilience-postgres-{suffix}"
    redis_name = f"agentops-redis-outage-{suffix}"
    postgres_port = _free_port()
    redis_port = _free_port()
    password = secrets.token_urlsafe(32)
    sqlalchemy_url = (
        f"postgresql+psycopg://agentops:{password}@127.0.0.1:{postgres_port}/agentops"
    )
    psycopg_url = sqlalchemy_url.replace("postgresql+psycopg://", "postgresql://", 1)
    redis_url = f"redis://127.0.0.1:{redis_port}/0"
    container_names = (postgres_name, redis_name)
    succeeded = False
    cleanup_error: Exception | None = None
    try:
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--pull",
                "never",
                "--name",
                postgres_name,
                "--tmpfs",
                "/var/lib/postgresql/data:rw,noexec,nosuid,size=512m",
                "--publish",
                f"127.0.0.1:{postgres_port}:5432",
                "--env",
                "POSTGRES_DB=agentops",
                "--env",
                "POSTGRES_USER=agentops",
                "--env",
                f"POSTGRES_PASSWORD={password}",
                postgres_image,
            ]
        )
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--pull",
                "never",
                "--name",
                redis_name,
                "--tmpfs",
                "/data:rw,noexec,nosuid,size=128m",
                "--publish",
                f"127.0.0.1:{redis_port}:6379",
                redis_image,
                "redis-server",
                "--save",
                "",
                "--appendonly",
                "no",
            ]
        )
        _wait_for_postgres(psycopg_url)
        _wait_for_redis(redis_url)

        environment = _safe_environment()
        environment.update(
            {
                "AGENTOPS_ENV": "test",
                "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP": "false",
                "AGENTOPS_DATABASE_URL": sqlalchemy_url,
                "AGENTOPS_REDIS_URL": redis_url,
                "AGENTOPS_TEST_REDIS_CONTAINER": redis_name,
                "AGENTOPS_SEMANTIC_SCANNER_MODE": "disabled",
                "AGENTOPS_OPA_URL": "",
                "AGENTOPS_OTEL_ENABLED": "false",
            }
        )
        _run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            environment=environment,
        )
        for script in CHECK_SCRIPTS:
            _run([sys.executable, script], environment=environment, timeout=240)
        succeeded = True
    finally:
        try:
            _remove_containers(container_names)
        except Exception as exc:  # cleanup failure must fail the release gate
            cleanup_error = exc

    if cleanup_error is not None:
        raise cleanup_error
    if not succeeded:
        raise RuntimeError("operational resilience verification did not complete")
    print(
        json.dumps(
            {
                "real_postgresql": True,
                "real_redis": True,
                "real_rq_worker": True,
                "real_gateway_processes": 2,
                "checks": [Path(script).stem for script in CHECK_SCRIPTS],
                "temporary_containers_removed": True,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
