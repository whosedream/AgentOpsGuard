#!/usr/bin/env python3
"""Verify real S3 Object Lock behavior without exposing temporary credentials."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
import httpx

from agentops_guard.backend.models import AuditCheckpoint
from agentops_guard.backend.services.audit_anchors import (
    S3ObjectLockSink,
    public_checkpoint_bytes,
)
from agentops_guard.backend.services.audit_checkpoints import audit_checkpoint_payload
from agentops_guard.backend.services.mcp_tool_revisions import canonical_json
from install_minio_object_lock_runtime import (
    DEFAULT_DESTINATION as MINIO_BINARY,
    INSTALLED_CHECKSUM_NAME,
    INSTALLED_SIGNATURE_NAME,
    MINIO_BINARY_SHA256,
    MINIO_SIGNATURE_SHA256,
    MINIO_VERSION,
    _sha256_file,
    _validate_checksum,
    _verify_minisign,
    _verify_version,
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_ready(base_url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 20
    with httpx.Client(timeout=1, trust_env=False) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("MinIO stopped before becoming ready")
            try:
                if client.get(f"{base_url}/minio/health/ready").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    raise RuntimeError("MinIO did not become ready")


def _checkpoint(now: datetime) -> AuditCheckpoint:
    payload = audit_checkpoint_payload(
        project_id="object-lock-verification",
        entry_id="audit-entry-1",
        entry_hash="a" * 64,
        checked_entries=3,
        issued_at=now,
    )
    return AuditCheckpoint(
        id="checkpoint-1",
        project_id="object-lock-verification",
        entry_id="audit-entry-1",
        entry_hash="a" * 64,
        checked_entries=3,
        payload_digest=sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
        signer="openbao-transit-ed25519",
        key_name="agentops-audit",
        key_version=1,
        signature="vault:v1:public-verification-fixture",
        public_key="public verification fixture",
        issued_at=now,
        created_at=now,
    )


def _expect_client_rejection(operation, *, label: str) -> str:
    try:
        operation()
    except ClientError as error:
        code = str(error.response.get("Error", {}).get("Code") or "")
        if not code:
            raise RuntimeError(f"{label} failed without a stable S3 error code") from error
        return code
    raise RuntimeError(f"{label} unexpectedly succeeded")


def verify() -> dict[str, object]:
    signature_file = MINIO_BINARY.parent / INSTALLED_SIGNATURE_NAME
    checksum_file = MINIO_BINARY.parent / INSTALLED_CHECKSUM_NAME
    if (
        not MINIO_BINARY.is_file()
        or MINIO_BINARY.is_symlink()
        or _sha256_file(MINIO_BINARY) != MINIO_BINARY_SHA256
        or not signature_file.is_file()
        or signature_file.is_symlink()
        or _sha256_file(signature_file) != MINIO_SIGNATURE_SHA256
        or not checksum_file.is_file()
        or checksum_file.is_symlink()
    ):
        raise RuntimeError("pinned MinIO runtime or verification material is invalid")
    _validate_checksum(checksum_file)
    _verify_minisign(MINIO_BINARY, signature_file)
    _verify_version(MINIO_BINARY)

    api_port = _free_port()
    console_port = _free_port()
    if api_port == console_port:
        raise RuntimeError("verification ports were not unique")
    root_user = f"agentops{secrets.token_hex(12)}"
    root_password = secrets.token_urlsafe(48)
    bucket = "agentops-audit-lock"
    now = datetime.now(UTC).replace(microsecond=0)
    row = _checkpoint(now)

    with tempfile.TemporaryDirectory(prefix="agentops-minio-object-lock-") as temp_dir:
        temp_path = Path(temp_dir)
        data_dir = temp_path / "data"
        config_dir = temp_path / "config"
        data_dir.mkdir(mode=0o700)
        config_dir.mkdir(mode=0o700)
        base_url = f"http://127.0.0.1:{api_port}"
        process = subprocess.Popen(
            (
                str(MINIO_BINARY),
                "server",
                "--quiet",
                "--address",
                f"127.0.0.1:{api_port}",
                "--console-address",
                f"127.0.0.1:{console_port}",
                "--config-dir",
                str(config_dir),
                str(data_dir),
            ),
            env={
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "MINIO_ROOT_USER": root_user,
                "MINIO_ROOT_PASSWORD": root_password,
                "MINIO_BROWSER": "off",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_until_ready(base_url, process)
            client = boto3.client(
                "s3",
                endpoint_url=base_url,
                region_name="us-east-1",
                aws_access_key_id=root_user,
                aws_secret_access_key=root_password,
                config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
            )
            client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
            sink = S3ObjectLockSink(
                client=client,
                bucket=bucket,
                prefix="anchors",
                retention_days=1,
            )
            sink.check_ready()
            receipt = sink.store(row, now=now)
            repeated = sink.store(row, now=now)
            sink.assert_database_history_is_not_behind([row])

            body = client.get_object(
                Bucket=bucket,
                Key=receipt.object_key,
                VersionId=receipt.version_id,
                ChecksumMode="ENABLED",
            )["Body"].read()
            if body != public_checkpoint_bytes(row):
                raise RuntimeError("exact locked object version changed after write")
            deletion_code = _expect_client_rejection(
                lambda: client.delete_object(
                    Bucket=bucket,
                    Key=receipt.object_key,
                    VersionId=receipt.version_id,
                ),
                label="COMPLIANCE exact-version deletion",
            )
            shortened = now + timedelta(hours=1)
            retention_code = _expect_client_rejection(
                lambda: client.put_object_retention(
                    Bucket=bucket,
                    Key=receipt.object_key,
                    VersionId=receipt.version_id,
                    Retention={"Mode": "COMPLIANCE", "RetainUntilDate": shortened},
                ),
                label="COMPLIANCE retention shortening",
            )
            retained = client.get_object_retention(
                Bucket=bucket,
                Key=receipt.object_key,
                VersionId=receipt.version_id,
            )["Retention"]
            if (
                retained.get("Mode") != "COMPLIANCE"
                or retained["RetainUntilDate"].astimezone(UTC) < receipt.retain_until
            ):
                raise RuntimeError("COMPLIANCE retention changed after rejected shortening")
            versions = client.list_object_versions(Bucket=bucket, Prefix="anchors/")
            if versions.get("DeleteMarkers") or len(versions.get("Versions", [])) != 1:
                raise RuntimeError("Object Lock verification produced unexpected history")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    if not repeated.already_existed or repeated.version_id != receipt.version_id:
        raise RuntimeError("idempotent write did not reuse the original locked version")
    result: dict[str, object] = {
        "minio_version": MINIO_VERSION,
        "checks": {
            "binary_digest_and_minisign_verified": True,
            "runtime_version_verified": True,
            "server_runs_as_non_root": os.geteuid() != 0,
            "listeners_are_loopback_only": True,
            "bucket_versioning_enabled": True,
            "object_lock_enabled": True,
            "compliance_retention_verified": True,
            "exact_version_read_back_verified": True,
            "idempotent_conditional_write_reused_version": True,
            "root_exact_version_delete_rejected": bool(deletion_code),
            "root_retention_shortening_rejected": bool(retention_code),
            "unexpected_versions_or_delete_markers_absent": True,
        },
        "limits": {
            "external_service_verified": False,
            "multi_node_durability_verified": False,
            "enterprise_workload_identity_verified": False,
            "tls_verified": False,
            "maintained_production_minio_release_verified": False,
        },
        "privacy": {
            "captures_temporary_credentials": False,
            "credentials_enter_command_arguments": False,
            "captures_checkpoint_body": False,
            "captures_environment_values": False,
        },
    }
    serialized = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if root_user in serialized or root_password in serialized:
        raise RuntimeError("temporary storage credential entered the report")
    return result


def main() -> None:
    result = verify()
    if not all(result["checks"].values()):
        raise RuntimeError("MinIO Object Lock verification failed")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
