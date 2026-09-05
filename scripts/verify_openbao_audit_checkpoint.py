from __future__ import annotations

from base64 import b64encode
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_ready(base_url: str) -> None:
    deadline = time.monotonic() + 15
    with httpx.Client(timeout=1, trust_env=False) as client:
        while time.monotonic() < deadline:
            try:
                if client.get(f"{base_url}/v1/sys/health").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    raise RuntimeError("OpenBao did not become ready")


def main() -> None:
    bao = shutil.which("bao")
    if bao is None:
        raise RuntimeError("OpenBao CLI is not installed")
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    token = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="agentops-openbao-audit-") as temp_dir:
        database_path = Path(temp_dir) / "checkpoint.sqlite3"
        process = subprocess.Popen(
            [
                bao,
                "server",
                "-dev",
                f"-dev-listen-address=127.0.0.1:{port}",
            ],
            env={
                "BAO_DEV_ROOT_TOKEN_ID": token,
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_until_ready(base_url)
            headers = {"X-Vault-Token": token}
            with httpx.Client(timeout=3, trust_env=False, headers=headers) as client:
                response = client.post(
                    f"{base_url}/v1/sys/mounts/transit",
                    json={"type": "transit"},
                )
                response.raise_for_status()
                response = client.post(
                    f"{base_url}/v1/transit/keys/agentops-audit",
                    json={"type": "ed25519", "exportable": False},
                )
                response.raise_for_status()
                response = client.get(f"{base_url}/v1/transit/keys/agentops-audit")
                response.raise_for_status()
                if response.json()["data"]["exportable"] is not False:
                    raise RuntimeError("audit signing key unexpectedly allows private-key export")

            os.environ.update(
                {
                    "AGENTOPS_DATABASE_URL": f"sqlite:///{database_path.as_posix()}",
                    "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP": "true",
                }
            )
            from agentops_guard.backend.database import SessionLocal, init_db
            from agentops_guard.backend.models import AuditChainHead, AuditLog
            from agentops_guard.backend.services.audit import (
                _audit_hash,
                record_audit,
                verify_audit_chain,
            )
            from agentops_guard.backend.services.audit_checkpoints import (
                audit_checkpoint_payload,
                create_audit_checkpoint,
                OpenBaoTransitSigner,
                verify_audit_checkpoint,
            )
            from agentops_guard.backend.services.mcp_tool_revisions import canonical_json

            init_db()
            signer = OpenBaoTransitSigner(
                url=base_url,
                token=token,
                mount="transit",
                key_name="agentops-audit",
                timeout=3,
            )
            signer.check_ready()
            project_id = "openbao_audit_verification"
            db = SessionLocal()
            try:
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
                checkpoint = create_audit_checkpoint(
                    db,
                    project_id=project_id,
                    signer=signer,
                )
                db.commit()
                initial_valid = verify_audit_checkpoint(db, checkpoint, signer=signer).valid

                original_signature = checkpoint.signature
                original_public_key = checkpoint.public_key
                attacker_key = Ed25519PrivateKey.generate()
                payload = audit_checkpoint_payload(
                    project_id=checkpoint.project_id,
                    entry_id=checkpoint.entry_id,
                    entry_hash=checkpoint.entry_hash,
                    checked_entries=checkpoint.checked_entries,
                    issued_at=checkpoint.issued_at,
                )
                attacker_signature = attacker_key.sign(
                    canonical_json(payload).encode("utf-8")
                )
                checkpoint.signature = (
                    f"vault:v1:{b64encode(attacker_signature).decode('ascii')}"
                )
                checkpoint.public_key = attacker_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("ascii")
                db.commit()
                key_replacement = verify_audit_checkpoint(
                    db, checkpoint, signer=signer
                )
                checkpoint.signature = original_signature
                checkpoint.public_key = original_public_key
                db.commit()

                first.after = {"status": "denied"}
                rows = (
                    db.query(AuditLog)
                    .filter(AuditLog.project_id == project_id)
                    .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
                    .all()
                )
                previous_hash = None
                for row in rows:
                    row.previous_hash = previous_hash
                    row.entry_hash = _audit_hash(
                        previous_hash=previous_hash,
                        row_id=row.id,
                        project_id=row.project_id,
                        actor_type=row.actor_type,
                        actor_id=row.actor_id,
                        action=row.action,
                        resource_type=row.resource_type,
                        resource_id=row.resource_id,
                        before=row.before,
                        after=row.after,
                        metadata=row.metadata_json or {},
                        created_at=row.created_at,
                    )
                    previous_hash = row.entry_hash
                head = db.get(AuditChainHead, project_id)
                assert head is not None
                head.entry_id = rows[-1].id
                head.entry_hash = rows[-1].entry_hash
                db.commit()

                chain_recomputed_valid = verify_audit_chain(db, project_id).valid
                checkpoint_after_rewrite = verify_audit_checkpoint(
                    db, checkpoint, signer=signer
                )
            finally:
                db.close()
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            os.environ.pop("AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP", None)
            os.environ.pop("AGENTOPS_DATABASE_URL", None)

    if (
        not initial_valid
        or key_replacement.valid
        or not chain_recomputed_valid
        or checkpoint_after_rewrite.valid
    ):
        raise RuntimeError("signed audit checkpoint verification failed")
    print(
        json.dumps(
            {
                "openbao_version": subprocess.run(
                    [bao, "version"], capture_output=True, text=True, check=True
                ).stdout.split()[1],
                "transit_key_type": "ed25519",
                "transit_private_key_exportable": False,
                "checkpoint_initially_valid": initial_valid,
                "checkpoint_detected_public_key_replacement": not key_replacement.valid,
                "public_key_replacement_failure_reason": key_replacement.reason,
                "database_chain_recomputed_valid": chain_recomputed_valid,
                "checkpoint_detected_history_rewrite": not checkpoint_after_rewrite.valid,
                "checkpoint_failure_reason": checkpoint_after_rewrite.reason,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
