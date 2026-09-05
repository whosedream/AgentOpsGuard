from __future__ import annotations

from base64 import b64decode, b64encode
import json
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.main import app
from agentops_guard.backend.models import AuditChainHead, AuditLog
from agentops_guard.backend.services.audit import _audit_hash, record_audit, verify_audit_chain
from agentops_guard.backend.services.audit_checkpoints import (
    AuditCheckpointUnavailable,
    OpenBaoTransitSigner,
    audit_checkpoint_payload,
    create_audit_checkpoint,
    verify_audit_checkpoint,
)
from agentops_guard.backend.services.mcp_tool_revisions import canonical_json
from agentops_guard.backend.services.projects import ensure_project


def _signer(token: str = "test-only-openbao-token") -> OpenBaoTransitSigner:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Vault-Token"] == token
        if request.method == "POST" and request.url.path.endswith("/sign/agentops-audit"):
            payload = b64decode(json.loads(request.content)["input"])
            signature = b64encode(private_key.sign(payload)).decode("ascii")
            return httpx.Response(200, json={"data": {"signature": f"vault:v1:{signature}"}})
        if request.method == "GET" and request.url.path.endswith("/keys/agentops-audit"):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "type": "ed25519",
                        "exportable": False,
                        "latest_version": 1,
                        "keys": {"1": {"public_key": public_key}},
                    }
                },
            )
        return httpx.Response(404)

    return OpenBaoTransitSigner(
        url="http://openbao.test",
        token=token,
        mount="transit",
        key_name="agentops-audit",
        timeout=1,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_signed_checkpoint_detects_history_rewritten_with_a_recomputed_chain():
    project_id = f"audit_checkpoint_{uuid4().hex}"
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
        signer = _signer()
        checkpoint = create_audit_checkpoint(db, project_id=project_id, signer=signer)
        db.commit()

        initial = verify_audit_checkpoint(db, checkpoint, signer=signer)
        assert initial.valid is True
        assert initial.key_origin_valid is True

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
        attacker_signature = attacker_key.sign(canonical_json(payload).encode("utf-8"))
        checkpoint.signature = f"vault:v1:{b64encode(attacker_signature).decode('ascii')}"
        checkpoint.public_key = attacker_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        db.commit()
        assert verify_audit_checkpoint(db, checkpoint).valid is True
        forged = verify_audit_checkpoint(db, checkpoint, signer=signer)
        assert forged.valid is False
        assert forged.key_origin_valid is False
        assert forged.reason == "checkpoint_key_changed"
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

        assert verify_audit_chain(db, project_id).valid is True
        result = verify_audit_checkpoint(db, checkpoint, signer=signer)
        assert result.valid is False
        assert result.signature_valid is True
        assert result.chain_prefix_valid is False
        assert result.reason == "audit_prefix_changed"
    finally:
        db.close()


def test_signer_rejects_a_signature_that_openbao_public_key_cannot_verify():
    private_key = Ed25519PrivateKey.generate()
    another_key = Ed25519PrivateKey.generate()
    public_key = another_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            payload = b64decode(json.loads(request.content)["input"])
            signature = b64encode(private_key.sign(payload)).decode("ascii")
            return httpx.Response(200, json={"data": {"signature": f"vault:v1:{signature}"}})
        return httpx.Response(
            200,
            json={
                "data": {
                    "type": "ed25519",
                    "exportable": False,
                    "latest_version": 1,
                    "keys": {"1": {"public_key": public_key}},
                }
            },
        )

    signer = OpenBaoTransitSigner(
        url="http://openbao.test",
        token="test-only-openbao-token",
        mount="transit",
        key_name="agentops-audit",
        timeout=1,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        signer.sign(b"checkpoint")
    except AuditCheckpointUnavailable:
        pass
    else:
        raise AssertionError("invalid OpenBao signature was accepted")


def test_checkpoint_api_issues_lists_and_verifies_public_evidence(monkeypatch):
    project_id = f"audit_checkpoint_api_{uuid4().hex}"
    db = SessionLocal()
    try:
        ensure_project(db, project_id)
        record_audit(
            db,
            project_id=project_id,
            action="execution.succeeded",
            resource_type="execution",
            after={"status": "succeeded"},
        )
        db.commit()
    finally:
        db.close()

    from agentops_guard.backend.services import audit_checkpoints

    monkeypatch.setattr(audit_checkpoints, "configured_audit_signer", _signer)
    client = TestClient(app)
    headers = {"X-AgentOps-Api-Key": "dev-agentops-key"}
    issued = client.post(
        "/v1/audit-logs/checkpoints",
        params={"project_id": project_id},
        headers=headers,
    )
    assert issued.status_code == 200, issued.text
    checkpoint = issued.json()
    assert checkpoint["signer"] == "openbao-transit-ed25519"
    assert "private" not in json.dumps(checkpoint).casefold()

    listed = client.get(
        "/v1/audit-logs/checkpoints",
        params={"project_id": project_id},
        headers=headers,
    )
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [checkpoint["id"]]

    verified = client.get(
        f"/v1/audit-logs/checkpoints/{checkpoint['id']}/integrity",
        params={"project_id": project_id},
        headers=headers,
    )
    assert verified.status_code == 200
    assert verified.json() == {
        "valid": True,
        "signature_valid": True,
        "chain_prefix_valid": True,
        "key_origin_valid": None,
        "reason": None,
    }
