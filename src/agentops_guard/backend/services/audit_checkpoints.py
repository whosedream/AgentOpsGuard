from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from urllib.parse import quote

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import func
from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.models import AuditChainHead, AuditCheckpoint, AuditLog
from agentops_guard.backend.services.audit import (
    lock_audit_chain,
    verify_audit_chain,
    verify_audit_prefix,
)
from agentops_guard.backend.services.content import new_id
from agentops_guard.backend.services.mcp_tool_revisions import canonical_json
from agentops_guard.backend.services.openbao_auth import (
    OpenBaoAuthenticationUnavailable,
    OpenBaoTokenProvider,
    configured_openbao_token_provider,
    resolve_openbao_token_provider,
)
from agentops_guard.backend.telemetry import inject_trace_headers


class AuditCheckpointUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class SignatureEnvelope:
    signature: str
    key_version: int
    public_key: str


@dataclass(frozen=True)
class AuditCheckpointIntegrity:
    valid: bool
    signature_valid: bool
    chain_prefix_valid: bool
    key_origin_valid: bool | None = None
    reason: str | None = None


class OpenBaoTransitSigner:
    """Ask OpenBao Transit to sign; private key material never leaves OpenBao."""

    def __init__(
        self,
        *,
        url: str,
        token: str | None = None,
        token_provider: OpenBaoTokenProvider | None = None,
        mount: str,
        key_name: str,
        timeout: float,
        client: httpx.Client | None = None,
    ) -> None:
        self._url = url.rstrip("/")
        self._token_provider = resolve_openbao_token_provider(
            token=token,
            token_provider=token_provider,
        )
        self._mount = mount
        self.key_name = key_name
        self._timeout = timeout
        self._client = client

    def sign(self, payload: bytes) -> SignatureEnvelope:
        try:
            response = self._request(
                "POST",
                f"sign/{quote(self.key_name, safe='')}",
                json={"input": b64encode(payload).decode("ascii")},
            )
            response.raise_for_status()
            signature = str(response.json()["data"]["signature"])
            key_version = _signature_version(signature)
            public_key = self.public_key(key_version)
            envelope = SignatureEnvelope(signature, key_version, public_key)
            _verify_signature(payload, envelope)
            return envelope
        except (
            httpx.HTTPError,
            OpenBaoAuthenticationUnavailable,
            KeyError,
            TypeError,
            ValueError,
            InvalidSignature,
        ):
            raise AuditCheckpointUnavailable("OpenBao audit signing failed") from None

    def check_ready(self) -> None:
        try:
            self.public_key()
        except AuditCheckpointUnavailable:
            raise AuditCheckpointUnavailable("OpenBao audit signing key is unavailable") from None

    def public_key(self, key_version: int | None = None) -> str:
        try:
            response = self._request("GET", f"keys/{quote(self.key_name, safe='')}")
            response.raise_for_status()
            data = response.json()["data"]
            if data["type"] != "ed25519" or data["exportable"] is not False:
                raise ValueError("audit key must be non-exportable Ed25519")
            resolved_version = str(key_version or int(data["latest_version"]))
            public_key = str(data["keys"][resolved_version]["public_key"])
            _load_ed25519_public_key(public_key)
            return public_key
        except (
            httpx.HTTPError,
            OpenBaoAuthenticationUnavailable,
            KeyError,
            TypeError,
            ValueError,
        ):
            raise AuditCheckpointUnavailable("OpenBao audit public key is unavailable") from None

    def _request(self, method: str, operation: str, **kwargs: Any) -> httpx.Response:
        token = self._token_provider.token()
        headers = {"X-Vault-Token": token} if token is not None else {}
        inject_trace_headers(headers)
        url = f"{self._url}/v1/{quote(self._mount, safe='')}/{operation}"
        if self._client is not None:
            response = self._client.request(method, url, headers=headers, **kwargs)
            if response.status_code not in {401, 403}:
                return response
            self._token_provider.invalidate()
            token = self._token_provider.token()
            if token is None:
                headers.pop("X-Vault-Token", None)
            else:
                headers["X-Vault-Token"] = token
            return self._client.request(method, url, headers=headers, **kwargs)
        with httpx.Client(timeout=self._timeout, follow_redirects=False, trust_env=False) as client:
            response = client.request(method, url, headers=headers, **kwargs)
            if response.status_code not in {401, 403}:
                return response
            self._token_provider.invalidate()
            token = self._token_provider.token()
            if token is None:
                headers.pop("X-Vault-Token", None)
            else:
                headers["X-Vault-Token"] = token
            return client.request(method, url, headers=headers, **kwargs)


def configured_audit_signer() -> OpenBaoTransitSigner:
    settings = get_settings()
    if settings.audit_checkpoint_backend != "openbao":
        raise AuditCheckpointUnavailable("audit checkpoint signing is disabled")
    assert settings.openbao_url is not None
    return OpenBaoTransitSigner(
        url=settings.openbao_url,
        token_provider=configured_openbao_token_provider(settings),
        mount=settings.openbao_transit_mount,
        key_name=settings.audit_checkpoint_key_name,
        timeout=settings.openbao_timeout_seconds,
    )


def create_audit_checkpoint(
    db: Session,
    *,
    project_id: str,
    signer: OpenBaoTransitSigner | None = None,
) -> AuditCheckpoint:
    lock_audit_chain(db, project_id)
    integrity = verify_audit_chain(db, project_id)
    if not integrity.valid:
        raise ValueError("audit chain is not valid")
    head = db.get(AuditChainHead, project_id)
    if head is None:
        raise ValueError("audit chain is empty")
    checked_entries = int(
        db.query(func.count(AuditLog.id))
        .filter(AuditLog.project_id == project_id, AuditLog.entry_hash.is_not(None))
        .scalar()
        or 0
    )
    issued_at = datetime.now(UTC)
    payload = audit_checkpoint_payload(
        project_id=project_id,
        entry_id=head.entry_id,
        entry_hash=head.entry_hash,
        checked_entries=checked_entries,
        issued_at=issued_at,
    )
    payload_bytes = canonical_json(payload).encode("utf-8")
    resolved_signer = signer or configured_audit_signer()
    signed = resolved_signer.sign(payload_bytes)
    row = AuditCheckpoint(
        id=new_id("checkpoint"),
        project_id=project_id,
        entry_id=head.entry_id,
        entry_hash=head.entry_hash,
        checked_entries=checked_entries,
        payload_digest=sha256(payload_bytes).hexdigest(),
        signer="openbao-transit-ed25519",
        key_name=resolved_signer.key_name,
        key_version=signed.key_version,
        signature=signed.signature,
        public_key=signed.public_key,
        issued_at=issued_at,
        created_at=issued_at,
    )
    db.add(row)
    db.flush()
    return row


def verify_audit_checkpoint(
    db: Session,
    row: AuditCheckpoint,
    *,
    signer: OpenBaoTransitSigner | None = None,
) -> AuditCheckpointIntegrity:
    payload = audit_checkpoint_payload(
        project_id=row.project_id,
        entry_id=row.entry_id,
        entry_hash=row.entry_hash,
        checked_entries=row.checked_entries,
        issued_at=row.issued_at,
    )
    payload_bytes = canonical_json(payload).encode("utf-8")
    if sha256(payload_bytes).hexdigest() != row.payload_digest:
        return AuditCheckpointIntegrity(False, False, False, False, "checkpoint_payload_changed")
    envelope = SignatureEnvelope(row.signature, row.key_version, row.public_key)
    try:
        _verify_signature(payload_bytes, envelope)
    except (TypeError, ValueError, InvalidSignature):
        return AuditCheckpointIntegrity(False, False, False, False, "checkpoint_signature_invalid")
    key_origin_valid = None
    if signer is not None:
        if signer.key_name != row.key_name:
            return AuditCheckpointIntegrity(False, True, False, False, "checkpoint_key_changed")
        trusted_key = signer.public_key(row.key_version)
        key_origin_valid = _public_key_bytes(trusted_key) == _public_key_bytes(row.public_key)
        if not key_origin_valid:
            return AuditCheckpointIntegrity(False, True, False, False, "checkpoint_key_changed")
    prefix = verify_audit_prefix(
        db,
        row.project_id,
        checked_entries=row.checked_entries,
        expected_entry_id=row.entry_id,
        expected_entry_hash=row.entry_hash,
    )
    if not prefix.valid:
        return AuditCheckpointIntegrity(
            False, True, False, key_origin_valid, "audit_prefix_changed"
        )
    return AuditCheckpointIntegrity(True, True, True, key_origin_valid)


def audit_checkpoint_payload(
    *,
    project_id: str,
    entry_id: str,
    entry_hash: str,
    checked_entries: int,
    issued_at: object,
) -> dict[str, Any]:
    normalized_issued_at = issued_at
    if normalized_issued_at.tzinfo is None:
        normalized_issued_at = normalized_issued_at.replace(tzinfo=UTC)
    return {
        "schema": "agentops-audit-checkpoint/v1",
        "project_id": project_id,
        "entry_id": entry_id,
        "entry_hash": entry_hash,
        "checked_entries": checked_entries,
        "issued_at": normalized_issued_at.astimezone(UTC).isoformat(),
    }


def _signature_version(signature: str) -> int:
    parts = signature.split(":", 2)
    if len(parts) != 3 or parts[0] != "vault" or not parts[1].startswith("v"):
        raise ValueError("unexpected OpenBao signature format")
    return int(parts[1][1:])


def _verify_signature(payload: bytes, envelope: SignatureEnvelope) -> None:
    if _signature_version(envelope.signature) != envelope.key_version:
        raise ValueError("signature key version mismatch")
    public_key = _load_ed25519_public_key(envelope.public_key)
    encoded_signature = envelope.signature.split(":", 2)[2]
    public_key.verify(b64decode(encoded_signature, validate=True), payload)


def _load_ed25519_public_key(encoded_key: str) -> Ed25519PublicKey:
    if encoded_key.startswith("-----BEGIN PUBLIC KEY-----"):
        public_key = load_pem_public_key(encoded_key.encode("ascii"))
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("audit signing key must be Ed25519")
        return public_key
    raw_key = b64decode(encoded_key, validate=True)
    if len(raw_key) != 32:
        raise ValueError("OpenBao Ed25519 public key must contain 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw_key)


def _public_key_bytes(encoded_key: str) -> bytes:
    return _load_ed25519_public_key(encoded_key).public_bytes_raw()
