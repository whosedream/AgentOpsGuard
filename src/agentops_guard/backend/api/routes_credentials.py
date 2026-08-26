import json
from datetime import UTC, datetime
from typing import Any

import httpx
from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import (
    AuthContext,
    authorize_project_access,
    get_auth_context,
    require_membership_capability,
    require_scope,
)
from agentops_guard.backend.database import get_db
from agentops_guard.backend.models import Project, ServiceCredential
from agentops_guard.backend.schemas import (
    CredentialRefOut,
    DeepSeekChatRequest,
    DeepSeekCredentialCreate,
    DeepSeekCredentialRotate,
    DeleteResponse,
)
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.content import detect_secret_labels, new_id
from agentops_guard.backend.services.credentials import (
    CredentialStore,
    CredentialStoreUnavailable,
    configured_credential_store,
)
from agentops_guard.backend.services.deepseek import (
    DEEPSEEK_CHAT_COMPLETIONS_URL,
    DeepSeekTransport,
)


DEEPSEEK_PROVIDER = "deepseek"
DEEPSEEK_TOOL = "deepseek.chat.completions"
DEEPSEEK_ORIGIN = "https://api.deepseek.com"
DEEPSEEK_INJECTION_FIELD = "Authorization"
DEEPSEEK_SCOPE = "models:invoke"

v1_router = APIRouter()


def get_credential_vault() -> CredentialStore:
    try:
        return configured_credential_store()
    except (CredentialStoreUnavailable, ValueError):
        raise HTTPException(503, "Credential vault is unavailable") from None


def get_deepseek_transport() -> DeepSeekTransport:
    return DeepSeekTransport()


def _resolve_bound_secret(
    credential_ref: str,
    *,
    row: ServiceCredential,
    vault: CredentialStore,
) -> str:
    if credential_ref != row.credential_ref:
        raise ValueError("credential reference mismatch")
    return vault.resolve_credential(
        row.credential_ref,
        row.encrypted_secret,
        row.binding_ciphertext,
        _binding(row),
    )


@v1_router.post(
    "/credentials/deepseek",
    response_model=CredentialRefOut,
    dependencies=[Depends(require_membership_capability("credentials:write"))],
)
def create_deepseek_credential(
    payload: DeepSeekCredentialCreate,
    request: Request,
    vault: CredentialStore = Depends(get_credential_vault),
    db: Session = Depends(get_db),
) -> CredentialRefOut:
    auth = get_auth_context(request)
    _authorize_active_project(db, auth, payload.project_id)
    credential_ref = new_id("cred")
    row = ServiceCredential(
        credential_ref=credential_ref,
        project_id=payload.project_id,
        name=payload.name,
        encrypted_secret="",
        binding_ciphertext="",
        provider=DEEPSEEK_PROVIDER,
        tool=DEEPSEEK_TOOL,
        origin=DEEPSEEK_ORIGIN,
        injection_field=DEEPSEEK_INJECTION_FIELD,
        credential_scope=DEEPSEEK_SCOPE,
        allowed_actor_ids=payload.allowed_actor_ids,
        status="active",
        version=1,
    )
    metadata = {"name": payload.name, "allowed_actor_ids": payload.allowed_actor_ids}
    plaintext_secret = payload.secret.get_secret_value()
    if (
        _metadata_contains_exact_secret(
            payload.name,
            payload.allowed_actor_ids,
            plaintext_secret,
        )
        or _contains_secret(metadata)
    ):
        raise HTTPException(400, "Credential metadata contains a raw secret")
    try:
        _store_credential(vault, row, plaintext_secret)
    except CredentialStoreUnavailable:
        raise HTTPException(503, "Credential vault is unavailable") from None
    db.add(row)
    db.flush()
    _audit(
        db,
        auth=auth,
        row=row,
        action="credential.create",
        after={"status": row.status, "version": row.version},
    )
    db.commit()
    return CredentialRefOut(credential_ref=credential_ref)


@v1_router.put(
    "/credentials/{credential_ref}/rotate",
    response_model=CredentialRefOut,
    dependencies=[Depends(require_membership_capability("credentials:write"))],
)
def rotate_deepseek_credential(
    credential_ref: str,
    payload: DeepSeekCredentialRotate,
    request: Request,
    vault: CredentialStore = Depends(get_credential_vault),
    db: Session = Depends(get_db),
) -> CredentialRefOut:
    auth = get_auth_context(request)
    _authorize_active_project(db, auth, payload.project_id)
    row = _credential_row(db, credential_ref, payload.project_id)
    _validate_static_binding(row)
    if row.status != "active":
        raise HTTPException(409, "Credential is not active")
    try:
        _validate_encrypted_binding(vault, row)
    except CredentialStoreUnavailable:
        raise HTTPException(503, "Credential vault is unavailable") from None
    except (InvalidToken, ValueError):
        raise HTTPException(409, "Credential binding is invalid") from None
    plaintext_secret = payload.secret.get_secret_value()
    if _metadata_contains_exact_secret(
        row.name,
        row.allowed_actor_ids,
        plaintext_secret,
    ):
        raise HTTPException(400, "Credential metadata contains a raw secret")
    previous_version = row.version
    row.version += 1
    try:
        _store_credential(vault, row, plaintext_secret)
    except CredentialStoreUnavailable:
        raise HTTPException(503, "Credential vault is unavailable") from None
    row.updated_at = datetime.now(UTC)
    _audit(
        db,
        auth=auth,
        row=row,
        action="credential.rotate",
        before={"version": previous_version},
        after={"version": row.version},
    )
    db.commit()
    return CredentialRefOut(credential_ref=credential_ref)


@v1_router.delete(
    "/credentials/{credential_ref}",
    response_model=DeleteResponse,
    dependencies=[Depends(require_membership_capability("credentials:write"))],
)
def revoke_deepseek_credential(
    credential_ref: str,
    project_id: str,
    request: Request,
    vault: CredentialStore = Depends(get_credential_vault),
    db: Session = Depends(get_db),
) -> DeleteResponse:
    auth = get_auth_context(request)
    _authorize_active_project(db, auth, project_id)
    row = _credential_row(db, credential_ref, project_id)
    _validate_static_binding(row)
    if row.status != "active":
        raise HTTPException(409, "Credential is not active")
    try:
        _validate_encrypted_binding(vault, row)
    except CredentialStoreUnavailable:
        raise HTTPException(503, "Credential vault is unavailable") from None
    except (InvalidToken, ValueError):
        raise HTTPException(409, "Credential binding is invalid") from None
    before = {"status": row.status, "version": row.version}
    row.status = "revoked"
    row.revoked_at = datetime.now(UTC)
    row.updated_at = row.revoked_at
    try:
        row.binding_ciphertext = vault.rebind_credential(
            row.credential_ref,
            row.encrypted_secret,
            row.binding_ciphertext,
            _binding(row),
        )
    except (CredentialStoreUnavailable, InvalidToken, ValueError):
        raise HTTPException(503, "Credential vault is unavailable") from None
    _audit(
        db,
        auth=auth,
        row=row,
        action="credential.revoke",
        before=before,
        after={"status": row.status, "version": row.version},
    )
    db.commit()
    return DeleteResponse(status="deleted", id=credential_ref)


@v1_router.post(
    "/deepseek/chat/completions",
    dependencies=[Depends(require_scope("models:invoke"))],
)
def deepseek_chat_completions(
    payload: DeepSeekChatRequest,
    request: Request,
    vault: CredentialStore = Depends(get_credential_vault),
    transport: DeepSeekTransport = Depends(get_deepseek_transport),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    auth = get_auth_context(request)
    _authorize_active_project(db, auth, payload.project_id)
    row = _credential_row(db, payload.credential_ref, payload.project_id)
    _authorize_runtime_binding(row, auth)
    request_body = payload.model_dump(exclude={"project_id", "credential_ref"})
    if _contains_secret(request_body):
        raise HTTPException(400, "Raw credentials are not allowed")
    try:
        _validate_encrypted_binding(vault, row)
    except (CredentialStoreUnavailable, InvalidToken, ValueError, KeyError, TypeError):
        raise HTTPException(503, "Credential vault is unavailable") from None
    try:
        result = transport.chat_completions(
            credential_ref=row.credential_ref,
            resolve_credential=lambda credential_ref: _resolve_bound_secret(
                credential_ref, row=row, vault=vault
            ),
            **request_body,
        )
    except (CredentialStoreUnavailable, InvalidToken):
        raise HTTPException(503, "Credential vault is unavailable") from None
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, "DeepSeek request failed") from None
    if _contains_secret(result):
        raise HTTPException(502, "DeepSeek response was rejected")
    row.last_used_at = datetime.now(UTC)
    row.updated_at = row.last_used_at
    _audit(
        db,
        auth=auth,
        row=row,
        action="credential.use",
        after={"status": "succeeded", "version": row.version},
        metadata={"model": payload.model, "endpoint": DEEPSEEK_CHAT_COMPLETIONS_URL},
    )
    db.commit()
    return result


def _credential_row(
    db: Session, credential_ref: str, project_id: str
) -> ServiceCredential:
    row = (
        db.query(ServiceCredential)
        .filter(
            ServiceCredential.credential_ref == credential_ref,
            ServiceCredential.project_id == project_id,
        )
        .with_for_update()
        .first()
    )
    if row is None:
        raise HTTPException(404, "Credential not found")
    return row


def _authorize_active_project(
    db: Session, auth: AuthContext, project_id: str
) -> Project:
    authorize_project_access(auth, project_id, db=db)
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(404, "Project not found")
    if project.status != "active":
        raise HTTPException(409, "Project is not active")
    return project


def _validate_static_binding(row: ServiceCredential) -> None:
    if (
        row.provider != DEEPSEEK_PROVIDER
        or row.tool != DEEPSEEK_TOOL
        or row.origin != DEEPSEEK_ORIGIN
        or row.injection_field != DEEPSEEK_INJECTION_FIELD
        or row.credential_scope != DEEPSEEK_SCOPE
        or row.version < 1
    ):
        raise HTTPException(409, "Credential binding is invalid")


def _authorize_runtime_binding(row: ServiceCredential, auth: AuthContext) -> None:
    _validate_static_binding(row)
    if row.status != "active" or row.revoked_at is not None:
        raise HTTPException(409, "Credential is not active")
    if auth.actor_id is None or auth.actor_id not in (row.allowed_actor_ids or []):
        raise HTTPException(403, "Credential actor is not authorized")


def _contains_secret(value: Any) -> bool:
    labels = set(detect_secret_labels(_serialized(value)))
    return bool(labels - {"email", "phone"})


def _metadata_contains_exact_secret(
    name: str,
    allowed_actor_ids: list[str],
    secret: str,
) -> bool:
    return secret in name or any(secret in actor_id for actor_id in allowed_actor_ids)


def _serialized(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _binding(row: ServiceCredential) -> dict[str, Any]:
    revoked_at = row.revoked_at
    if revoked_at is not None and revoked_at.tzinfo is None:
        revoked_at = revoked_at.replace(tzinfo=UTC)
    return {
        "credential_ref": row.credential_ref,
        "project_id": row.project_id,
        "provider": row.provider,
        "tool": row.tool,
        "origin": row.origin,
        "injection_field": row.injection_field,
        "credential_scope": row.credential_scope,
        "status": row.status,
        "version": row.version,
        "allowed_actor_ids": sorted(row.allowed_actor_ids or []),
        "revoked_at": revoked_at.astimezone(UTC).isoformat()
        if revoked_at is not None
        else None,
    }


def _store_credential(
    vault: CredentialStore, row: ServiceCredential, secret: str
) -> None:
    stored = vault.store_credential(row.credential_ref, secret, _binding(row))
    row.encrypted_secret = stored.secret_ref
    row.binding_ciphertext = stored.binding_proof


def _validate_encrypted_binding(
    vault: CredentialStore, row: ServiceCredential
) -> None:
    vault.resolve_credential(
        row.credential_ref,
        row.encrypted_secret,
        row.binding_ciphertext,
        _binding(row),
    )


def _audit(
    db: Session,
    *,
    auth: AuthContext,
    row: ServiceCredential,
    action: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    record_audit(
        db,
        project_id=row.project_id,
        action=action,
        resource_type="service_credential",
        resource_id=row.credential_ref,
        actor_type=auth.kind,
        actor_id=auth.actor_id,
        before=before,
        after=after,
        metadata=metadata,
    )
