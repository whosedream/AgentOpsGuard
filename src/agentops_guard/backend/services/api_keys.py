from datetime import UTC, datetime
from hashlib import sha256
from secrets import token_urlsafe

from sqlalchemy.orm import Session

from agentops_guard.backend.models import ApiKey
from agentops_guard.backend.services.content import new_id


def hash_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def create_api_key(
    db: Session,
    project_id: str,
    name: str,
    scopes: list[str],
    expires_at: datetime | None = None,
    agent_id: str | None = None,
) -> tuple[ApiKey, str]:
    token = f"ag_{token_urlsafe(32)}"
    row = ApiKey(
        id=new_id("key"),
        project_id=project_id,
        name=name,
        agent_id=agent_id,
        key_hash=hash_token(token),
        scopes=scopes,
        expires_at=expires_at,
    )
    db.add(row)
    db.flush()
    return row, token


def authenticate_api_key(db: Session, token: str) -> ApiKey | None:
    row = db.query(ApiKey).filter(ApiKey.key_hash == hash_token(token)).first()
    if not row or row.revoked_at is not None:
        return None
    if row.expires_at is not None:
        expires_at = row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            return None
    row.last_used_at = datetime.now(UTC)
    db.flush()
    return row


def has_scope(row: ApiKey | None, required_scope: str | None) -> bool:
    if required_scope is None:
        return True
    if row is None:
        return True
    scopes = set(row.scopes or [])
    prefix = required_scope.split(":", 1)[0]
    return "admin:*" in scopes or required_scope in scopes or f"{prefix}:*" in scopes
