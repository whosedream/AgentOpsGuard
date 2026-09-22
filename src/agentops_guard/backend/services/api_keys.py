from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from agentops_guard.backend.models import ApiKey
from agentops_guard.backend.services.content import new_id


# Display-only activity time, not an authorization cache or per-request audit.
ACTIVITY_REFRESH_INTERVAL = timedelta(seconds=60)


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
    current = datetime.now(UTC)
    if row.expires_at is not None:
        expires_at = row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= current:
            return None
    last_used = row.last_used_at
    if last_used is not None and last_used.tzinfo is None:
        last_used = last_used.replace(tzinfo=UTC)
    cutoff = current - ACTIVITY_REFRESH_INTERVAL
    if last_used is None or last_used <= cutoff:
        # Only the optional display update may skip a busy row. The original
        # authentication SELECT above always checks committed credentials.
        due = select(ApiKey.id).where(
            ApiKey.id == row.id, ApiKey.revoked_at.is_(None),
            or_(ApiKey.expires_at.is_(None), ApiKey.expires_at > current),
            or_(ApiKey.last_used_at.is_(None), ApiKey.last_used_at <= cutoff),
        ).with_for_update(skip_locked=True)
        refreshed = db.scalar(update(ApiKey).where(ApiKey.id.in_(due))
            .values(last_used_at=current).returning(ApiKey.last_used_at)
            .execution_options(synchronize_session=False))
        if refreshed is not None:
            # Do not leave the ORM object dirty and enqueue another UPDATE at
            # the caller's normal commit. Commit/rollback remain caller-owned.
            set_committed_value(row, "last_used_at", refreshed)
    return row


def has_scope(row: ApiKey | None, required_scope: str | None) -> bool:
    if required_scope is None:
        return True
    if row is None:
        return True
    scopes = set(row.scopes or [])
    prefix = required_scope.split(":", 1)[0]
    return "admin:*" in scopes or required_scope in scopes or f"{prefix}:*" in scopes
