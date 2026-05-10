from typing import Any

from sqlalchemy.orm import Session

from agentops_guard.backend.models import AuditLog
from agentops_guard.backend.services.content import new_id


def record_audit(
    db: Session,
    *,
    project_id: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    actor_type: str = "api_key",
    actor_id: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    row = AuditLog(
        id=new_id("audit"),
        project_id=project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        before=before,
        after=after,
        metadata_json=metadata or {},
    )
    db.add(row)
    db.flush()
    return row

