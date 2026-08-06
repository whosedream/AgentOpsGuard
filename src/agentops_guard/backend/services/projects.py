from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.models import Project
from agentops_guard.backend.services.identity import ensure_bootstrap_organization


def ensure_project(db: Session, project_id: str, organization_id: str | None = None) -> Project:
    project = db.get(Project, project_id)
    if project:
        if organization_id and not project.organization_id:
            project.organization_id = organization_id
            db.flush()
        return project
    settings = get_settings()
    organization = ensure_bootstrap_organization(db)
    project = Project(
        id=project_id,
        organization_id=organization_id or organization.id,
        name=project_id,
        store_raw_content=settings.store_raw_content,
        retention_days=settings.retention_days,
        policy_fail_mode=settings.policy_fail_mode,
        status="active",
        metadata_json={},
    )
    db.add(project)
    db.flush()
    return project


def project_for_resource(db: Session, model, resource_id: str, *, project_field: str = "project_id"):
    row = db.get(model, resource_id)
    if row is None:
        return None, None
    return row, getattr(row, project_field, None)
