from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe
from typing import Literal

from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.models import (
    Membership,
    Organization,
    Project,
    Session as AuthSession,
    User,
)
from agentops_guard.backend.schemas import MembershipCreate, MembershipUpdate, OrganizationCreate
from agentops_guard.backend.services.content import new_id
from agentops_guard.backend.services.oidc import oidc_external_subject


ROLE_CAPABILITIES: dict[str, list[str]] = {
    "admin": [
        "organizations:read",
        "organizations:write",
        "projects:read",
        "projects:write",
        "control:read",
        "control:admin",
        "mcp:read",
        "mcp:invoke",
        "mcp:admin",
        "runs:read",
        "runs:write",
        "replays:read",
        "replays:write",
        "evals:read",
        "evals:write",
        "approvals:read",
        "approvals:write",
        "audit:read",
        "audit:write",
        "raw_content:read",
        "api_keys:write",
        "policies:read",
        "policies:admin",
        "scanner:read",
        "scanner:admin",
        "jobs:read",
        "jobs:admin",
        "runs:admin",
        "credentials:write",
        "models:invoke",
    ],
    "security_reviewer": [
        "projects:read",
        "control:read",
        "approvals:read",
        "approvals:write",
        "audit:read",
        "runs:read",
        "replays:read",
        "evals:read",
        "raw_content:read",
        "policies:read",
        "scanner:read",
        "jobs:read",
    ],
    "developer": [
        "projects:read",
        "runs:read",
        "runs:write",
        "replays:read",
        "replays:write",
        "evals:read",
        "evals:write",
        "policies:read",
        "scanner:read",
        "mcp:read",
        "mcp:invoke",
        "jobs:read",
    ],
    "read_only": [
        "projects:read",
        "runs:read",
        "replays:read",
        "evals:read",
        "mcp:read",
        "jobs:read",
    ],
}


def role_capabilities(role: str) -> list[str]:
    return ROLE_CAPABILITIES.get(role, [])


def ensure_bootstrap_organization(db: Session) -> Organization:
    organization = db.get(Organization, "org_bootstrap")
    if organization:
        return organization
    organization = Organization(id="org_bootstrap", slug="bootstrap", name="Bootstrap Organization")
    db.add(organization)
    db.flush()
    return organization


def create_organization(
    db: Session, payload: OrganizationCreate
) -> tuple[Organization, User, Membership, Project | None]:
    organization = Organization(
        id=new_id("org"),
        slug=payload.slug or _slugify(payload.name),
        name=payload.name,
    )
    db.add(organization)
    db.flush()

    user = _get_or_create_user(
        db,
        email=payload.initial_admin["email"],
        display_name=payload.initial_admin.get("display_name") or payload.initial_admin["email"],
        provider="bootstrap",
    )
    membership = _create_membership_row(db, organization.id, user.id, "admin")
    project = None
    if payload.initial_project:
        project = Project(
            id=payload.initial_project["id"],
            organization_id=organization.id,
            name=payload.initial_project.get("name") or payload.initial_project["id"],
            store_raw_content=get_settings().store_raw_content,
            retention_days=get_settings().retention_days,
            policy_fail_mode=get_settings().policy_fail_mode,
            status="active",
            metadata_json={},
        )
        db.add(project)
        db.flush()

    return organization, user, membership, project


def list_organizations(db: Session) -> list[Organization]:
    return db.query(Organization).order_by(Organization.created_at.asc()).all()


def create_membership(db: Session, organization_id: str, payload: MembershipCreate) -> Membership:
    if payload.oidc_subject is not None and get_settings().oidc_issuer is None:
        raise ValueError("OIDC is not configured")
    user = _get_or_create_user(
        db,
        email=payload.email,
        display_name=payload.display_name,
        provider="oidc" if payload.oidc_subject is not None else "dev_stub",
    )
    if payload.oidc_subject is not None:
        assert get_settings().oidc_issuer is not None
        user.external_subject = oidc_external_subject(
            get_settings().oidc_issuer,
            payload.oidc_subject,
        )
    membership = (
        db.query(Membership)
        .filter(Membership.organization_id == organization_id, Membership.user_id == user.id)
        .first()
    )
    if membership:
        membership.role = payload.role
        membership.status = "active"
        db.flush()
        return membership
    membership = _create_membership_row(db, organization_id, user.id, payload.role)
    db.flush()
    return membership


def update_membership(db: Session, membership_id: str, payload: MembershipUpdate) -> Membership:
    membership = db.get(Membership, membership_id)
    if membership is None:
        raise ValueError("Membership not found")
    if payload.role is not None:
        membership.role = payload.role
    if payload.status is not None:
        membership.status = payload.status
    db.flush()
    return membership


def create_dev_session(
    db: Session,
    *,
    email: str,
    display_name: str,
    role: Literal["admin", "security_reviewer", "developer", "read_only"],
    organization_id: str | None = None,
    organization_name: str | None = None,
) -> tuple[Organization, User, Membership, Project]:
    user = _get_or_create_user(db, email=email, display_name=display_name, provider="dev_stub")

    if organization_id:
        organization = db.get(Organization, organization_id)
        if organization is None:
            raise ValueError("Organization not found")
    else:
        organization = (
            db.query(Organization)
            .filter(Organization.name == (organization_name or "Default Organization"))
            .first()
        )
        if organization is None:
            organization = Organization(
                id=new_id("org"),
                slug=_slugify(organization_name or "Default Organization"),
                name=organization_name or "Default Organization",
            )
            db.add(organization)
            db.flush()

    membership = (
        db.query(Membership)
        .filter(Membership.organization_id == organization.id, Membership.user_id == user.id)
        .first()
    )
    if membership is None:
        membership = _create_membership_row(db, organization.id, user.id, role)
    else:
        membership.role = role
        membership.status = "active"

    project = (
        db.query(Project)
        .filter(Project.organization_id == organization.id)
        .order_by(Project.created_at.asc())
        .first()
    )
    if project is None:
        preferred_project_id = (
            "default" if organization.slug == "default-organization" else new_id("project")
        )
        if db.get(Project, preferred_project_id) is not None:
            preferred_project_id = new_id("project")
        project = Project(
            id=preferred_project_id,
            organization_id=organization.id,
            name="Default Project",
            store_raw_content=get_settings().store_raw_content,
            retention_days=get_settings().retention_days,
            policy_fail_mode=get_settings().policy_fail_mode,
            status="active",
            metadata_json={},
        )
        db.add(project)
        db.flush()

    return organization, user, membership, project


def revoke_session(db: Session, session_token: str) -> None:
    session = (
        db.query(AuthSession)
        .filter(AuthSession.token_hash == hash_session_token(session_token))
        .first()
    )
    if session is None:
        return
    session.revoked_at = datetime.now(UTC)
    db.flush()


def authenticate_session(db: Session, session_token: str) -> AuthSession | None:
    row = (
        db.query(AuthSession)
        .filter(AuthSession.token_hash == hash_session_token(session_token))
        .first()
    )
    if row is None or row.revoked_at is not None:
        return None
    membership = db.get(Membership, row.membership_id)
    user = db.get(User, row.user_id)
    if (
        membership is None
        or user is None
        or membership.status != "active"
        or user.status != "active"
        or membership.user_id != row.user_id
        or membership.organization_id != row.organization_id
    ):
        return None
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(UTC):
        return None
    row.last_used_at = datetime.now(UTC)
    db.flush()
    return row


def hash_session_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def create_session_record(
    db: Session,
    user_id: str,
    organization_id: str,
    membership_id: str,
    provider: str,
) -> tuple[AuthSession, str]:
    token = token_urlsafe(32)
    row = AuthSession(
        id=new_id("sess"),
        token_hash=hash_session_token(token),
        user_id=user_id,
        organization_id=organization_id,
        membership_id=membership_id,
        provider=provider,
        expires_at=datetime.now(UTC) + timedelta(hours=12),
        last_used_at=datetime.now(UTC),
    )
    db.add(row)
    db.flush()
    return row, token


def _slugify(value: str) -> str:
    return (
        value.lower().replace(" ", "-").replace("_", "-").replace("/", "-").strip("-")
    ) or "organization"


def _get_or_create_user(db: Session, *, email: str, display_name: str, provider: str) -> User:
    user = db.query(User).filter(User.email == email).first()
    if user:
        user.display_name = display_name
        if provider:
            user.auth_provider = provider
        return user
    user = User(
        id=new_id("user"),
        email=email,
        display_name=display_name,
        auth_provider=provider,
        status="active",
    )
    db.add(user)
    db.flush()
    return user


def _create_membership_row(
    db: Session, organization_id: str, user_id: str, role: str
) -> Membership:
    membership = Membership(
        id=new_id("membership"),
        organization_id=organization_id,
        user_id=user_id,
        role=role,
        status="active",
    )
    db.add(membership)
    db.flush()
    return membership
