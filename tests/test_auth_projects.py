from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from agentops_guard.backend.auth import require_api_key
from agentops_guard.backend.database import Base
from agentops_guard.backend.models import Project
from agentops_guard.backend.services.projects import ensure_project


def test_auth_rejects_invalid_api_key():
    try:
        require_api_key(x_agentops_api_key="bad-key")
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("invalid key should be rejected")


def test_ensure_project_creates_once():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        ensure_project(session, "demo")
        ensure_project(session, "demo")
        assert session.query(Project).filter(Project.id == "demo").count() == 1
