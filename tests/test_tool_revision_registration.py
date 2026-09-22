from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import NoResultFound
import pytest

from agentops_guard.backend.database import Base
from agentops_guard.backend.models import McpServer, McpTool, McpToolRevision
from agentops_guard.backend.services.mcp_tool_revisions import record_tool_revision


@pytest.fixture
def revision_database():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(McpServer(id="server", project_id="project", name="server", transport="stdio", status="active"))
        db.add(McpTool(id="tool", project_id="project", server_id="server", name="read_status",
                       description="read", input_schema={}, annotations={}, risk_score=0,
                       risk_labels=[], status="active"))
        db.commit()
    yield engine
    engine.dispose()


def test_tool_revision_insert_does_not_commit_the_callers_sqlite_transaction(revision_database):
    with Session(revision_database) as db:
        record_tool_revision(db, db.get(McpServer, "server"), db.get(McpTool, "tool"))
        db.rollback()
    with Session(revision_database) as db:
        assert db.query(McpToolRevision).count() == 0
        assert db.get(McpTool, "tool").current_revision_id is None


def test_duplicate_revision_insert_reuses_immutable_row_without_losing_outer_work(revision_database, monkeypatch):
    with Session(revision_database, autoflush=False) as db:
        server, tool = db.get(McpServer, "server"), db.get(McpTool, "tool")
        first = record_tool_revision(db, server, tool)
        db.commit()
        revision_id = first.id
        db.add(McpServer(id="outer-work", project_id="project", name="outer-work", transport="stdio", status="active"))
        query = db.query(McpToolRevision)
        # Simulate a peer committing the row after this caller's first SELECT.
        query.one_or_none = lambda: None
        real_filter = query.filter

        def empty_first_read(*args):
            filtered = real_filter(*args)
            filtered.one_or_none = lambda: None
            return filtered

        monkeypatch.setattr(query, "filter", empty_first_read)
        monkeypatch.setattr(db, "query", lambda _model: query)
        assert record_tool_revision(db, server, tool).id == revision_id
        db.commit()
    with Session(revision_database) as db:
        assert db.query(McpToolRevision).count() == 1
        assert db.get(McpServer, "outer-work") is not None
        assert db.get(McpToolRevision, revision_id).descriptor["description"] == "read"


def test_revision_id_conflict_cannot_reuse_a_different_tools_revision(revision_database):
    with Session(revision_database) as db:
        server, tool = db.get(McpServer, "server"), db.get(McpTool, "tool")
        record_tool_revision(db, server, tool)
        db.commit()
        other = McpTool(id="other-tool", project_id=tool.project_id, server_id=tool.server_id,
                        name=tool.name, description=tool.description, input_schema=tool.input_schema,
                        annotations=tool.annotations, risk_score=tool.risk_score,
                        risk_labels=tool.risk_labels, status=tool.status)
        with pytest.raises(NoResultFound):
            record_tool_revision(db, server, other)
        db.rollback()
