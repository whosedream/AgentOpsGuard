"""Controlled PostgreSQL race probe; source arrives from the trusted local controller.

Run in the disposable eval-driver via stdin. No credentials or exception text
are returned, and no application module is replaced on disk or in the gateway.
"""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import sys
from threading import Barrier, local
from uuid import uuid4

from sqlalchemy import event, text
from sqlalchemy.exc import IntegrityError

from agentops_guard.backend.database import SessionLocal, engine
from agentops_guard.backend.models import McpServer, McpTool, McpToolRevision
from agentops_guard.backend.services.projects import ensure_project


def main():
    payload = json.load(sys.stdin)
    namespace = {"__name__": "controlled_revision_candidate"}
    exec(compile(payload["source"], "controlled_revision_candidate.py", "exec"), namespace)
    record = namespace["record_tool_revision"]
    count = 8
    run = "revision_race_" + uuid4().hex
    server_id, tool_id = run + "_server", run + "_tool"
    with engine.begin() as connection:
        connection.execute(text("""CREATE TABLE IF NOT EXISTS eval_revision_markers
            (run_id text NOT NULL, worker integer NOT NULL, PRIMARY KEY(run_id,worker))"""))
    with SessionLocal() as db:
        ensure_project(db, run)
        db.add(McpServer(id=server_id, project_id=run, name="race probe", transport="stdio", status="active"))
        db.add(McpTool(id=tool_id, project_id=run, server_id=server_id, name="read_status",
                       description="controlled read", input_schema={}, annotations={"readOnlyHint": True},
                       risk_score=0, risk_labels=[], status="active"))
        db.commit()
    barrier, seen = Barrier(count), local()

    def after_select(_connection, _cursor, statement, _parameters, _context, _many):
        if "FROM mcp_tool_revisions" in statement and not getattr(seen, "selected", False):
            seen.selected = True
            barrier.wait(timeout=15)

    event.listen(engine, "after_cursor_execute", after_select)

    def create(index):
        with SessionLocal() as db:
            server, tool = db.get(McpServer, server_id), db.get(McpTool, tool_id)
            # This outer transaction must survive duplicate-insert handling.
            db.execute(text("INSERT INTO eval_revision_markers VALUES (:run,:worker)"), {"run": run, "worker": index})
            try:
                revision_id = record(db, server, tool).id
                db.commit()
                return {"revision_id": revision_id, "ok": True}
            except IntegrityError:
                db.rollback()
                return {"ok": False, "error": "IntegrityError"}

    try:
        with ThreadPoolExecutor(max_workers=count) as executor:
            results = list(executor.map(create, range(count)))
    finally:
        event.remove(engine, "after_cursor_execute", after_select)
    with SessionLocal() as db:
        revisions = db.query(McpToolRevision).filter_by(tool_id=tool_id).count()
        markers = db.execute(text("SELECT count(*) FROM eval_revision_markers WHERE run_id=:run"), {"run": run}).scalar_one()
    success = sum(row["ok"] for row in results)
    print(json.dumps({"scope": "real_postgresql_forced_first_registration_race", "workers": count,
        "succeeded": success, "integrity_errors": count-success, "revision_rows": revisions,
        "distinct_returned_revisions": len({row["revision_id"] for row in results if row["ok"]}),
        "outer_transaction_markers": markers, "passed": success == count and revisions == 1 and markers == count,
        "source_sha256": sha256(payload["source"].encode()).hexdigest(), "raw_credentials_or_errors": False}))


if __name__ == "__main__":
    main()
