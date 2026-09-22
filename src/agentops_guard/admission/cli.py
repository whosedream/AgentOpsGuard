"""Operator CLI. Secret values never appear in arguments or normal output."""
import os
from pathlib import Path
import secrets
from hashlib import sha256
import time
from datetime import timedelta

import typer
import uvicorn

from agentops_guard.admission.store import AdmissionSettings, Grant, Store, now
from agentops_guard.backend.database_resilience import database_http_boundary

app = typer.Typer(pretty_exceptions_enable=False)


@app.command()
def migrate():
    """Create the separate v1 admission schema; never use the business DSN."""
    store = Store(AdmissionSettings())
    try:
        store.initialize()
    finally:
        store.engine.dispose()


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8003):
    """Expose behind a trusted TLS proxy; access logs deliberately disabled."""
    uvicorn.run("agentops_guard.admission.app:create_app", factory=True,
                host=host, port=port, access_log=False)


def private_token_file(path: Path):
    # Exclusive creation: never overwrite an existing credential or follow a symlink.
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")


@app.command("grant")
def create_grant(key_id: str = typer.Option(...), tool_id: list[str] = typer.Option(...),
                 token_file: Path = typer.Option(...),
                 lifetime_seconds: int = 3600):
    """Bind reviewed tools to an existing business key ID, NOT its secret value."""
    from agentops_guard.admission.importer import provision
    from agentops_guard.backend.database import SessionLocal

    store = Store(AdmissionSettings())
    try:
        with private_token_file(token_file) as output, database_http_boundary(), SessionLocal() as db:
            grant_id, token = provision(store, db, key_id=key_id, tool_ids=tool_id,
                                         lifetime_seconds=lifetime_seconds)
            output.write(token)
            output.flush()
            os.fsync(output.fileno())
        typer.echo(f"Created {grant_id}; credential written to the private file")
    finally:
        store.engine.dispose()


@app.command("revoke")
def revoke(grant_id: str):
    """Stop NEW deposits and status access. This does not cancel accepted work."""
    store = Store(AdmissionSettings())
    try:
        with database_http_boundary(), store.sessions() as db:
            grant = db.query(Grant).filter_by(id=grant_id).with_for_update().one()
            grant.revoked_at = now()
            db.commit()
        typer.echo("Admission grant revoked; accepted work is not cancelled")
    finally:
        store.engine.dispose()


@app.command("rotate")
def rotate(grant_id: str, token_file: Path, lifetime_seconds: int = 3600):
    """Issue a new deposit credential, keeping the same identity and tool review."""
    if not 60 <= lifetime_seconds <= 86400:
        raise typer.BadParameter("Lifetime must be 60..86400 seconds")
    store = Store(AdmissionSettings())
    try:
        with private_token_file(token_file) as output, database_http_boundary(), store.sessions() as db:
            grant = db.query(Grant).filter_by(id=grant_id).with_for_update().one()
            token = "admission_" + secrets.token_urlsafe(32)
            grant.token_hash = sha256(token.encode()).hexdigest()
            grant.expires_at, grant.revoked_at = now() + timedelta(seconds=lifetime_seconds), None
            db.commit()
            output.write(token)
            output.flush()
            os.fsync(output.fileno())
        typer.echo("Credential rotated; no tool permissions changed")
    finally:
        store.engine.dispose()


@app.command("import")
def import_loop(once: bool = False):
    """Lease local entries and idempotently import to the existing job/outbox."""
    from agentops_guard.admission.importer import handoff
    from agentops_guard.backend.database import SessionLocal

    store = Store(AdmissionSettings())
    try:
        while True:
            # Unexpected failures exit visibly; a supervisor may restart. Expired
            # leases let another importer take over, without an action replay.
            with database_http_boundary():
                claim = store.claim()
                if claim:
                    handoff(store, SessionLocal, claim)
            if once:
                return
            time.sleep(.2 if claim else 1)
    finally:
        store.engine.dispose()


if __name__ == "__main__":
    app()
