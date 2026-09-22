"""Single durable source for acceptance and status. No business DB on HTTP paths."""
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import re
import secrets
from types import SimpleNamespace
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi import HTTPException
import psycopg
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, UniqueConstraint, exc, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from agentops_guard.backend.database_resilience import create_database_engine


def now():
    return datetime.now(UTC)


def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return sha256(canonical(value).encode()).hexdigest()


class AdmissionSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTOPS_ADMISSION_", hide_input_in_errors=True)
    enabled: bool = False
    database_url: SecretStr
    encryption_key: SecretStr
    allow_test_sqlite: bool = False
    max_pending_per_grant: int = Field(default=1000, ge=1, le=10000)
    max_records_per_grant: int = Field(default=20000, ge=1, le=100000)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    lease_seconds: int = Field(default=30, ge=5, le=120)
    request_timeout_seconds: float = Field(default=8, ge=1, le=45)

    @model_validator(mode="after")
    def supported_storage(self):
        backend = make_url(self.database_url.get_secret_value()).get_backend_name()
        if backend != "postgresql" and not (backend == "sqlite" and self.allow_test_sqlite):
            raise ValueError("Independent PostgreSQL is required outside tests")
        Fernet(self.encryption_key.get_secret_value().encode())
        return self


class Base(DeclarativeBase):
    pass


class Grant(Base):
    __tablename__ = "admission_grants_v1"
    __table_args__ = (UniqueConstraint("project_id", "actor_digest"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    actor_digest: Mapped[str] = mapped_column(String(64))
    subject: Mapped[dict] = mapped_column(JSON)
    tools: Mapped[dict] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Entry(Base):
    __tablename__ = "admission_entries_v1"
    __table_args__ = (UniqueConstraint("project_id", "actor_digest", "request_id"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    grant_id: Mapped[str] = mapped_column(ForeignKey(Grant.id), index=True)
    project_id: Mapped[str] = mapped_column(String(64))
    actor_digest: Mapped[str] = mapped_column(String(64))
    request_id: Mapped[str] = mapped_column(String(36))
    tool_id: Mapped[str] = mapped_column(String(384))
    payload_digest: Mapped[str] = mapped_column(String(64))
    encrypted_payload: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(32), default="accepted", index=True)
    reason: Mapped[str | None] = mapped_column(String(64))
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    next_check_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    lease_token: Mapped[str | None] = mapped_column(String(64))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    business_id: Mapped[str | None] = mapped_column(String(64))
    business_state: Mapped[str | None] = mapped_column(String(32))
    business_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Store:
    def __init__(self, settings: AdmissionSettings, *, isolate_queries=False):
        self.settings = settings
        self.cipher = Fernet(settings.encryption_key.get_secret_value().encode())
        database = SimpleNamespace(
            database_url=settings.database_url.get_secret_value(),
            database_connect_timeout_seconds=2, database_pool_timeout_seconds=1,
            database_statement_timeout_ms=3000, database_lock_timeout_ms=1000,
            database_tcp_user_timeout_ms=3000)
        split = isolate_queries and make_url(database.database_url).get_backend_name() == "postgresql"
        # Preserve the former per-HTTP-process ceiling of 15 connections:
        # deposits may use 12, leaving 3 for fresh authenticated status reads.
        self.engine = create_database_engine(database, **({"pool_size": 12, "max_overflow": 0} if split else {}))
        self.query_engine = (create_database_engine(database, pool_size=3, max_overflow=0)
                             if split else self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)

    def dispose(self):
        self.engine.dispose()
        if self.query_engine is not self.engine:
            self.query_engine.dispose()

    def initialize(self):
        # Operator migration command only; API startup/readiness never mutates schema.
        Base.metadata.create_all(self.engine)

    def authenticate(self, db, token, *, lock=False):
        if not token or len(token) > 256:
            raise HTTPException(401, "Admission credential required")
        query = select(Grant).where(Grant.token_hash == sha256(token.encode()).hexdigest())
        if lock:
            query = query.with_for_update()
        grant = db.scalar(query)
        if grant is None or grant.revoked_at is not None or utc(grant.expires_at) <= now():
            raise HTTPException(401, "Admission credential is invalid or revoked")
        return grant

    def confirm_commit(self, db, before_commit):
        if before_commit is not None:
            before_commit()
        connection = db.connection()
        if connection.dialect.name != "postgresql":
            db.commit()
            return
        driver = connection.connection.driver_connection
        warned = False

        def notice(diagnostic):
            nonlocal warned
            # PostgreSQL can end a cancelled synchronous-replication wait with
            # WARNING, not an exception. Never retain potentially sensitive
            # notice text or call such a COMMIT durable confirmation.
            if diagnostic.severity_nonlocalized == "WARNING":
                warned = True

        driver.add_notice_handler(notice)
        try:
            # Do not allow a connection-level message filter to hide the
            # synchronous-replication cancellation warning from this guard.
            db.execute(text("SET LOCAL client_min_messages = 'warning'"))
            db.commit()
        finally:
            driver.remove_notice_handler(notice)
        if warned:
            raise exc.OperationalError(None, None,
                psycopg.OperationalError("Admission commit confirmation was not reliable"))

    def accept(self, db, token, payload, *, before_commit=None):
        from agentops_guard.backend.services.content import detect_secret_labels

        grant = self.authenticate(db, token, lock=True)
        tool_id = f"{payload['serverId']}:{payload['name']}"
        if tool_id not in grant.tools:
            raise HTTPException(403, "Tool is outside the admission grant")
        raw = canonical(payload)
        if len(raw.encode()) > 65536:
            raise HTTPException(413, "Admission payload exceeds 64 KiB")
        if (set(detect_secret_labels(raw)) - {"email", "phone"}
                or re.search(r"\b(?:admission_|ag_)[A-Za-z0-9_-]{32,}", raw)):
            raise HTTPException(400, "Use credential references, not secret values")
        existing = db.scalar(select(Entry).where(Entry.project_id == grant.project_id,
            Entry.actor_digest == grant.actor_digest, Entry.request_id == payload["requestId"]))
        if existing is not None:
            if existing.payload_digest != digest(payload):
                raise HTTPException(409, "requestId is bound to different input")
            # Visibility alone does not prove synchronous replication: a prior
            # COMMIT may have lost its reply or its replication wait. Confirm a
            # fresh write before acknowledging the same record, without changing
            # its payload, state, TTL or creating another executable task.
            db.execute(update(Entry).where(Entry.id == existing.id)
                       .values(payload_digest=Entry.payload_digest))
            self.confirm_commit(db, before_commit)
            return existing
        # One active grant per actor is enforced by provisioning. Grant row lock
        # serializes both duplicate submissions and capacity checks across replicas.
        rows = db.query(Entry).filter_by(grant_id=grant.id)
        if (rows.count() >= self.settings.max_records_per_grant
                or rows.filter(Entry.state.in_(["accepted", "imported"])).count()
                >= self.settings.max_pending_per_grant):
            raise HTTPException(429, "Admission capacity exhausted")
        entry_id = "adm_" + uuid4().hex
        encrypted = self.cipher.encrypt(canonical({"id": entry_id, "grant": grant.id,
            "project": grant.project_id, "actor": grant.actor_digest, "payload": payload}).encode()).decode()
        row = Entry(id=entry_id, grant_id=grant.id, project_id=grant.project_id,
            actor_digest=grant.actor_digest, request_id=payload["requestId"], tool_id=tool_id,
            payload_digest=digest(payload), encrypted_payload=encrypted,
            expires_at=now() + timedelta(seconds=self.settings.ttl_seconds))
        db.add(row)
        self.confirm_commit(db, before_commit)  # No 202 before durable confirmation.
        return row

    def lookup(self, db, token, request_id):
        grant = self.authenticate(db, token)
        row = db.scalar(select(Entry).where(Entry.project_id == grant.project_id,
            Entry.actor_digest == grant.actor_digest, Entry.request_id == request_id))
        if row is None or row.tool_id not in grant.tools:
            raise HTTPException(404, "Admission not found")
        return row

    def claim(self):
        with self.sessions() as db:
            row = db.scalar(select(Entry).where(Entry.state.in_(["accepted", "imported"]),
                Entry.next_check_at <= now(),
                (Entry.lease_until.is_(None)) | (Entry.lease_until < now()))
                .order_by(Entry.next_check_at, Entry.id).with_for_update(skip_locked=True).limit(1))
            if row is None:
                return None
            row.lease_token = secrets.token_hex(24)
            row.lease_until = now() + timedelta(seconds=self.settings.lease_seconds)
            db.commit()
            return row.id, row.lease_token

    def finish(self, claim, **values):
        with self.sessions() as db:
            changed = db.query(Entry).filter(Entry.id == claim[0], Entry.lease_token == claim[1],
                Entry.lease_until > now()).update({**values, "lease_until": None, "lease_token": None,
                    "next_check_at": now() + timedelta(seconds=2)}, synchronize_session=False)
            db.commit()
            return bool(changed)


def public_status(row, *, durability_confirmed=False):
    # GET only observes a record; a fresh POST commit confirms durability under
    # the configured storage policy. Neither is a live observation of execution.
    # Missing notifications never imply not_found or authorize tool replay.
    return {"requestId": row.request_id, "accepted": True, "state": row.state,
        "durabilityConfirmed": durability_confirmed,
        "acceptanceEvidence": "commit_confirmed" if durability_confirmed else "record_observed",
        "acceptedAt": utc(row.accepted_at).isoformat(), "expiresAt": utc(row.expires_at).isoformat(),
        "reason": row.reason, "businessState": row.business_state,
        "businessObservedAt": utc(row.business_observed_at).isoformat() if row.business_observed_at else None,
        "businessStatusIsSnapshot": True, "resultIncluded": False, "clientMayReplay": False}
