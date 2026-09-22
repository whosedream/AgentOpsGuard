from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentops_guard.backend.database import Base, utcnow


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    slug: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_provider: Mapped[str] = mapped_column(String(64), default="dev_stub")
    external_subject: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class Membership(Base):
    __tablename__ = "memberships"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("organizations.id"), index=True
    )
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True, default="")
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id"), index=True)
    organization_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("organizations.id"), index=True
    )
    membership_id: Mapped[str] = mapped_column(String(64), ForeignKey("memberships.id"), index=True)
    provider: Mapped[str] = mapped_column(String(64), default="dev_stub")
    expires_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    last_used_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("organizations.id"), index=True, default=""
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    store_raw_content: Mapped[bool] = mapped_column(Boolean, default=False)
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    policy_fail_mode: Mapped[str] = mapped_column(String(64), default="closed_for_high_risk")
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, default=dict)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), ForeignKey("projects.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(64))
    runtime: Mapped[str | None] = mapped_column(String(128))
    owner: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), ForeignKey("projects.id"), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(128), index=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    user_id: Mapped[str | None] = mapped_column(String(128), index=True)
    input_ref: Mapped[str | None] = mapped_column(String(64))
    output_ref: Mapped[str | None] = mapped_column(String(64))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_labels: Mapped[list] = mapped_column(JSON, default=list)
    total_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)

    events: Mapped[list["TraceEvent"]] = relationship(back_populates="run")


class ContentObject(Base):
    __tablename__ = "content_objects"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    content_hash: Mapped[str] = mapped_column(String(128), index=True)
    content_type: Mapped[str] = mapped_column(String(64), default="text")
    summary: Mapped[str | None] = mapped_column(Text)
    redacted_text: Mapped[str | None] = mapped_column(Text)
    raw_text: Mapped[str | None] = mapped_column(Text)
    object_uri: Mapped[str | None] = mapped_column(String(512))
    labels: Mapped[list] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class TraceEvent(Base):
    __tablename__ = "trace_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("runs.id"), index=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    span_id: Mapped[str] = mapped_column(String(64), index=True)
    parent_span_id: Mapped[str | None] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="completed", index=True)
    actor: Mapped[dict] = mapped_column(JSON, default=dict)
    input_ref: Mapped[str | None] = mapped_column(String(64))
    output_ref: Mapped[str | None] = mapped_column(String(64))
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_labels: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)

    run: Mapped[Run] = relationship(back_populates="events")


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    run_id: Mapped[str | None] = mapped_column(String(64), index=True)
    event_id: Mapped[str | None] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(32), index=True)
    reason_code: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32), default="low", index=True)
    matched_policy: Mapped[str | None] = mapped_column(String(255))
    remediation: Mapped[str | None] = mapped_column(Text)
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    builtin_policy_version: Mapped[str] = mapped_column(String(64), default="legacy")
    policy_pack_revisions: Mapped[list] = mapped_column(JSON, default=list)
    opa_bundle_revision: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    run_id: Mapped[str | None] = mapped_column(String(64), index=True)
    event_id: Mapped[str | None] = mapped_column(String(64), index=True)
    decision_id: Mapped[str | None] = mapped_column(String(64), index=True)
    execution_request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), default="require_approval")
    requester: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    reason_code: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32), default="high", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_labels: Mapped[list] = mapped_column(JSON, default=list)
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    resolved_by: Mapped[str | None] = mapped_column(String(128))
    resolved_reason: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExecutionRequest(Base):
    __tablename__ = "execution_requests"
    __table_args__ = (
        UniqueConstraint("approval_id", name="uq_execution_request_approval"),
        UniqueConstraint(
            "project_id",
            "idempotency_key",
            name="uq_execution_request_idempotency",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    run_id: Mapped[str | None] = mapped_column(String(64), index=True)
    decision_id: Mapped[str] = mapped_column(String(64), index=True)
    approval_id: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[dict] = mapped_column(JSON, default=dict)
    actor_digest: Mapped[str] = mapped_column(String(64), index=True)
    server_id: Mapped[str] = mapped_column(String(64), index=True)
    tool_name: Mapped[str] = mapped_column(String(255), index=True)
    tool_revision_id: Mapped[str] = mapped_column(String(64), index=True)
    tool_revision_digest: Mapped[str] = mapped_column(String(64))
    arguments_digest: Mapped[str] = mapped_column(String(64), index=True)
    intent_ref: Mapped[str | None] = mapped_column(String(64))
    policy_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    policy_snapshot_digest: Mapped[str] = mapped_column(String(64))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_labels: Mapped[list] = mapped_column(JSON, default=list)
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="waiting_approval", index=True)
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    approved_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    claimed_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    result_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    reconciliation_resolution: Mapped[str | None] = mapped_column(String(32))
    reconciliation_evidence_sha256: Mapped[str | None] = mapped_column(String(64))
    reconciled_by: Mapped[str | None] = mapped_column(String(128))
    reconciled_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolExecutionPolicy(Base):
    """Operator-reviewed capability; upstream annotations never grant retries."""

    __tablename__ = "tool_execution_policies"
    tool_id: Mapped[str] = mapped_column(String(384), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    revision_digest: Mapped[str] = mapped_column(String(64))
    queue_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    retry_mode: Mapped[str] = mapped_column(String(32), default="never")
    evidence_sha256: Mapped[str] = mapped_column(String(64))
    receipt_contract: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(128))
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolInvocation(Base):
    __tablename__ = "tool_invocations"
    __table_args__ = (
        UniqueConstraint("project_id", "actor_digest", "request_id", name="uq_tool_invocation_request"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    request_id: Mapped[str] = mapped_column(String(36))
    actor_digest: Mapped[str] = mapped_column(String(64))
    subject: Mapped[dict] = mapped_column(JSON, default=dict)
    payload_digest: Mapped[str] = mapped_column(String(64))
    tool_id: Mapped[str] = mapped_column(String(384))
    revision_digest: Mapped[str | None] = mapped_column(String(64))
    execution_policy_digest: Mapped[str | None] = mapped_column(String(64))
    receipt_binding: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    mode: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    lease_token: Mapped[str | None] = mapped_column(String(36))
    lease_expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[object] = mapped_column(DateTime(timezone=True))
    encrypted_payload: Mapped[str | None] = mapped_column(Text)
    encrypted_result: Mapped[str | None] = mapped_column(Text)
    result_expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    job_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyPack(Base):
    __tablename__ = "policy_packs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    family_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), default="0.1.0")
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    description: Mapped[str | None] = mapped_column(Text)
    rules: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanRule(Base):
    __tablename__ = "scan_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    label: Mapped[str] = mapped_column(String(128), index=True)
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="medium", index=True)
    score: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(32), default="enabled", index=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class RunSuppression(Base):
    __tablename__ = "run_suppressions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    created_by: Mapped[str | None] = mapped_column(String(128))
    expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class RiskEvent(Base):
    __tablename__ = "risk_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    run_id: Mapped[str | None] = mapped_column(String(64), index=True)
    event_id: Mapped[str | None] = mapped_column(String(64), index=True)
    risk_type: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    labels: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(128), index=True)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceCredential(Base):
    __tablename__ = "service_credentials"

    credential_ref: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), ForeignKey("projects.id"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    binding_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    tool: Mapped[str] = mapped_column(String(128), nullable=False)
    origin: Mapped[str] = mapped_column(String(255), nullable=False)
    injection_field: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_scope: Mapped[str] = mapped_column(String(128), nullable=False)
    allowed_actor_ids: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    last_used_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    actor_type: Mapped[str] = mapped_column(String(64), default="api_key")
    actor_id: Mapped[str | None] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource_type: Mapped[str] = mapped_column(String(128), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), index=True)
    before: Mapped[dict | None] = mapped_column(JSON)
    after: Mapped[dict | None] = mapped_column(JSON)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"

    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    entry_hash: Mapped[str] = mapped_column(String(64))
    entry_id: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditCheckpoint(Base):
    __tablename__ = "audit_checkpoints"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    entry_id: Mapped[str] = mapped_column(String(64), index=True)
    entry_hash: Mapped[str] = mapped_column(String(64), index=True)
    checked_entries: Mapped[int] = mapped_column(Integer)
    payload_digest: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    signer: Mapped[str] = mapped_column(String(64))
    key_name: Mapped[str] = mapped_column(String(255))
    key_version: Mapped[int] = mapped_column(Integer)
    signature: Mapped[str] = mapped_column(Text)
    public_key: Mapped[str] = mapped_column("public_key_pem", Text)
    issued_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class McpServer(Base):
    __tablename__ = "mcp_servers"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    transport: Mapped[str] = mapped_column(String(64), nullable=False)
    runtime_provider: Mapped[str] = mapped_column(String(32), default="direct")
    command: Mapped[str | None] = mapped_column(String(512))
    args: Mapped[list] = mapped_column(JSON, default=list)
    url: Mapped[str | None] = mapped_column(String(512))
    trust_level: Mapped[str] = mapped_column(String(64), default="external")
    allowed_agents: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class McpTool(Base):
    __tablename__ = "mcp_tools"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    server_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    input_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    annotations: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_labels: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    current_revision_id: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class McpToolRevision(Base):
    __tablename__ = "mcp_tool_revisions"
    __table_args__ = (
        UniqueConstraint("tool_id", "content_digest", name="uq_mcp_tool_revision_digest"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    tool_id: Mapped[str] = mapped_column(String(128), index=True)
    server_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    content_digest: Mapped[str] = mapped_column(String(64), index=True)
    source_digest: Mapped[str] = mapped_column(String(64))
    server_digest: Mapped[str] = mapped_column(String(64))
    descriptor: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_labels: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), index=True)
    scanner_version: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvalSuite(Base):
    __tablename__ = "eval_suites"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    cases: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvalRun(Base):
    __tablename__ = "eval_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    suite_id: Mapped[str | None] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="completed")
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    results: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReplayRun(Base):
    __tablename__ = "replay_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    source_run_id: Mapped[str] = mapped_column(String(64), index=True)
    mode: Mapped[str] = mapped_column(String(32), default="exact")
    status: Mapped[str] = mapped_column(String(32), default="completed")
    confidence: Mapped[str] = mapped_column(String(32), default="high")
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    diff: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class BackgroundJob(Base):
    __tablename__ = "background_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    rq_job_id: Mapped[str | None] = mapped_column(String(128), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    run_after: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    lease_owner: Mapped[str | None] = mapped_column(String(128), index=True)
    lease_expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), index=True)
    started_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


class OutboxEvent(Base):
    __tablename__ = "outbox_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(64), index=True)
    topic: Mapped[str] = mapped_column(String(128), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), index=True)
    lease_expires_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), index=True)
    delivered_at: Mapped[object | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), default=utcnow)


Index("ix_trace_events_run_parent", TraceEvent.run_id, TraceEvent.parent_span_id)
Index("ix_trace_events_run_type", TraceEvent.run_id, TraceEvent.event_type)
Index("ix_memberships_org_user", Membership.organization_id, Membership.user_id)
Index("ix_sessions_user_org", Session.user_id, Session.organization_id)
