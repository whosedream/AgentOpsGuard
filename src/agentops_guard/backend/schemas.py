from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


def _validate_outbound_secret(value: SecretStr) -> SecretStr:
    raw_value = value.get_secret_value()
    if not raw_value.isascii() or any(
        ord(character) < 33 or ord(character) == 127 for character in raw_value
    ):
        raise ValueError("value must contain printable ASCII characters only")
    return value


EventType = Literal[
    "run_started",
    "model_call",
    "tool_call",
    "mcp_call",
    "handoff",
    "state_change",
    "policy_decision",
    "scanner_result",
    "approval",
    "error",
    "run_completed",
]

RoleType = Literal["admin", "security_reviewer", "developer", "read_only"]


class Actor(BaseModel):
    agent_id: str | None = None
    user_id: str | None = None
    role: str | None = None


class Risk(BaseModel):
    score: float = 0.0
    labels: list[str] = Field(default_factory=list)


class ContentIn(BaseModel):
    text: str | None = None
    content_type: str = "text"
    labels: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    store_raw: bool | None = None


class ContentOut(BaseModel):
    id: str
    content_hash: str
    summary: str | None = None
    redacted_text: str | None = None
    labels: list[str] = Field(default_factory=list)


class RunCreate(BaseModel):
    project_id: str = "default"
    agent_id: str | None = None
    name: str | None = None
    user_id: str | None = None
    input: ContentIn | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RunUpdate(BaseModel):
    status: str | None = None
    output: ContentIn | None = None
    risk: Risk | None = None
    total_cost_usd: float | None = None
    total_tokens: int | None = None
    metadata: dict[str, Any] | None = None


class RunOut(BaseModel):
    id: str
    project_id: str
    agent_id: str | None
    trace_id: str
    name: str | None
    status: str
    user_id: str | None
    input_ref: str | None
    output_ref: str | None
    risk_score: float
    risk_labels: list[str]
    total_cost_usd: float
    total_tokens: int
    metadata: dict[str, Any]
    started_at: datetime | None
    ended_at: datetime | None


class TraceEventIn(BaseModel):
    event_id: str | None = None
    run_id: str
    project_id: str = "default"
    trace_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None
    event_type: EventType
    actor: Actor = Field(default_factory=Actor)
    status: str = "completed"
    input: ContentIn | None = None
    output: ContentIn | None = None
    input_ref: str | None = None
    output_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    risk: Risk = Field(default_factory=Risk)
    started_at: datetime | None = None
    ended_at: datetime | None = None


class EventsIn(BaseModel):
    events: list[TraceEventIn]


class TraceEventOut(BaseModel):
    id: str
    run_id: str
    project_id: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    event_type: str
    status: str
    actor: dict[str, Any]
    input_ref: str | None
    output_ref: str | None
    metadata: dict[str, Any]
    risk_score: float
    risk_labels: list[str]
    started_at: datetime | None
    ended_at: datetime | None
    created_at: datetime


class DagNode(BaseModel):
    id: str
    type: str
    status: str
    label: str
    risk_score: float
    risk_labels: list[str]
    metadata: dict[str, Any]


class DagEdge(BaseModel):
    source: str
    target: str


class RunDag(BaseModel):
    run: RunOut
    nodes: list[DagNode]
    edges: list[DagEdge]


class PolicyContext(BaseModel):
    project_id: str = "default"
    run_id: str | None = None
    event_id: str | None = None
    actor: dict[str, Any] = Field(default_factory=dict)
    tool: dict[str, Any] = Field(default_factory=dict)
    resource: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)
    environment: str = "dev"
    risk_score: float = 0.0
    risk_labels: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyDecisionOut(BaseModel):
    id: str | None = None
    action: str
    reason_code: str
    severity: str = "low"
    matched_policy: str | None = None
    remediation: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    project_id: str = "default"
    run_id: str | None = None
    event_id: str | None = None
    content: str
    content_type: str = "text"
    source: str = "external"
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceSpan(BaseModel):
    label: str
    start: int
    end: int
    snippet: str


class SemanticAssessment(BaseModel):
    status: Literal["ok", "error"]
    mode: Literal["shadow", "enforce"]
    label: Literal["benign", "prompt_injection"] | None = None
    score: float | None = None
    model: str


class ScanResponse(BaseModel):
    risk_score: float
    risk_labels: list[str]
    evidence_spans: list[EvidenceSpan]
    sanitized_content_ref: str | None = None
    sanitized_text: str
    severity: str
    semantic_assessment: SemanticAssessment | None = Field(default=None, exclude=True)


class OrganizationCreate(BaseModel):
    name: str
    slug: str | None = None
    initial_admin: dict[str, str]
    initial_project: dict[str, str] | None = None


class OrganizationOut(BaseModel):
    id: str
    slug: str
    name: str
    created_at: datetime
    initial_project_id: str | None = None


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str
    auth_provider: str
    status: str
    created_at: datetime


class MembershipCreate(BaseModel):
    email: str
    display_name: str
    role: RoleType


class MembershipUpdate(BaseModel):
    role: RoleType | None = None
    status: Literal["active", "disabled"] | None = None


class MembershipOut(BaseModel):
    id: str
    organization_id: str
    user_id: str
    role: RoleType
    status: str
    created_at: datetime
    user: UserOut


class DevLoginRequest(BaseModel):
    email: str
    display_name: str
    role: RoleType = "admin"
    organization_id: str | None = None
    organization_name: str | None = None


class DevLoginOut(BaseModel):
    session_id: str
    user: UserOut
    membership: MembershipOut
    project_id: str | None = None


class ProjectCreate(BaseModel):
    id: str
    organization_id: str | None = None
    name: str | None = None
    store_raw_content: bool = False
    retention_days: int = 30
    policy_fail_mode: str = "closed_for_high_risk"
    status: Literal["active", "paused", "archived"] = "active"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProjectUpdate(BaseModel):
    name: str | None = None
    store_raw_content: bool | None = None
    retention_days: int | None = None
    policy_fail_mode: str | None = None
    status: Literal["active", "paused", "archived"] | None = None
    metadata: dict[str, Any] | None = None


class ProjectOut(BaseModel):
    id: str
    organization_id: str
    name: str
    store_raw_content: bool
    retention_days: int
    policy_fail_mode: str
    status: str
    metadata: dict[str, Any]
    created_at: datetime


class ApprovalRequestCreate(BaseModel):
    project_id: str = "default"
    run_id: str | None = None
    event_id: str | None = None
    decision_id: str | None = None
    action: str = "require_approval"
    requester: dict[str, Any] = Field(default_factory=dict)
    reason_code: str = "manual_review"
    severity: str = "high"
    risk_score: float = 0.0
    risk_labels: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None


class ApprovalReview(BaseModel):
    status: Literal["approved", "denied", "expired", "cancelled"]
    resolved_by: str | None = None
    resolved_reason: str | None = None


class ApprovalRequestOut(BaseModel):
    id: str
    project_id: str
    run_id: str | None
    event_id: str | None
    decision_id: str | None
    action: str
    requester: dict[str, Any]
    status: str
    reason_code: str
    severity: str
    risk_score: float
    risk_labels: list[str]
    context: dict[str, Any]
    resolved_by: str | None
    resolved_reason: str | None
    expires_at: datetime | None
    resolved_at: datetime | None
    created_at: datetime


class PolicyPackCreate(BaseModel):
    project_id: str = "default"
    name: str
    version: str = "0.1.0"
    status: Literal["active", "disabled"] = "active"
    description: str | None = None
    rules: list[dict[str, Any]] = Field(default_factory=list)


class PolicyPackUpdate(BaseModel):
    name: str | None = None
    version: str | None = None
    status: Literal["active", "disabled"] | None = None
    description: str | None = None
    rules: list[dict[str, Any]] | None = None


class PolicyPackOut(BaseModel):
    id: str
    family_id: str
    project_id: str
    name: str
    version: str
    status: str
    description: str | None
    rules: list[dict[str, Any]]
    created_at: datetime


class PolicyPackVersionCreate(BaseModel):
    version: str
    status: Literal["active", "disabled"] = "active"
    description: str | None = None
    rules: list[dict[str, Any]] = Field(default_factory=list)


class ScanRuleCreate(BaseModel):
    project_id: str = "default"
    label: str
    pattern: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    score: float = 0.5
    status: Literal["enabled", "disabled"] = "enabled"
    description: str | None = None


class ScanRuleUpdate(BaseModel):
    label: str | None = None
    pattern: str | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    score: float | None = None
    status: Literal["enabled", "disabled"] | None = None
    description: str | None = None


class ScanRuleOut(BaseModel):
    id: str
    project_id: str
    label: str
    pattern: str
    severity: str
    score: float
    status: str
    description: str | None
    created_at: datetime


class RunSuppressionCreate(BaseModel):
    project_id: str = "default"
    reason: str
    created_by: str | None = None
    expires_at: datetime | None = None


class RunSuppressionUpdate(BaseModel):
    status: Literal["active", "resolved", "expired"]
    reason: str | None = None


class RunSuppressionOut(BaseModel):
    id: str
    project_id: str
    run_id: str
    reason: str
    status: str
    created_by: str | None
    expires_at: datetime | None
    created_at: datetime


class ControlPlaneStatusOut(BaseModel):
    project: ProjectOut
    pending_approvals: int
    active_policy_packs: int
    enabled_scan_rules: int
    active_suppressions: int
    run_statuses: dict[str, int]


class RiskEventOut(BaseModel):
    id: str
    project_id: str
    event_id: str | None
    run_id: str | None
    risk_type: str
    severity: str
    score: float
    labels: list[str]
    evidence: list[dict[str, Any]]
    description: str | None
    created_at: datetime


class ReplayCreate(BaseModel):
    project_id: str = "default"
    source_run_id: str
    mode: Literal["exact", "mock", "policy"] = "exact"


class ReplayOut(BaseModel):
    id: str
    project_id: str
    source_run_id: str
    mode: str
    status: str
    confidence: str
    summary: dict[str, Any]
    diff: list[dict[str, Any]]
    created_at: datetime


class EvalSuiteCreate(BaseModel):
    project_id: str = "default"
    name: str
    description: str | None = None
    cases: list[dict[str, Any]] = Field(default_factory=list)


class EvalSuiteOut(BaseModel):
    id: str
    project_id: str
    name: str
    description: str | None
    cases: list[dict[str, Any]]
    created_at: datetime


class EvalRunCreate(BaseModel):
    project_id: str = "default"
    suite_id: str | None = None
    cases: list[dict[str, Any]] | None = None


class EvalRunOut(BaseModel):
    id: str
    project_id: str
    suite_id: str | None
    status: str
    passed: bool
    summary: dict[str, Any]
    results: list[dict[str, Any]]
    created_at: datetime


class McpServerConfig(BaseModel):
    id: str | None = None
    project_id: str = "default"
    name: str
    transport: Literal["stdio", "streamable_http", "legacy_http"]
    runtime_provider: Literal["direct", "toolhive"] = "direct"
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    trust_level: Literal["internal", "external", "sandboxed"] = "external"
    allowed_agents: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_runtime_provider(self) -> "McpServerConfig":
        if self.runtime_provider == "toolhive" and (
            self.transport != "streamable_http"
            or not self.url
            or self.trust_level != "sandboxed"
        ):
            raise ValueError(
                "ToolHive servers require streamable_http, a URL, and sandboxed trust"
            )
        return self


class McpServerOut(McpServerConfig):
    id: str
    status: str
    created_at: datetime


class McpToolOut(BaseModel):
    id: str
    project_id: str
    server_id: str
    name: str
    description: str | None
    input_schema: dict[str, Any]
    annotations: dict[str, Any]
    risk_score: float
    risk_labels: list[str]
    status: str
    created_at: datetime


class McpServerUpdate(BaseModel):
    name: str | None = None
    transport: Literal["stdio", "streamable_http", "legacy_http"] | None = None
    runtime_provider: Literal["direct", "toolhive"] | None = None
    command: str | None = None
    args: list[str] | None = None
    url: str | None = None
    trust_level: Literal["internal", "external", "sandboxed"] | None = None
    allowed_agents: list[str] | None = None
    status: Literal["active", "quarantined", "disabled", "error"] | None = None


class DeleteResponse(BaseModel):
    status: str
    id: str


class PageOut(BaseModel):
    items: list[Any]
    next_cursor: str | None = None


class ApiKeyCreate(BaseModel):
    project_id: str = "default"
    name: str
    scopes: list[str] = Field(default_factory=lambda: ["admin:*"])
    expires_at: datetime | None = None


class ApiKeyOut(BaseModel):
    id: str
    project_id: str
    name: str
    scopes: list[str]
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime


class ApiKeyCreateOut(ApiKeyOut):
    token: str


class DeepSeekCredentialCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str = "default"
    name: str = Field(min_length=1, max_length=255)
    secret: SecretStr = Field(min_length=1)
    allowed_actor_ids: list[str] = Field(default_factory=list)

    _printable_secret = field_validator("secret")(_validate_outbound_secret)


class DeepSeekCredentialRotate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str = "default"
    secret: SecretStr = Field(min_length=1)

    _printable_secret = field_validator("secret")(_validate_outbound_secret)


class CredentialRefOut(BaseModel):
    credential_ref: str


class DeepSeekMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str


class DeepSeekChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str = "default"
    credential_ref: str
    model: str = Field(min_length=1, max_length=128)
    messages: list[DeepSeekMessage] = Field(min_length=1)
    max_tokens: int | None = Field(default=None, ge=1)


class AuditLogOut(BaseModel):
    id: str
    project_id: str
    actor_type: str
    actor_id: str | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class MembershipSummaryOut(BaseModel):
    id: str
    organization_id: str
    role: RoleType
    status: str


class AuthContextUserOut(BaseModel):
    id: str
    email: str
    display_name: str


class AuthContextOut(BaseModel):
    kind: str
    user: AuthContextUserOut | None = None
    organization_id: str | None = None
    memberships: list[MembershipSummaryOut] = Field(default_factory=list)
    active_membership_id: str | None = None
    active_role: str | None = None
    project_id: str | None = None
    scopes: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    is_operator: bool = False


class JobOut(BaseModel):
    id: str
    project_id: str
    kind: str
    status: str
    rq_job_id: str | None = None
    payload: dict[str, Any]
    result: dict[str, Any] | None = None
    error: str | None = None
    attempts: int
    run_after: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class ComponentStatus(BaseModel):
    status: str
    detail: str | None = None
    url: str | None = None


class SystemCounts(BaseModel):
    runs: int
    risks: int
    eval_suites: int
    eval_runs: int
    replays: int
    mcp_servers: int
    mcp_tools: int
    pending_approvals: int = 0
    policy_packs: int = 0
    scan_rules: int = 0
    active_suppressions: int = 0


class SystemConfig(BaseModel):
    project_id: str = "default"
    store_raw_content: bool
    policy_fail_mode: str
    retention_days: int | None = None
    status: str | None = None


class SystemStatusOut(BaseModel):
    api: ComponentStatus
    database: ComponentStatus
    gateway: ComponentStatus
    counts: SystemCounts
    config: SystemConfig
