from agentops_guard.backend.models import (
    ApiKey,
    AuditLog,
    BackgroundJob,
    EvalRun,
    McpServer,
    McpTool,
    ReplayRun,
    RiskEvent,
    TraceEvent,
)
from agentops_guard.backend.schemas import (
    ApiKeyOut,
    AuditLogOut,
    EvalRunOut,
    JobOut,
    McpServerOut,
    McpToolOut,
    ReplayOut,
    RiskEventOut,
    TraceEventOut,
)


def replay_out(row: ReplayRun) -> ReplayOut:
    return ReplayOut(
        id=row.id,
        project_id=row.project_id,
        source_run_id=row.source_run_id,
        mode=row.mode,
        status=row.status,
        confidence=row.confidence,
        summary=row.summary or {},
        diff=row.diff or [],
        created_at=row.created_at,
    )


def eval_run_out(row: EvalRun) -> EvalRunOut:
    return EvalRunOut(
        id=row.id,
        project_id=row.project_id,
        suite_id=row.suite_id,
        status=row.status,
        passed=row.passed,
        summary=row.summary or {},
        results=row.results or [],
        created_at=row.created_at,
    )


def event_out(event: TraceEvent) -> TraceEventOut:
    return TraceEventOut(
        id=event.id,
        run_id=event.run_id,
        project_id=event.project_id,
        trace_id=event.trace_id,
        span_id=event.span_id,
        parent_span_id=event.parent_span_id,
        event_type=event.event_type,
        status=event.status,
        actor=event.actor or {},
        input_ref=event.input_ref,
        output_ref=event.output_ref,
        metadata=event.metadata_json or {},
        risk_score=event.risk_score,
        risk_labels=event.risk_labels or [],
        started_at=event.started_at,
        ended_at=event.ended_at,
        created_at=event.created_at,
    )


def risk_out(risk: RiskEvent) -> RiskEventOut:
    return RiskEventOut(
        id=risk.id,
        project_id=risk.project_id,
        run_id=risk.run_id,
        event_id=risk.event_id,
        risk_type=risk.risk_type,
        severity=risk.severity,
        score=risk.score,
        labels=risk.labels or [],
        evidence=risk.evidence or [],
        description=risk.description,
        created_at=risk.created_at,
    )


def mcp_server_out(row: McpServer) -> McpServerOut:
    return McpServerOut(
        id=row.id,
        project_id=row.project_id,
        name=row.name,
        transport=row.transport,
        runtime_provider=row.runtime_provider,
        command=row.command,
        args=row.args or [],
        url=row.url,
        trust_level=row.trust_level,
        allowed_agents=row.allowed_agents or [],
        status=row.status,
        created_at=row.created_at,
    )


def mcp_tool_out(row: McpTool) -> McpToolOut:
    return McpToolOut(
        id=row.id,
        project_id=row.project_id,
        server_id=row.server_id,
        name=row.name,
        description=row.description,
        input_schema=row.input_schema or {},
        annotations=row.annotations or {},
        risk_score=row.risk_score,
        risk_labels=row.risk_labels or [],
        status=row.status,
        current_revision_id=row.current_revision_id,
        created_at=row.created_at,
    )


def api_key_out(row: ApiKey) -> ApiKeyOut:
    return ApiKeyOut(
        id=row.id,
        project_id=row.project_id,
        name=row.name,
        agent_id=row.agent_id,
        scopes=row.scopes or [],
        expires_at=row.expires_at,
        last_used_at=row.last_used_at,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
    )


def audit_out(row: AuditLog) -> AuditLogOut:
    return AuditLogOut(
        id=row.id,
        project_id=row.project_id,
        actor_type=row.actor_type,
        actor_id=row.actor_id,
        action=row.action,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        before=row.before,
        after=row.after,
        metadata=row.metadata_json or {},
        previous_hash=row.previous_hash,
        entry_hash=row.entry_hash,
        created_at=row.created_at,
    )


def job_out(row: BackgroundJob) -> JobOut:
    return JobOut(
        id=row.id,
        project_id=row.project_id,
        kind=row.kind,
        status=row.status,
        rq_job_id=row.rq_job_id,
        payload=row.payload or {},
        result=row.result,
        error=row.error,
        attempts=row.attempts,
        run_after=row.run_after,
        started_at=row.started_at,
        finished_at=row.finished_at,
        created_at=row.created_at,
    )
