from sqlalchemy.orm import Session

from agentops_guard.backend.models import ReplayRun, Run, TraceEvent
from agentops_guard.backend.schemas import ReplayCreate, ReplayOut
from agentops_guard.backend.services.content import new_id


def create_replay(db: Session, request: ReplayCreate) -> ReplayOut:
    run = db.get(Run, request.source_run_id)
    events = (
        db.query(TraceEvent)
        .filter(TraceEvent.run_id == request.source_run_id)
        .order_by(TraceEvent.created_at.asc())
        .all()
    )
    missing_content = sum(1 for event in events if not event.input_ref and not event.output_ref)
    confidence = "high" if missing_content == 0 else "medium"
    event_counts: dict[str, int] = {}
    for event in events:
        event_counts[event.event_type] = event_counts.get(event.event_type, 0) + 1
    blocked = [event for event in events if event.status in {"blocked", "failed"} or event.risk_score >= 0.7]
    summary = {
        "source_status": run.status if run else "unknown",
        "mode": request.mode,
        "event_count": len(events),
        "event_counts": event_counts,
        "blocked_or_high_risk_events": len(blocked),
        "likely_failure_reason": _failure_reason(blocked, event_counts),
        "suggestions": _suggestions(blocked, event_counts),
    }
    diff = [
        {
            "event_id": event.id,
            "event_type": event.event_type,
            "status": event.status,
            "risk_score": event.risk_score,
            "risk_labels": event.risk_labels,
        }
        for event in blocked
    ]
    replay = ReplayRun(
        id=new_id("replay"),
        project_id=request.project_id,
        source_run_id=request.source_run_id,
        mode=request.mode,
        status="completed",
        confidence=confidence,
        summary=summary,
        diff=diff,
    )
    db.add(replay)
    db.flush()
    return ReplayOut(
        id=replay.id,
        project_id=replay.project_id,
        source_run_id=replay.source_run_id,
        mode=replay.mode,
        status=replay.status,
        confidence=replay.confidence,
        summary=replay.summary,
        diff=replay.diff,
        created_at=replay.created_at,
    )


def _failure_reason(blocked: list[TraceEvent], event_counts: dict[str, int]) -> str:
    if any("prompt" in label or "injection" in label for event in blocked for label in event.risk_labels):
        return "prompt_injection_or_untrusted_content"
    if any(event.event_type == "policy_decision" or event.status == "blocked" for event in blocked):
        return "policy_blocked_high_risk_action"
    if event_counts.get("tool_call", 0) == 0 and event_counts.get("model_call", 0) > 0:
        return "model_failed_to_select_tool"
    if blocked:
        return "tool_or_runtime_failure"
    return "no_failure_detected"


def _suggestions(blocked: list[TraceEvent], event_counts: dict[str, int]) -> list[str]:
    suggestions = []
    labels = {label for event in blocked for label in event.risk_labels}
    if labels:
        suggestions.append("Review scanner evidence and sanitize untrusted content before it enters the agent context.")
    if any(event.status == "blocked" for event in blocked):
        suggestions.append("Check policy decision reason codes and add explicit approvals for legitimate high-risk tools.")
    if event_counts.get("mcp_call", 0):
        suggestions.append("Verify MCP tool descriptions, schemas, and upstream trust level.")
    if not suggestions:
        suggestions.append("Convert this run into an eval case to guard against future regressions.")
    return suggestions
