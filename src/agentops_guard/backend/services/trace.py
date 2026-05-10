from agentops_guard.backend.models import Run, TraceEvent
from agentops_guard.backend.schemas import DagEdge, DagNode, RunDag, RunOut


def run_to_schema(run: Run) -> RunOut:
    return RunOut(
        id=run.id,
        project_id=run.project_id,
        agent_id=run.agent_id,
        trace_id=run.trace_id,
        name=run.name,
        status=run.status,
        user_id=run.user_id,
        input_ref=run.input_ref,
        output_ref=run.output_ref,
        risk_score=run.risk_score,
        risk_labels=run.risk_labels or [],
        total_cost_usd=run.total_cost_usd,
        total_tokens=run.total_tokens,
        metadata=run.metadata_json or {},
        started_at=run.started_at,
        ended_at=run.ended_at,
    )


def build_dag(run: Run, events: list[TraceEvent]) -> RunDag:
    nodes = [
        DagNode(
            id=event.span_id,
            type=event.event_type,
            status=event.status,
            label=event.metadata_json.get("name") or event.metadata_json.get("tool_name") or event.event_type,
            risk_score=event.risk_score,
            risk_labels=event.risk_labels or [],
            metadata=event.metadata_json or {},
        )
        for event in events
    ]
    known = {node.id for node in nodes}
    edges = [
        DagEdge(source=event.parent_span_id, target=event.span_id)
        for event in events
        if event.parent_span_id and event.parent_span_id in known
    ]
    return RunDag(run=run_to_schema(run), nodes=nodes, edges=edges)
