from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, Iterator
from uuid import uuid4

from agentops_guard.backend.services.content import redact_text, redact_value
from agentops_guard.sdk.client import AgentOpsClient

_current_run: ContextVar[dict[str, Any] | None] = ContextVar("agentops_current_run", default=None)
_current_span: ContextVar[str | None] = ContextVar("agentops_current_span", default=None)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _span_id() -> str:
    return f"span_{uuid4().hex[:24]}"


class AgentOpsTracer:
    def __init__(
        self,
        client: AgentOpsClient | None = None,
        project_id: str = "default",
        agent_id: str | None = None,
    ) -> None:
        self.client = client or AgentOpsClient()
        self.project_id = project_id
        self.agent_id = agent_id

    @contextmanager
    def start_run(
        self,
        name: str | None = None,
        user_id: str | None = None,
        input_text: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        run = self.client.create_run(
            project_id=self.project_id,
            agent_id=self.agent_id,
            name=redact_text(name),
            user_id=redact_text(user_id),
            input={"text": redact_text(input_text)} if input_text is not None else None,
            metadata=redact_value(metadata or {}),
        ) or {"id": f"run_{uuid4().hex[:24]}", "trace_id": f"trace_{uuid4().hex[:24]}"}
        token_run = _current_run.set(run)
        token_span = _current_span.set(None)
        self.record_state_change("run_started", metadata={"name": name})
        try:
            yield run
            self.client.update_run(run["id"], status="completed")
        except Exception as exc:
            self.record_error(exc)
            self.client.update_run(
                run["id"],
                status="failed",
                metadata={"error_type": type(exc).__name__},
            )
            raise
        finally:
            _current_run.reset(token_run)
            _current_span.reset(token_span)

    @contextmanager
    def trace_model_call(
        self, model: str, input_text: str | None = None, metadata: dict[str, Any] | None = None
    ) -> Iterator[dict[str, Any]]:
        with self._span(
            "model_call", input_text=input_text, metadata={"model": model, **(metadata or {})}
        ) as span:
            yield span

    @contextmanager
    def trace_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        with self._span(
            "tool_call",
            input_text=str(args or {}),
            metadata={"tool_name": tool_name, **(metadata or {})},
        ) as span:
            yield span

    @contextmanager
    def trace_handoff(
        self, target_agent: str, metadata: dict[str, Any] | None = None
    ) -> Iterator[dict[str, Any]]:
        with self._span(
            "handoff", metadata={"target_agent": target_agent, **(metadata or {})}
        ) as span:
            yield span

    def record_state_change(self, name: str, metadata: dict[str, Any] | None = None) -> None:
        self._record_event("state_change", metadata={"name": name, **(metadata or {})})

    def record_policy_decision(self, decision: dict[str, Any]) -> None:
        self._record_event(
            "policy_decision",
            status="blocked" if decision.get("action") in {"deny", "quarantine"} else "completed",
            metadata=decision,
        )

    def record_error(self, exc: Exception) -> None:
        self._record_event(
            "error",
            status="failed",
            metadata={"error_type": type(exc).__name__},
        )

    @contextmanager
    def _span(
        self, event_type: str, input_text: str | None = None, metadata: dict[str, Any] | None = None
    ) -> Iterator[dict[str, Any]]:
        parent_span_id = _current_span.get()
        span_id = _span_id()
        started_at = _now()
        token = _current_span.set(span_id)
        span = {"span_id": span_id, "parent_span_id": parent_span_id, "started_at": started_at}
        try:
            yield span
            self._record_event(
                event_type,
                span_id=span_id,
                parent_span_id=parent_span_id,
                input_text=input_text,
                metadata=metadata or {},
                started_at=started_at,
                ended_at=_now(),
            )
        except Exception as exc:
            self._record_event(
                event_type,
                span_id=span_id,
                parent_span_id=parent_span_id,
                input_text=input_text,
                status="failed",
                metadata={**(metadata or {}), "error_type": type(exc).__name__},
                started_at=started_at,
                ended_at=_now(),
            )
            raise
        finally:
            _current_span.reset(token)

    def _record_event(
        self,
        event_type: str,
        span_id: str | None = None,
        parent_span_id: str | None = None,
        input_text: str | None = None,
        output_text: str | None = None,
        status: str = "completed",
        metadata: dict[str, Any] | None = None,
        started_at: str | None = None,
        ended_at: str | None = None,
    ) -> None:
        run = _current_run.get()
        if not run:
            return
        self.client.record_events(
            [
                {
                    "run_id": run["id"],
                    "project_id": self.project_id,
                    "trace_id": run.get("trace_id"),
                    "span_id": span_id or _span_id(),
                    "parent_span_id": parent_span_id
                    if parent_span_id is not None
                    else _current_span.get(),
                    "event_type": event_type,
                    "status": status,
                    "actor": {"agent_id": self.agent_id},
                    "input": {"text": redact_text(input_text)} if input_text is not None else None,
                    "output": {"text": redact_text(output_text)}
                    if output_text is not None
                    else None,
                    "metadata": redact_value(metadata or {}),
                    "started_at": started_at,
                    "ended_at": ended_at,
                }
            ]
        )
