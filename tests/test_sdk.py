import json

from agentops_guard.sdk.tracing import AgentOpsTracer


class FakeClient:
    def __init__(self):
        self.events = []
        self.updates = []

    def create_run(self, **payload):
        self.created = payload
        return {"id": "run_sdk", "trace_id": "trace_sdk"}

    def update_run(self, run_id, **payload):
        self.updates.append((run_id, payload))
        return {"id": run_id, **payload}

    def record_events(self, events):
        self.events.extend(events)
        return events


def test_sdk_tracer_records_nested_spans_and_completion():
    client = FakeClient()
    tracer = AgentOpsTracer(client=client, project_id="default", agent_id="sdk-agent")

    with tracer.start_run(name="sdk smoke", input_text="hello"):
        with tracer.trace_model_call("demo-model", input_text="prompt"):
            with tracer.trace_tool_call("search.web", {"query": "agentops"}):
                pass
        with tracer.trace_handoff("review-agent"):
            pass
        tracer.record_policy_decision({"action": "allow", "reason_code": "ok"})

    event_types = [event["event_type"] for event in client.events]
    assert "state_change" in event_types
    assert "model_call" in event_types
    assert "tool_call" in event_types
    assert "handoff" in event_types
    assert "policy_decision" in event_types
    assert client.updates[-1] == ("run_sdk", {"status": "completed"})


def test_sdk_tracer_records_failed_run():
    client = FakeClient()
    tracer = AgentOpsTracer(client=client, project_id="default", agent_id="sdk-agent")

    try:
        with tracer.start_run(name="sdk fail"):
            raise RuntimeError("boom")
    except RuntimeError:
        pass

    assert any(event["event_type"] == "error" for event in client.events)
    assert client.updates[-1][1]["status"] == "failed"
    assert client.updates[-1][1]["metadata"] == {"error_type": "RuntimeError"}


def test_sdk_tracer_does_not_store_exception_message():
    canary = "secret-value-that-must-not-be-recorded"
    client = FakeClient()
    tracer = AgentOpsTracer(client=client, project_id="default", agent_id="sdk-agent")

    try:
        with tracer.start_run(name="sdk fail"):
            raise RuntimeError(canary)
    except RuntimeError:
        pass

    assert canary not in json.dumps(
        {"events": client.events, "updates": client.updates},
        ensure_ascii=False,
    )


def test_sdk_tracer_redacts_detectable_secrets_before_sending():
    canary = "sk-abcdefghijklmnopqrstuvwxyz123456"
    client = FakeClient()
    tracer = AgentOpsTracer(client=client, project_id="default", agent_id="sdk-agent")

    with tracer.start_run(input_text=canary, metadata={"nested": {"token": canary}}):
        tracer.record_state_change("safe", metadata={"token": canary})

    assert canary not in json.dumps(
        {"created": client.created, "events": client.events, "updates": client.updates}
    )
