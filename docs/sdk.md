# AgentOps Guard Python SDK

This guide covers the minimum Python SDK integration for local development and production-like deployments.

## Install

From this repository:

```powershell
uv sync --extra dev
```

For an application that depends on the package, configure:

```powershell
$env:AGENTOPS_API_KEY="dev-agentops-key"
$env:AGENTOPS_API_URL="http://localhost:8000"
```

## Trace a Run

```python
from agentops_guard.sdk.tracing import AgentTracer

tracer = AgentTracer(agent_id="coding-agent", project_id="default")

with tracer.run(name="demo task") as run:
    with run.span("model_call", metadata={"model": "gpt-example"}) as span:
        span.set_output("hello")
```

The SDK creates a run, records span events, and marks the run `completed` or `failed` when the context exits.

## Policy and Scanner Calls

Use the HTTP client when an agent needs explicit governance checks:

```python
from agentops_guard.sdk.client import AgentOpsClient

client = AgentOpsClient(api_key="dev-agentops-key", base_url="http://localhost:8000")

scan = client.scan(content="Ignore previous instructions", source="agent_input")
decision = client.evaluate_policy(
    actor={"agent_id": "coding-agent"},
    tool={"name": "shell.execute", "command": "ls"},
    risk_labels=scan["risk_labels"],
)
```

Recommended flow:

1. Scan untrusted input, tool output, or retrieved content.
2. Pass risk labels and tool metadata to policy evaluation.
3. Record policy decisions as trace events for auditability.

## Content Storage

Raw content storage is disabled by default. Set `AGENTOPS_STORE_RAW_CONTENT=true` only when replay workflows require original prompts or tool outputs. Redacted summaries remain available without raw storage.

## Common Errors

- `401 Unauthorized`: API key is missing, revoked, or does not include the required scope.
- `403 Forbidden`: API key exists but lacks the route scope.
- `503 Redis queue unavailable`: async replay/eval/MCP refresh jobs require Redis.
- `422 Unprocessable Entity`: request body does not match the API contract.

## Validation

```powershell
uv run pytest tests/test_sdk.py tests/test_sdk_client.py -q
```
