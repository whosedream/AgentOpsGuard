from agentops_guard.sdk import AgentOpsClient, AgentOpsTracer

client = AgentOpsClient(base_url="http://localhost:8000", api_key="dev-agentops-key")
tracer = AgentOpsTracer(client=client, project_id="default", agent_id="demo-agent")

with tracer.start_run(name="demo trace", user_id="local", input_text="Summarize docs safely"):
    with tracer.trace_model_call("gpt-4.1-mini", input_text="Plan which tool to use"):
        pass
    with tracer.trace_tool_call("search.web", {"query": "AgentOps Guard MCP"}):
        pass
    decision = client.evaluate_policy(
        project_id="default",
        actor={"agent_id": "demo-agent"},
        tool={"name": "search.web"},
        risk_score=0.0,
        risk_labels=[],
    )
    if decision:
        tracer.record_policy_decision(decision)

print("Demo run sent to AgentOps Guard")
