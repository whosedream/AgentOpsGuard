import httpx

from agentops_guard.sdk.client import AgentOpsClient


def test_agentops_client_success_paths():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/runs" and request.method == "POST":
            return httpx.Response(200, json={"id": "run_client"})
        if request.url.path == "/v1/runs/run_client" and request.method == "PATCH":
            return httpx.Response(200, json={"id": "run_client", "status": "completed"})
        if request.url.path == "/v1/events":
            return httpx.Response(200, json=[])
        if request.url.path == "/v1/policies/evaluate":
            return httpx.Response(200, json={"action": "allow"})
        if request.url.path == "/v1/scanner/scan":
            return httpx.Response(200, json={"risk_labels": []})
        return httpx.Response(404)

    client = AgentOpsClient(base_url="http://test", api_key="key")
    client._client = httpx.Client(transport=httpx.MockTransport(handler), headers={"X-AgentOps-Api-Key": "key"})

    assert client.create_run()["id"] == "run_client"
    assert client.update_run("run_client", status="completed")["status"] == "completed"
    assert client.record_events([]) == []
    assert client.evaluate_policy()["action"] == "allow"
    assert client.scan(content="hello")["risk_labels"] == []
    client.close()


def test_agentops_client_error_paths_return_none():
    client = AgentOpsClient(base_url="http://test", api_key="key")
    client._client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(500)))

    assert client.create_run() is None
    assert client.update_run("missing") is None
