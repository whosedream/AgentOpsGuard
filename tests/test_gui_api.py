from uuid import uuid4

from fastapi.testclient import TestClient

from agentops_guard.backend.main import app

client = TestClient(app)
headers = {"X-AgentOps-Api-Key": "dev-agentops-key"}


def test_SPEC_SETUP_001_system_status_contract():
    response = client.get("/v1/system/status", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["api"]["status"] == "ok"
    assert body["database"]["status"] == "ok"
    assert set(body["counts"]) >= {
        "runs",
        "risks",
        "eval_suites",
        "eval_runs",
        "replays",
        "mcp_servers",
        "mcp_tools",
    }
    assert body["config"]["project_id"] == "default"


def test_SPEC_REPLAY_002_list_replays_after_create():
    run = client.post("/v1/runs", headers=headers, json={"project_id": "default", "name": "replay seed"}).json()
    created = client.post("/v1/replays", headers=headers, json={"project_id": "default", "source_run_id": run["id"], "mode": "exact"})
    assert created.status_code == 200

    response = client.get(f"/v1/replays?project_id=default&source_run_id={run['id']}", headers=headers)
    assert response.status_code == 200
    assert response.json()[0]["id"] == created.json()["id"]


def test_SPEC_EVAL_002_run_suite_shortcut_and_SPEC_EVAL_003_list_runs():
    suite = client.post(
        "/v1/eval-suites",
        headers=headers,
        json={
            "project_id": "default",
            "name": "gui smoke",
            "cases": [
                {
                    "name": "dangerous shell",
                    "agent": "coding-agent",
                    "input": "hello",
                    "tool": {"name": "shell.execute", "command": "rm -rf /"},
                    "expected": {"policy_decisions": [{"action": "deny", "reason_code": "dangerous_command"}]},
                }
            ],
        },
    ).json()

    run_response = client.post(f"/v1/eval-suites/{suite['id']}/run", headers=headers)
    assert run_response.status_code == 200
    eval_run = run_response.json()
    assert eval_run["suite_id"] == suite["id"]
    assert eval_run["passed"] is True

    list_response = client.get(f"/v1/eval-runs?project_id=default&suite_id={suite['id']}", headers=headers)
    assert list_response.status_code == 200
    assert list_response.json()[0]["id"] == eval_run["id"]


def test_SPEC_MCP_001_mcp_server_crud_and_404():
    created = client.post(
        "/v1/mcp/servers",
        headers=headers,
        json={"id": "gui_test_server", "name": "gui_test_server", "transport": "stdio", "trust_level": "internal"},
    )
    assert created.status_code == 200

    fetched = client.get("/v1/mcp/servers/gui_test_server", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "gui_test_server"

    updated = client.patch(
        "/v1/mcp/servers/gui_test_server",
        headers=headers,
        json={"name": "renamed", "allowed_agents": ["coding-agent"]},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "renamed"
    assert updated.json()["allowed_agents"] == ["coding-agent"]

    deleted = client.delete("/v1/mcp/servers/gui_test_server", headers=headers)
    assert deleted.status_code == 200
    assert deleted.json() == {"status": "deleted", "id": "gui_test_server"}

    missing = client.get("/v1/mcp/servers/gui_test_server", headers=headers)
    assert missing.status_code == 404


def test_SPEC_RUN_001_server_side_filters_and_SPEC_RUN_003_pagination():
    project_id = f"gui_filters_{uuid4().hex[:8]}"
    first = client.post(
        "/v1/runs",
        headers=headers,
        json={"project_id": project_id, "agent_id": "alpha-agent", "name": "alpha"},
    ).json()
    second = client.post(
        "/v1/runs",
        headers=headers,
        json={"project_id": project_id, "agent_id": "beta-agent", "name": "beta"},
    ).json()
    client.patch(
        f"/v1/runs/{first['id']}",
        headers=headers,
        json={"status": "completed", "risk": {"score": 0.8, "labels": ["credential_exfiltration"]}},
    )
    client.patch(
        f"/v1/runs/{second['id']}",
        headers=headers,
        json={"status": "failed", "risk": {"score": 0.2, "labels": ["benign"]}},
    )

    filtered = client.get(
        f"/v1/runs?project_id={project_id}&status=completed&agent=alpha&risk_label=credential&page_mode=envelope&limit=1",
        headers=headers,
    )
    assert filtered.status_code == 200
    body = filtered.json()
    assert [item["id"] for item in body["items"]] == [first["id"]]
    assert body["next_cursor"] is None


def test_SPEC_RISK_001_server_side_severity_filter_and_pagination():
    project_id = f"risk_filters_{uuid4().hex[:8]}"
    run = client.post(
        "/v1/runs",
        headers=headers,
        json={"project_id": project_id, "name": "risk seed"},
    ).json()
    client.post(
        "/v1/events",
        headers=headers,
        json={
            "events": [
                {
                    "run_id": run["id"],
                    "project_id": project_id,
                    "event_type": "tool_call",
                    "risk": {"score": 0.8, "labels": ["critical_like"]},
                },
                {
                    "run_id": run["id"],
                    "project_id": project_id,
                    "event_type": "tool_call",
                    "risk": {"score": 0.5, "labels": ["medium_like"]},
                },
            ]
        },
    )

    high = client.get(
        f"/v1/risks?project_id={project_id}&severity=high&page_mode=envelope&limit=1",
        headers=headers,
    )
    assert high.status_code == 200
    body = high.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["severity"] == "high"
    assert body["items"][0]["run_id"] == run["id"]

