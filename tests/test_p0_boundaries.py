from __future__ import annotations

from fastapi.testclient import TestClient

from agentops_guard.backend.main import app


client = TestClient(app)
headers = {"X-AgentOps-Api-Key": "dev-agentops-key"}


def test_SPEC_P0_003_project_keys_cannot_cross_project_reads_or_mutations():
    project_a = client.post(
        "/v1/projects",
        headers=headers,
        json={"id": "tenant_a", "name": "Tenant A"},
    )
    project_b = client.post(
        "/v1/projects",
        headers=headers,
        json={"id": "tenant_b", "name": "Tenant B"},
    )
    assert project_a.status_code in {200, 409}
    assert project_b.status_code in {200, 409}

    run = client.post(
        "/v1/runs",
        headers=headers,
        json={"project_id": "tenant_b", "name": "isolated run"},
    )
    assert run.status_code == 200

    key_response = client.post(
        "/v1/api-keys",
        headers=headers,
        json={"project_id": "tenant_a", "name": "tenant-a-reader", "scopes": ["runs:*", "runs:read", "runs:admin"]},
    )
    assert key_response.status_code == 200
    project_key = {"X-AgentOps-Api-Key": key_response.json()["token"]}

    assert client.get(f"/v1/runs/{run.json()['id']}", headers=project_key).status_code == 404
    assert client.patch(
        f"/v1/runs/{run.json()['id']}",
        headers=project_key,
        json={"status": "failed"},
    ).status_code == 404
    assert client.get("/v1/runs?project_id=tenant_b", headers=project_key).status_code == 403


def test_SPEC_P0_003_project_keys_cannot_cross_project_admin_queries():
    key_response = client.post(
        "/v1/api-keys",
        headers=headers,
        json={"project_id": "tenant_a", "name": "tenant-a-admin", "scopes": ["control:read", "control:admin", "api_keys:*"]},
    )
    assert key_response.status_code == 200
    project_key = {"X-AgentOps-Api-Key": key_response.json()["token"]}

    assert client.get("/v1/projects/tenant_b", headers=project_key).status_code == 404
    assert client.patch(
        "/v1/projects/tenant_b",
        headers=project_key,
        json={"retention_days": 90},
    ).status_code == 404
    assert client.get("/v1/projects", headers=project_key).status_code == 403
