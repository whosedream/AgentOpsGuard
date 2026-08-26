from fastapi.testclient import TestClient
from uuid import uuid4

from agentops_guard.backend.main import app


client = TestClient(app)
operator_headers = {"X-AgentOps-Api-Key": "dev-agentops-key"}


def test_dev_login_context_and_logout_flow():
    suffix = uuid4().hex[:8]
    login = client.post(
        "/v1/auth/dev-login",
        json={
            "email": f"admin-{suffix}@example.com",
            "display_name": f"Admin {suffix}",
            "role": "admin",
            "organization_name": f"Default Organization {suffix}",
        },
    )
    assert login.status_code == 200
    assert "agentops_session" in login.cookies
    client.cookies.update(login.cookies)

    context = client.get("/v1/auth/context")
    assert context.status_code == 200
    body = context.json()
    assert body["kind"] == "session_user"
    assert body["active_role"] == "admin"
    assert body["organization_id"]
    assert body["memberships"]

    logout = client.post("/v1/auth/logout")
    assert logout.status_code == 200
    after = client.get("/v1/auth/context")
    assert after.status_code == 401


def test_operator_bootstrap_organization_and_membership_flow():
    suffix = uuid4().hex[:8]
    created = client.post(
        "/v1/organizations",
        headers=operator_headers,
        json={
            "name": f"Acme Security {suffix}",
            "slug": f"acme-security-{suffix}",
            "initial_admin": {
                "email": f"owner-{suffix}@acme.test",
                "display_name": "Acme Owner",
            },
            "initial_project": {
                "id": f"acme-default-{suffix}",
                "name": "Acme Default",
            },
        },
    )
    assert created.status_code == 200
    organization = created.json()
    assert organization["slug"] == f"acme-security-{suffix}"
    assert organization["initial_project_id"] == f"acme-default-{suffix}"

    listed = client.get("/v1/organizations", headers=operator_headers)
    assert listed.status_code == 200
    assert any(item["id"] == organization["id"] for item in listed.json())

    membership = client.post(
        f"/v1/organizations/{organization['id']}/memberships",
        headers=operator_headers,
        json={
            "email": f"reviewer-{suffix}@acme.test",
            "display_name": "Acme Reviewer",
            "role": "security_reviewer",
        },
    )
    assert membership.status_code == 200
    assert membership.json()["role"] == "security_reviewer"


def test_read_only_session_cannot_access_governance_or_mcp_admin_actions():
    suffix = uuid4().hex[:8]
    login = client.post(
        "/v1/auth/dev-login",
        json={
            "email": f"reader-{suffix}@example.com",
            "display_name": f"Reader {suffix}",
            "role": "read_only",
            "organization_name": f"Reader Org {suffix}",
        },
    )
    assert login.status_code == 200
    client.cookies.update(login.cookies)
    context = client.get("/v1/auth/context").json()
    project_id = context["project_id"]

    assert client.get(f"/v1/runs?project_id={project_id}").status_code == 200
    assert client.get(f"/v1/control-plane/status?project_id={project_id}").status_code == 403
    denied = client.post(
        "/v1/mcp/servers",
        json={"project_id": project_id, "name": "reader-denied", "transport": "stdio"},
    )
    assert denied.status_code == 403
