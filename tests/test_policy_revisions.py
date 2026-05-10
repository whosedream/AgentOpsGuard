from fastapi.testclient import TestClient

from agentops_guard.backend.main import app


client = TestClient(app)
headers = {"X-AgentOps-Api-Key": "dev-agentops-key"}


def test_SPEC_P2_001_policy_pack_revision_create_without_mutating_original():
    pack = client.post(
        "/v1/policy-packs",
        headers=headers,
        json={"project_id": "default", "name": "revisionable", "version": "1.0.0", "rules": [{"id": "one", "action": "deny"}]},
    )
    assert pack.status_code == 200
    created = pack.json()

    revision = client.post(
        f"/v1/policy-packs/{created['id']}/versions",
        headers=headers,
        json={"version": "1.1.0", "rules": [{"id": "two", "action": "allow"}], "description": "next revision"},
    )
    assert revision.status_code == 200
    revised = revision.json()

    original = client.get("/v1/policy-packs?project_id=default", headers=headers).json()
    original_row = next(item for item in original if item["id"] == created["id"])
    assert original_row["version"] == "1.0.0"
    assert revised["version"] == "1.1.0"
