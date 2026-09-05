from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_keycloak_oidc.py"
SPEC = importlib.util.spec_from_file_location("verify_keycloak_oidc", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


def test_realm_configuration_has_short_lived_scoped_workload_identity():
    configuration = verifier._realm_configuration("generated-only-during-runtime")

    assert configuration["accessTokenLifespan"] == 60
    client = configuration["clients"][0]
    assert client["serviceAccountsEnabled"] is True
    assert client["standardFlowEnabled"] is False
    assert client["directAccessGrantsEnabled"] is False
    assert set(client["defaultClientScopes"]) == {"runs:write", "mcp:invoke"}
    mapped_claims = {
        mapper["config"].get("claim.name"): mapper["config"].get("claim.value")
        for mapper in client["protocolMappers"]
    }
    assert mapped_claims["token_use"] == "agent"
    assert mapped_claims["project_id"] == verifier.PROJECT_ID
    assert mapped_claims["agent_id"] == verifier.AGENT_ID


def test_tampered_signature_changes_only_signature_segment():
    token = "header.payload.signature"

    tampered = verifier._tamper_signature(token)

    assert tampered.split(".")[:2] == ["header", "payload"]
    assert tampered.split(".")[2] != "signature"
