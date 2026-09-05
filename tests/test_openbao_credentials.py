from __future__ import annotations

import json

import httpx
import pytest

from agentops_guard.backend.config import Settings
from agentops_guard.backend.services.credentials import (
    CredentialStoreUnavailable,
    OpenBaoCredentialStore,
)
from agentops_guard.backend.services.openbao_auth import ProxyOpenBaoTokenProvider


def test_openbao_store_keeps_secret_out_of_sql_markers_and_binds_metadata():
    secret = "provider-secret-never-store-in-sql"
    token = "openbao-test-token"
    records: dict[str, dict[str, object]] = {}
    version = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal version
        assert request.headers["X-Vault-Token"] == token
        assert secret not in str(request.url)
        if request.method == "POST":
            version += 1
            body = json.loads(request.content)
            records[request.url.path] = {
                **body["data"],
                "version": version,
            }
            return httpx.Response(200, json={"data": {"version": version}})
        record = records[request.url.path]
        return httpx.Response(
            200,
            json={
                "data": {
                    "data": {
                        "secret": record["secret"],
                        "binding_digest": record["binding_digest"],
                    },
                    "metadata": {"version": record["version"]},
                }
            },
        )

    binding = {
        "credential_ref": "cred_test",
        "project_id": "project_test",
        "provider": "deepseek",
        "status": "active",
        "version": 1,
        "allowed_actor_ids": ["operator"],
        "revoked_at": None,
    }
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        store = OpenBaoCredentialStore(
            url="http://openbao.test",
            token=token,
            mount="secret",
            client=client,
        )
        stored = store.store_credential("cred_test", secret, binding)

        assert stored.secret_ref == "openbao:secret/agentops/cred_test"
        assert stored.binding_proof == "openbao-version:1"
        assert secret not in repr(stored)
        assert (
            store.resolve_credential(
                "cred_test",
                stored.secret_ref,
                stored.binding_proof,
                binding,
            )
            == secret
        )

        with pytest.raises(ValueError, match="binding mismatch"):
            store.resolve_credential(
                "cred_test",
                stored.secret_ref,
                stored.binding_proof,
                {**binding, "allowed_actor_ids": ["attacker"]},
            )


def test_openbao_rebinds_revocation_without_returning_secret():
    secret = "provider-secret-revocation-test"
    record: dict[str, object] = {}
    version = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal version
        if request.method == "POST":
            version += 1
            record.update(json.loads(request.content)["data"])
            record["version"] = version
            return httpx.Response(200, json={"data": {"version": version}})
        return httpx.Response(
            200,
            json={
                "data": {
                    "data": {
                        "secret": record["secret"],
                        "binding_digest": record["binding_digest"],
                    },
                    "metadata": {"version": record["version"]},
                }
            },
        )

    active = {
        "credential_ref": "cred_revoke",
        "project_id": "project_test",
        "status": "active",
        "version": 1,
        "revoked_at": None,
    }
    revoked = {**active, "status": "revoked", "revoked_at": "2026-08-24T00:00:00+00:00"}
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        store = OpenBaoCredentialStore(url="http://openbao.test", token="test-token", client=client)
        stored = store.store_credential("cred_revoke", secret, active)
        proof = store.rebind_credential(
            "cred_revoke",
            stored.secret_ref,
            stored.binding_proof,
            revoked,
        )

        assert proof == "openbao-version:2"
        assert secret not in proof
        assert (
            store.resolve_credential(
                "cred_revoke",
                stored.secret_ref,
                proof,
                revoked,
            )
            == secret
        )


def test_openbao_request_failure_does_not_chain_token_bearing_request():
    token_marker = "short-lived-token-canary-never-echo"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        store = OpenBaoCredentialStore(
            url="http://openbao.test",
            token=token_marker,
            client=client,
        )
        with pytest.raises(CredentialStoreUnavailable) as captured:
            store.store_credential(
                "cred_failure",
                "provider-secret",
                {"credential_ref": "cred_failure", "status": "active"},
            )

    assert captured.value.__cause__ is None
    assert token_marker not in str(captured.value)
    assert token_marker not in repr(captured.value)


def test_openbao_proxy_mode_sends_no_token_header_from_application():
    def handler(request: httpx.Request) -> httpx.Response:
        assert "X-Vault-Token" not in request.headers
        return httpx.Response(200, json={"data": {"version": 1}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        store = OpenBaoCredentialStore(
            url="http://127.0.0.1:8100",
            token_provider=ProxyOpenBaoTokenProvider(),
            client=client,
        )
        stored = store.store_credential(
            "cred_proxy",
            "provider-secret",
            {"credential_ref": "cred_proxy", "status": "active"},
        )

    assert stored.binding_proof == "openbao-version:1"


def test_openbao_settings_require_credential_free_url_and_secret_token():
    with pytest.raises(ValueError, match="requires AGENTOPS_OPENBAO_URL"):
        Settings(_env_file=None, credential_store="openbao")

    with pytest.raises(ValueError, match="credential-free HTTP base URL"):
        Settings(
            _env_file=None,
            credential_store="openbao",
            openbao_url="https://user:password@openbao.test",
            openbao_token="token",
        )

    settings = Settings(
        _env_file=None,
        credential_store="openbao",
        openbao_url="https://openbao.test",
        openbao_token="token",
    )
    assert settings.openbao_token is not None
    assert "token" not in repr(settings.openbao_token)
