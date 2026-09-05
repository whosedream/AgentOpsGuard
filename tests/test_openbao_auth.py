from __future__ import annotations

import json

import httpx
import pytest

from agentops_guard.backend.config import Settings
from agentops_guard.backend.services.openbao_auth import (
    AppRoleOpenBaoTokenProvider,
    OpenBaoAuthenticationUnavailable,
)


def test_approle_provider_caches_short_lived_token_and_rereads_rotated_secret_id(
    tmp_path,
):
    secret_id_file = tmp_path / "secret-id"
    secret_id_file.write_text("first-secret-id", encoding="utf-8")
    now = [100.0]
    login_requests: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/auth/approle/login"
        assert "X-Vault-Token" not in request.headers
        payload = json.loads(request.content)
        login_requests.append(payload)
        return httpx.Response(
            200,
            json={
                "auth": {
                    "client_token": f"short-lived-token-{len(login_requests)}",
                    "lease_duration": 10,
                    "renewable": False,
                }
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        provider = AppRoleOpenBaoTokenProvider(
            url="https://openbao.test",
            role_id="api-role-id",
            secret_id_file=secret_id_file,
            client=client,
            monotonic=lambda: now[0],
        )
        assert provider.token() == "short-lived-token-1"
        assert provider.token() == "short-lived-token-1"
        assert len(login_requests) == 1

        secret_id_file.write_text("rotated-secret-id", encoding="utf-8")
        now[0] = 109.0
        assert provider.token() == "short-lived-token-2"

    assert login_requests == [
        {"role_id": "api-role-id", "secret_id": "first-secret-id"},
        {"role_id": "api-role-id", "secret_id": "rotated-secret-id"},
    ]


def test_approle_provider_failure_does_not_expose_secret_id(tmp_path):
    marker = "secret-id-canary-never-echo"
    secret_id_file = tmp_path / "secret-id"
    secret_id_file.write_text(marker, encoding="utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        provider = AppRoleOpenBaoTokenProvider(
            url="https://openbao.test",
            role_id="api-role-id",
            secret_id_file=secret_id_file,
            client=client,
        )
        with pytest.raises(OpenBaoAuthenticationUnavailable) as captured:
            provider.token()

    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)
    assert captured.value.__cause__ is None


def test_production_openbao_requires_loopback_proxy(tmp_path):
    base = {
        "_env_file": None,
        "env": "prod",
        "api_key": "production-api-key",
        "operator_api_key": "production-operator-key",
        "cors_allowed_origins": ["https://guard.example"],
        "allow_schema_bootstrap": False,
        "credential_store": "openbao",
        "openbao_url": "https://openbao.test",
    }
    with pytest.raises(ValueError, match="requires OpenBao Proxy"):
        Settings(**base, openbao_token="legacy-token")

    with pytest.raises(ValueError, match="must be an absolute path"):
        Settings(
            **base,
            openbao_auth_method="approle",
            openbao_approle_role_id="api-role-id",
            openbao_approle_secret_id_file="relative/secret-id",
        )

    direct_settings = Settings(
        **{**base, "env": "test"},
        openbao_auth_method="approle",
        openbao_approle_role_id="api-role-id",
        openbao_approle_secret_id_file=tmp_path / "secret-id",
    )
    assert direct_settings.openbao_auth_method == "approle"

    with pytest.raises(ValueError, match="must use a loopback URL"):
        Settings(**base, openbao_auth_method="proxy")

    with pytest.raises(ValueError, match="cannot receive direct credentials"):
        Settings(
            **{**base, "openbao_url": "http://127.0.0.1:8100"},
            openbao_auth_method="proxy",
            openbao_token="must-not-reach-application",
        )

    settings = Settings(
        **{**base, "openbao_url": "http://127.0.0.1:8100"},
        openbao_auth_method="proxy",
    )
    assert settings.openbao_auth_method == "proxy"
    assert settings.openbao_token is None
