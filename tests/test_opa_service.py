from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from agentops_guard.backend.services import opa


def _mock_client(monkeypatch, policy_revision: str):
    original_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={})
        return httpx.Response(
            200,
            json={
                "result": {
                    "action": "allow",
                    "policy_revision": policy_revision,
                }
            },
        )

    def client(**kwargs):
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(opa.httpx, "Client", client)
    monkeypatch.setattr(
        opa,
        "get_settings",
        lambda: SimpleNamespace(
            opa_url="http://opa.test:8181",
            opa_timeout_seconds=1,
            opa_expected_policy_revision="agentops-guard-v2",
        ),
    )


def test_opa_accepts_only_the_approved_policy_revision(monkeypatch):
    _mock_client(monkeypatch, "agentops-guard-v2")

    result = opa.evaluate_opa({"tool": {"name": "records.read"}, "risk_score": 0})

    assert result["policy_revision"] == "agentops-guard-v2"
    opa.check_opa_health()


def test_opa_rejects_a_valid_response_from_an_unapproved_revision(monkeypatch):
    _mock_client(monkeypatch, "agentops-guard-v1")

    with pytest.raises(opa.OpaUnavailable, match="approved revision"):
        opa.evaluate_opa({"tool": {"name": "records.read"}, "risk_score": 0})
    with pytest.raises(opa.OpaUnavailable, match="approved revision"):
        opa.check_opa_health()
