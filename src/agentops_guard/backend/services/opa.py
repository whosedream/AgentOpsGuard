from __future__ import annotations

from typing import Any

import httpx

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.telemetry import inject_trace_headers


class OpaUnavailable(RuntimeError):
    pass


def evaluate_opa(input_document: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    if settings.opa_url is None:
        raise OpaUnavailable("OPA is not configured")
    try:
        with httpx.Client(
            timeout=settings.opa_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            headers: dict[str, str] = {}
            inject_trace_headers(headers)
            response = client.post(
                f"{settings.opa_url.rstrip('/')}/v1/data/agentops/guard/decision",
                json={"input": input_document},
                headers=headers,
            )
            response.raise_for_status()
            result = response.json().get("result")
    except (httpx.HTTPError, ValueError) as exc:
        raise OpaUnavailable("OPA policy evaluation failed") from exc
    if not isinstance(result, dict):
        raise OpaUnavailable("OPA returned no decision")
    expected_revision = settings.opa_expected_policy_revision
    if expected_revision is not None and result.get("policy_revision") != expected_revision:
        raise OpaUnavailable("OPA policy revision does not match the approved revision")
    return result


def check_opa_health() -> None:
    settings = get_settings()
    if settings.opa_url is None:
        return
    try:
        with httpx.Client(
            timeout=settings.opa_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            headers: dict[str, str] = {}
            inject_trace_headers(headers)
            response = client.get(
                f"{settings.opa_url.rstrip('/')}/health",
                params={"bundles": "true", "plugins": "true"},
                headers=headers,
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise OpaUnavailable("OPA health check failed") from exc
    if settings.opa_expected_policy_revision is not None:
        evaluate_opa({"tool": {"name": "records.read"}, "risk_score": 0})
