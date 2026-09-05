from __future__ import annotations

from pathlib import Path
from threading import Lock
import time
from collections.abc import Callable
from typing import Protocol
from urllib.parse import quote

import httpx

from agentops_guard.backend.config import Settings
from agentops_guard.backend.telemetry import inject_trace_headers


class OpenBaoAuthenticationUnavailable(RuntimeError):
    pass


class OpenBaoTokenProvider(Protocol):
    def token(self) -> str | None: ...

    def invalidate(self) -> None: ...


class StaticOpenBaoTokenProvider:
    """Compatibility provider for local development only."""

    def __init__(self, token: str) -> None:
        self._token = token

    def token(self) -> str:
        return self._token

    def invalidate(self) -> None:
        return None


class ProxyOpenBaoTokenProvider:
    """Let a loopback OpenBao Proxy inject and renew the workload token."""

    def token(self) -> None:
        return None

    def invalidate(self) -> None:
        return None


class AppRoleOpenBaoTokenProvider:
    """Exchange a file-mounted AppRole SecretID for a short-lived workload token."""

    def __init__(
        self,
        *,
        url: str,
        role_id: str,
        secret_id_file: Path,
        mount: str = "approle",
        timeout: float = 5.0,
        client: httpx.Client | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url.rstrip("/")
        self._role_id = role_id
        self._secret_id_file = secret_id_file
        self._mount = mount
        self._timeout = timeout
        self._client = client
        self._monotonic = monotonic
        self._cached_token: str | None = None
        self._refresh_at = 0.0
        self._lock = Lock()

    def token(self) -> str:
        now = self._now()
        if self._cached_token is not None and now < self._refresh_at:
            return self._cached_token
        with self._lock:
            now = self._now()
            if self._cached_token is not None and now < self._refresh_at:
                return self._cached_token
            token, lease_duration = self._login()
            refresh_margin = min(30.0, max(0.1, lease_duration * 0.1))
            self._cached_token = token
            self._refresh_at = now + max(0.0, lease_duration - refresh_margin)
            return token

    def invalidate(self) -> None:
        with self._lock:
            self._cached_token = None
            self._refresh_at = 0.0

    def _now(self) -> float:
        return float(self._monotonic())

    def _login(self) -> tuple[str, float]:
        try:
            secret_id = self._secret_id_file.read_text(encoding="utf-8").strip()
            if not secret_id or len(secret_id.encode("utf-8")) > 16_384:
                raise ValueError("invalid AppRole SecretID file")
            headers: dict[str, str] = {}
            inject_trace_headers(headers)
            url = f"{self._url}/v1/auth/{quote(self._mount, safe='')}/login"
            payload = {"role_id": self._role_id, "secret_id": secret_id}
            if self._client is not None:
                response = self._client.post(url, headers=headers, json=payload)
            else:
                with httpx.Client(
                    timeout=self._timeout,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            auth = response.json()["auth"]
            token = str(auth["client_token"])
            lease_duration = float(auth["lease_duration"])
            if not token or lease_duration <= 0:
                raise ValueError("invalid AppRole login response")
            return token, lease_duration
        except (OSError, httpx.HTTPError, KeyError, TypeError, ValueError):
            raise OpenBaoAuthenticationUnavailable("OpenBao AppRole login failed") from None


def configured_openbao_token_provider(settings: Settings) -> OpenBaoTokenProvider:
    if settings.openbao_auth_method == "proxy":
        return ProxyOpenBaoTokenProvider()
    if settings.openbao_auth_method == "approle":
        assert settings.openbao_url is not None
        assert settings.openbao_approle_role_id is not None
        assert settings.openbao_approle_secret_id_file is not None
        return AppRoleOpenBaoTokenProvider(
            url=settings.openbao_url,
            role_id=settings.openbao_approle_role_id,
            secret_id_file=settings.openbao_approle_secret_id_file,
            mount=settings.openbao_approle_mount,
            timeout=settings.openbao_timeout_seconds,
        )
    assert settings.openbao_token is not None
    return StaticOpenBaoTokenProvider(settings.openbao_token.get_secret_value())


def resolve_openbao_token_provider(
    *,
    token: str | None,
    token_provider: OpenBaoTokenProvider | None,
) -> OpenBaoTokenProvider:
    if (token is None) == (token_provider is None):
        raise ValueError("configure exactly one OpenBao authentication source")
    if token_provider is not None:
        return token_provider
    assert token is not None
    return StaticOpenBaoTokenProvider(token)
