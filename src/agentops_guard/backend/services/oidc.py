from __future__ import annotations

from functools import lru_cache
from hashlib import sha256
from typing import Any

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError

from agentops_guard.backend.config import get_settings


class OidcTokenInvalid(ValueError):
    pass


def oidc_external_subject(issuer: str, subject: str) -> str:
    if not issuer or not subject or len(subject) > 220:
        raise OidcTokenInvalid("OIDC subject is invalid")
    value = f"{sha256(issuer.encode('utf-8')).hexdigest()[:16]}:{subject}"
    if len(value) > 255:
        raise OidcTokenInvalid("OIDC subject is too long")
    return value


def verify_oidc_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    if (
        settings.oidc_issuer is None
        or settings.oidc_audience is None
        or settings.oidc_jwks_url is None
    ):
        raise OidcTokenInvalid("OIDC is not configured")
    if (
        not isinstance(token, str)
        or not token.isascii()
        or len(token) > settings.oidc_max_token_bytes
    ):
        raise OidcTokenInvalid("OIDC token exceeds the accepted size")
    try:
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        if algorithm not in {"RS256", "ES256"}:
            raise OidcTokenInvalid("Unsupported OIDC signing algorithm")
        key_id = header.get("kid")
        if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
            raise OidcTokenInvalid("OIDC signing key identity is invalid")
        key = _jwks_client(
            settings.oidc_jwks_url,
            settings.oidc_timeout_seconds,
        ).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=[algorithm],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={"require": ["exp", "iat", "sub"]},
        )
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        subject = claims.get("sub")
        if (
            not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at <= issued_at
            or expires_at - issued_at > settings.oidc_max_token_lifetime_seconds
        ):
            raise OidcTokenInvalid("OIDC token lifetime is invalid")
        if not isinstance(subject, str) or not subject or len(subject) > 220:
            raise OidcTokenInvalid("OIDC subject is invalid")
        return claims
    except OidcTokenInvalid:
        raise
    except PyJWTError as exc:
        raise OidcTokenInvalid("OIDC token verification failed") from exc


@lru_cache(maxsize=8)
def _jwks_client(url: str, timeout: float) -> PyJWKClient:
    return PyJWKClient(url, cache_keys=True, timeout=timeout)
