#!/usr/bin/env python3
"""Exercise AgentOps OIDC verification against a real pinned Keycloak runtime."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import jwt

from agentops_guard.backend import auth as auth_service
from agentops_guard.backend.models import Project
from agentops_guard.backend.services import oidc as oidc_service


KEYCLOAK_VERSION = "26.7.3"
JRE_VERSION = "21.0.12.1+1"
KEYCLOAK_ARCHIVE_SHA256 = "77657f30b7e90d70f727712ce1c967f430fd6a5e9f458d32d8c6df0635345f47"
JRE_ARCHIVE_SHA256 = "2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500"
KEYCLOAK_SIGNATURE_SHA256 = "128903d42c4b10e189cc922a89b3671ab60b8dbcd4f6b90091bc21751e54b7e6"
KEYCLOAK_PUBLIC_KEY_SHA256 = "cc0aafd52039fa77266f451bebfcb67cdfc2391e7204a160872cd9ab3163970a"
KEYCLOAK_SIGNER_FINGERPRINT = "861AB50E8CC6611FB6BC01A6B8F12EA26FD6EEBA"
JRE_SIGNATURE_SHA256 = "269a886dc5f1fc39bf640cc0a1a39473932a3f40f49492dcb81b0d09bc5822d6"
JRE_PUBLIC_KEY_SHA256 = "a46d5d3ab75c3c86dddf1bfd2957a067a24b1c6b2d2ed2bc69294bf970c5160b"
JRE_SIGNER_FINGERPRINT = "3B04D753C9050D9A5D343F39843C48A565F8F04B"
DEFAULT_RUNTIME = (
    Path.home() / f".local/share/agentops-guard/keycloak/{KEYCLOAK_VERSION}-signed-v1"
)
REALM = "agentops-runtime"
CLIENT_ID = "agentops-workload"
AUDIENCE = "agentops-guard"
PROJECT_ID = "keycloak-runtime-project"
AGENT_ID = "keycloak-runtime-agent"
ACCESS_TOKEN_LIFESPAN_SECONDS = 60


class _ProjectDatabase:
    def get(self, model: object, identity: str) -> SimpleNamespace | None:
        if model is Project and identity == PROJECT_ID:
            return SimpleNamespace(
                id=PROJECT_ID,
                organization_id="keycloak-runtime-organization",
                status="active",
            )
        return None


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _runtime_environment(runtime: Path, admin_password: str | None = None) -> dict[str, str]:
    java_home = runtime / "jre"
    environment = {
        "JAVA_HOME": str(java_home),
        "PATH": f"{java_home / 'bin'}:/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "LANG": "C",
        "KC_CACHE": "local",
    }
    if admin_password is not None:
        environment["KC_BOOTSTRAP_ADMIN_USERNAME"] = "runtime-admin"
        environment["KC_BOOTSTRAP_ADMIN_PASSWORD"] = admin_password
    return environment


def _verify_runtime_manifest(runtime: Path) -> None:
    manifest_path = runtime / "release.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise RuntimeError("pinned Keycloak runtime manifest is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        raise RuntimeError("pinned Keycloak runtime manifest is invalid") from None
    expected = {
        "keycloak_version": KEYCLOAK_VERSION,
        "keycloak_archive_sha256": KEYCLOAK_ARCHIVE_SHA256,
        "keycloak_signature_sha256": KEYCLOAK_SIGNATURE_SHA256,
        "keycloak_public_key_sha256": KEYCLOAK_PUBLIC_KEY_SHA256,
        "keycloak_signer_fingerprint": KEYCLOAK_SIGNER_FINGERPRINT,
        "jre_version": JRE_VERSION,
        "jre_archive_sha256": JRE_ARCHIVE_SHA256,
        "jre_signature_sha256": JRE_SIGNATURE_SHA256,
        "jre_public_key_sha256": JRE_PUBLIC_KEY_SHA256,
        "jre_signer_fingerprint": JRE_SIGNER_FINGERPRINT,
        "detached_signatures_verified": True,
    }
    if manifest != expected:
        raise RuntimeError("pinned Keycloak runtime manifest does not match reviewed releases")
    if not (runtime / "keycloak/bin/kc.sh").is_file() or not (
        runtime / "jre/bin/java"
    ).is_file():
        raise RuntimeError("pinned Keycloak runtime is incomplete")


def _hardcoded_claim_mapper(name: str, claim: str, value: str) -> dict[str, object]:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "consentRequired": False,
        "config": {
            "claim.name": claim,
            "claim.value": value,
            "jsonType.label": "String",
            "access.token.claim": "true",
            "id.token.claim": "false",
            "userinfo.token.claim": "false",
        },
    }


def _realm_configuration(client_secret: str) -> dict[str, object]:
    client_scopes = []
    for scope in ("runs:write", "mcp:invoke"):
        client_scopes.append(
            {
                "name": scope,
                "protocol": "openid-connect",
                "attributes": {
                    "include.in.token.scope": "true",
                    "display.on.consent.screen": "false",
                },
            }
        )
    mappers = [
        {
            "name": "agentops-audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": False,
            "config": {
                "included.client.audience": AUDIENCE,
                "access.token.claim": "true",
                "id.token.claim": "false",
                "introspection.token.claim": "true",
            },
        },
        _hardcoded_claim_mapper("agentops-token-use", "token_use", "agent"),
        _hardcoded_claim_mapper("agentops-project", "project_id", PROJECT_ID),
        _hardcoded_claim_mapper("agentops-agent", "agent_id", AGENT_ID),
    ]
    return {
        "realm": REALM,
        "enabled": True,
        "accessTokenLifespan": ACCESS_TOKEN_LIFESPAN_SECONDS,
        "ssoSessionIdleTimeout": 120,
        "ssoSessionMaxLifespan": 300,
        "clientScopes": client_scopes,
        "clients": [
            {
                "clientId": CLIENT_ID,
                "name": "AgentOps runtime verification workload",
                "enabled": True,
                "protocol": "openid-connect",
                "clientAuthenticatorType": "client-secret",
                "secret": client_secret,
                "publicClient": False,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "fullScopeAllowed": False,
                "defaultClientScopes": ["runs:write", "mcp:invoke"],
                "protocolMappers": mappers,
            }
        ],
    }


def _run_import(runtime: Path, realm_file: Path, database_url: str) -> None:
    result = subprocess.run(
        (
            str(runtime / "keycloak/bin/kc.sh"),
            "import",
            "--file",
            str(realm_file),
            "--override=true",
            "--db=dev-file",
            f"--db-url={database_url}",
        ),
        env=_runtime_environment(runtime),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Keycloak rejected the temporary verification realm")


def _bootstrap_admin(runtime: Path, database_url: str, admin_password: str) -> None:
    result = subprocess.run(
        (
            str(runtime / "keycloak/bin/kc.sh"),
            "bootstrap-admin",
            "user",
            "--username=runtime-admin",
            "--password:env=KC_BOOTSTRAP_ADMIN_PASSWORD",
            "--no-prompt",
            "--db=dev-file",
            f"--db-url={database_url}",
        ),
        env=_runtime_environment(runtime, admin_password),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Keycloak temporary administrator bootstrap failed")


def _start_keycloak(
    runtime: Path,
    *,
    port: int,
    database_url: str,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        (
            str(runtime / "keycloak/bin/kc.sh"),
            "start-dev",
            "--http-host=127.0.0.1",
            f"--http-port={port}",
            "--hostname-strict=false",
            "--health-enabled=true",
            "--db=dev-file",
            f"--db-url={database_url}",
            "--log-level=warn",
        ),
        env=_runtime_environment(runtime),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _wait_for_discovery(base_url: str, process: subprocess.Popen[bytes]) -> dict[str, object]:
    deadline = time.monotonic() + 90
    discovery_url = f"{base_url}/realms/{REALM}/.well-known/openid-configuration"
    with httpx.Client(timeout=2, trust_env=False) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Keycloak stopped before becoming ready")
            try:
                response = client.get(discovery_url)
                if response.status_code == 200:
                    payload = response.json()
                    if isinstance(payload, dict):
                        return payload
            except (httpx.HTTPError, json.JSONDecodeError):
                pass
            time.sleep(0.2)
    raise RuntimeError("Keycloak did not become ready in time")


def _request_token(base_url: str, client_secret: str) -> str:
    with httpx.Client(timeout=5, trust_env=False) as client:
        response = client.post(
            f"{base_url}/realms/{REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": client_secret,
            },
        )
    if response.status_code != 200:
        raise RuntimeError("Keycloak did not issue the workload token")
    try:
        token = response.json()["access_token"]
    except (json.JSONDecodeError, KeyError, TypeError):
        raise RuntimeError("Keycloak returned an invalid workload token response") from None
    if not isinstance(token, str) or token.count(".") != 2:
        raise RuntimeError("Keycloak returned an invalid workload token")
    return token


def _request_admin_token(base_url: str, admin_password: str) -> str:
    with httpx.Client(timeout=5, trust_env=False) as client:
        response = client.post(
            f"{base_url}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "runtime-admin",
                "password": admin_password,
            },
        )
    if response.status_code != 200:
        raise RuntimeError("Keycloak temporary administrator authentication failed")
    try:
        token = response.json()["access_token"]
    except (json.JSONDecodeError, KeyError, TypeError):
        raise RuntimeError("Keycloak returned an invalid administrator response") from None
    if not isinstance(token, str):
        raise RuntimeError("Keycloak returned an invalid administrator token")
    return token


def _verified_claims(token: str, issuer: str, jwks_url: str) -> dict[str, object]:
    settings = SimpleNamespace(
        oidc_issuer=issuer,
        oidc_audience=AUDIENCE,
        oidc_jwks_url=jwks_url,
        oidc_timeout_seconds=3.0,
        oidc_max_token_bytes=16_384,
        oidc_max_token_lifetime_seconds=900,
    )
    with patch.object(oidc_service, "get_settings", return_value=settings):
        return oidc_service.verify_oidc_token(token)


def _is_rejected(token: str, *, issuer: str, audience: str, jwks_url: str) -> bool:
    settings = SimpleNamespace(
        oidc_issuer=issuer,
        oidc_audience=audience,
        oidc_jwks_url=jwks_url,
        oidc_timeout_seconds=3.0,
        oidc_max_token_bytes=16_384,
        oidc_max_token_lifetime_seconds=900,
    )
    with patch.object(oidc_service, "get_settings", return_value=settings):
        try:
            oidc_service.verify_oidc_token(token)
        except oidc_service.OidcTokenInvalid:
            return True
    return False


def _tamper_signature(token: str) -> str:
    header, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    return f"{header}.{payload}.{replacement}{signature[1:]}"


def _rotate_signing_key(base_url: str, admin_token: str) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    with httpx.Client(timeout=5, trust_env=False, headers=headers) as client:
        realm_response = client.get(f"{base_url}/admin/realms/{REALM}")
        if realm_response.status_code != 200:
            raise RuntimeError("Keycloak realm lookup failed during signing-key rotation")
        realm_id = realm_response.json().get("id")
        if not isinstance(realm_id, str):
            raise RuntimeError("Keycloak realm identity is invalid")
        response = client.post(
            f"{base_url}/admin/realms/{REALM}/components",
            json={
                "name": "agentops-rotated-rsa",
                "providerId": "rsa-generated",
                "providerType": "org.keycloak.keys.KeyProvider",
                "parentId": realm_id,
                "config": {
                    "priority": ["200"],
                    "enabled": ["true"],
                    "active": ["true"],
                    "algorithm": ["RS256"],
                    "keySize": ["2048"],
                },
            },
        )
    if response.status_code != 201:
        raise RuntimeError("Keycloak signing-key rotation failed")


def _disable_client(base_url: str, admin_token: str) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    with httpx.Client(timeout=5, trust_env=False, headers=headers) as client:
        response = client.get(
            f"{base_url}/admin/realms/{REALM}/clients",
            params={"clientId": CLIENT_ID},
        )
        if response.status_code != 200:
            raise RuntimeError("Keycloak client lookup failed")
        clients = response.json()
        if not isinstance(clients, list) or len(clients) != 1:
            raise RuntimeError("Keycloak returned an ambiguous client identity")
        client_uuid = clients[0].get("id")
        if not isinstance(client_uuid, str):
            raise RuntimeError("Keycloak client identity is invalid")
        representation = client.get(
            f"{base_url}/admin/realms/{REALM}/clients/{client_uuid}"
        )
        if representation.status_code != 200:
            raise RuntimeError("Keycloak client representation lookup failed")
        payload = representation.json()
        payload["enabled"] = False
        disabled = client.put(
            f"{base_url}/admin/realms/{REALM}/clients/{client_uuid}",
            json=payload,
        )
    if disabled.status_code != 204:
        raise RuntimeError("Keycloak client disable operation failed")


def _set_access_token_lifespan(base_url: str, admin_token: str, seconds: int) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    with httpx.Client(timeout=5, trust_env=False, headers=headers) as client:
        response = client.get(f"{base_url}/admin/realms/{REALM}")
        if response.status_code != 200:
            raise RuntimeError("Keycloak realm lookup failed during expiry verification")
        payload = response.json()
        payload["accessTokenLifespan"] = seconds
        updated = client.put(f"{base_url}/admin/realms/{REALM}", json=payload)
    if updated.status_code != 204:
        raise RuntimeError("Keycloak access-token lifespan update failed")


def _new_token_is_denied(base_url: str, client_secret: str) -> bool:
    with httpx.Client(timeout=5, trust_env=False) as client:
        response = client.post(
            f"{base_url}/realms/{REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": client_secret,
            },
        )
    return response.status_code in {400, 401, 403}


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def verify(runtime: Path) -> dict[str, object]:
    _verify_runtime_manifest(runtime)
    client_secret = secrets.token_urlsafe(48)
    admin_password = secrets.token_urlsafe(48)
    with tempfile.TemporaryDirectory(prefix="agentops-keycloak-oidc-", dir="/tmp") as temp:
        temp_path = Path(temp)
        realm_file = temp_path / "realm.json"
        realm_file.write_text(
            json.dumps(_realm_configuration(client_secret), separators=(",", ":")),
            encoding="utf-8",
        )
        realm_file.chmod(0o600)
        database_path = temp_path / "data" / "keycloak"
        database_path.parent.mkdir(mode=0o700)
        database_url = f"jdbc:h2:file:{database_path};NON_KEYWORDS=VALUE"
        _run_import(runtime, realm_file, database_url)
        _bootstrap_admin(runtime, database_url, admin_password)
        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        process = _start_keycloak(
            runtime,
            port=port,
            database_url=database_url,
        )
        try:
            discovery = _wait_for_discovery(base_url, process)
            issuer = discovery.get("issuer")
            jwks_url = discovery.get("jwks_uri")
            if not isinstance(issuer, str) or not isinstance(jwks_url, str):
                raise RuntimeError("Keycloak discovery metadata is incomplete")
            if issuer != f"{base_url}/realms/{REALM}":
                raise RuntimeError("Keycloak discovery issuer is unexpected")
            token_before_rotation = _request_token(base_url, client_secret)
            initial_kid = jwt.get_unverified_header(token_before_rotation).get("kid")
            if not isinstance(initial_kid, str):
                raise RuntimeError("Keycloak workload token has no signing-key identity")
            oidc_service._jwks_client.cache_clear()
            claims = _verified_claims(token_before_rotation, issuer, jwks_url)
            issued_at = claims.get("iat")
            expires_at = claims.get("exp")
            if (
                not isinstance(issued_at, int)
                or not isinstance(expires_at, int)
                or expires_at - issued_at != ACCESS_TOKEN_LIFESPAN_SECONDS
            ):
                raise RuntimeError("Keycloak workload token has an unexpected lifetime")
            scopes = claims.get("scope", "").split()
            if not {"runs:write", "mcp:invoke"}.issubset(scopes):
                raise RuntimeError("Keycloak workload token is missing required scopes")
            if any(
                claims.get(name) != value
                for name, value in (
                    ("token_use", "agent"),
                    ("project_id", PROJECT_ID),
                    ("agent_id", AGENT_ID),
                )
            ):
                raise RuntimeError("Keycloak workload identity claims are incomplete")
            context = auth_service.oidc_auth_context(_ProjectDatabase(), claims, issuer)
            if (
                context.project_id != PROJECT_ID
                or context.agent_id != AGENT_ID
                or not {"runs:write", "mcp:invoke"}.issubset(context.capabilities)
            ):
                raise RuntimeError("AgentOps did not bind the verified workload identity")
            wrong_audience_rejected = _is_rejected(
                token_before_rotation,
                issuer=issuer,
                audience="another-service",
                jwks_url=jwks_url,
            )
            wrong_issuer_rejected = _is_rejected(
                token_before_rotation,
                issuer=f"{base_url}/realms/another-realm",
                audience=AUDIENCE,
                jwks_url=jwks_url,
            )
            tampered_signature_rejected = _is_rejected(
                _tamper_signature(token_before_rotation),
                issuer=issuer,
                audience=AUDIENCE,
                jwks_url=jwks_url,
            )
            admin_token = _request_admin_token(base_url, admin_password)
            _rotate_signing_key(base_url, admin_token)
            token_after_rotation = _request_token(base_url, client_secret)
            rotated_kid = jwt.get_unverified_header(token_after_rotation).get("kid")
            if not isinstance(rotated_kid, str) or rotated_kid == initial_kid:
                raise RuntimeError("Keycloak did not use the rotated signing key")
            rotated_token_accepted = bool(
                _verified_claims(token_after_rotation, issuer, jwks_url).get("sub")
            )
            old_token_after_rotation_accepted = bool(
                _verified_claims(token_before_rotation, issuer, jwks_url).get("sub")
            )
            _set_access_token_lifespan(base_url, admin_token, 1)
            expiring_token = _request_token(base_url, client_secret)
            time.sleep(2)
            expired_token_rejected = _is_rejected(
                expiring_token,
                issuer=issuer,
                audience=AUDIENCE,
                jwks_url=jwks_url,
            )
            _disable_client(base_url, admin_token)
            disabled_client_stopped_new_tokens = _new_token_is_denied(
                base_url, client_secret
            )
            old_token_after_disable_accepted = bool(
                _verified_claims(token_before_rotation, issuer, jwks_url).get("sub")
            )
        finally:
            _stop_process(process)
    checks = {
        "loopback_discovery": True,
        "signature_issuer_audience_expiry_verified": True,
        "workload_claims_and_scopes_bound": True,
        "wrong_audience_rejected": wrong_audience_rejected,
        "wrong_issuer_rejected": wrong_issuer_rejected,
        "tampered_signature_rejected": tampered_signature_rejected,
        "expired_token_rejected": expired_token_rejected,
        "rotated_signing_key_observed": rotated_kid != initial_kid,
        "rotated_token_accepted": rotated_token_accepted,
        "old_token_after_rotation_accepted": old_token_after_rotation_accepted,
        "disabled_client_stopped_new_tokens": disabled_client_stopped_new_tokens,
        "old_token_after_disable_accepted": old_token_after_disable_accepted,
        "offline_jwt_revocation_limit_observed": old_token_after_disable_accepted,
    }
    if not all(checks.values()):
        raise RuntimeError("one or more live Keycloak OIDC checks failed")
    return {
        "schema_version": "agentops.keycloak-oidc-runtime.v1",
        "keycloak_version": KEYCLOAK_VERSION,
        "jre_version": JRE_VERSION,
        "access_token_lifespan_seconds": ACCESS_TOKEN_LIFESPAN_SECONDS,
        "checks": checks,
        "secrets_in_report": False,
        "tokens_in_report": False,
        "claims_in_report": False,
        "production_gate_closed": False,
        "remaining_boundary": (
            "local development-mode identity provider without TLS, HA, federation, "
            "production database, or immediate JWT revocation"
        ),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    args = parser.parse_args()
    print(json.dumps(verify(args.runtime), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
