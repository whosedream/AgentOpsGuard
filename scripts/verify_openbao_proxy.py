from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

import httpx

from agentops_guard.backend.services.audit_checkpoints import (
    AuditCheckpointUnavailable,
    OpenBaoTransitSigner,
)
from agentops_guard.backend.services.credentials import (
    CredentialStoreUnavailable,
    OpenBaoCredentialStore,
)
from agentops_guard.backend.services.openbao_auth import ProxyOpenBaoTokenProvider
from verify_openbao_approle import (
    ROOT,
    _enable_approle,
    _enable_mount,
    _free_port,
    _wait_until_ready,
    _write_secret_file,
)


def _wait_for_listener(port: int) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("OpenBao Proxy did not become ready")


def _configure_wrapped_role(
    administrator: httpx.Client,
    delivery_client: httpx.Client,
    *,
    role_name: str,
    policy_name: str,
    role_id_file: Path,
    wrapping_token_file: Path,
) -> None:
    response = administrator.post(
        f"/v1/auth/approle/role/{role_name}",
        json={
            "token_policies": [policy_name],
            "token_ttl": "3s",
            "token_max_ttl": "3s",
            "secret_id_ttl": "60s",
            "secret_id_num_uses": 0,
            "token_num_uses": 0,
        },
    )
    response.raise_for_status()
    role_id_response = delivery_client.get(f"/v1/auth/approle/role/{role_name}/role-id")
    role_id_response.raise_for_status()
    wrapped_secret_id_response = delivery_client.post(
        f"/v1/auth/approle/role/{role_name}/secret-id",
        headers={"X-Vault-Wrap-TTL": "60s"},
    )
    wrapped_secret_id_response.raise_for_status()
    role_id = str(role_id_response.json()["data"]["role_id"])
    wrapping_token = str(wrapped_secret_id_response.json()["wrap_info"]["token"])
    _write_secret_file(role_id_file, role_id)
    _write_secret_file(wrapping_token_file, wrapping_token)


def _write_proxy_config(
    path: Path,
    *,
    server_url: str,
    listener_port: int,
    role_name: str,
    role_id_file: Path,
    wrapping_token_file: Path,
    ca_cert: Path | None = None,
) -> None:
    values = {
        "pid": json.dumps(str(path.with_suffix(".pid"))),
        "server": json.dumps(server_url),
        "listener": json.dumps(f"127.0.0.1:{listener_port}"),
        "role_id": json.dumps(str(role_id_file)),
        "secret_id": json.dumps(str(wrapping_token_file)),
        "wrapping_path": json.dumps(f"auth/approle/role/{role_name}/secret-id"),
        "ca_cert": json.dumps(str(ca_cert)) if ca_cert is not None else None,
    }
    ca_cert_line = f"  ca_cert = {values['ca_cert']}\n" if values["ca_cert"] else ""
    path.write_text(
        f"""pid_file = {values["pid"]}

vault {{
  address = {values["server"]}
{ca_cert_line}}}

auto_auth {{
  method {{
    type = "approle"
    mount_path = "auth/approle"
    config = {{
      role_id_file_path = {values["role_id"]}
      secret_id_file_path = {values["secret_id"]}
      remove_secret_id_file_after_reading = false
      secret_id_response_wrapping_path = {values["wrapping_path"]}
    }}
  }}
}}

listener "tcp" {{
  address = {values["listener"]}
  tls_disable = true
}}

api_proxy {{
  use_auto_auth_token = "force"
}}
""",
        encoding="utf-8",
    )


def _replace_wrapping_token(path: Path, value: str) -> None:
    replacement = path.with_name(f".{path.name}.next")
    _write_secret_file(replacement, value)
    os.replace(replacement, path)


def _rotate_wrapped_secret_id(
    delivery_client: httpx.Client,
    *,
    role_name: str,
    wrapping_token_file: Path,
) -> None:
    response = delivery_client.post(
        f"/v1/auth/approle/role/{role_name}/secret-id",
        headers={"X-Vault-Wrap-TTL": "60s"},
    )
    response.raise_for_status()
    wrapping_token = str(response.json()["wrap_info"]["token"])
    _replace_wrapping_token(wrapping_token_file, wrapping_token)


def _create_delivery_token(
    administrator: httpx.Client,
    *,
    policy_name: str,
    ttl: str = "60s",
) -> str:
    response = administrator.post(
        "/v1/auth/token/create",
        json={
            "policies": [policy_name],
            "no_default_policy": True,
            "renewable": False,
            "ttl": ttl,
            "explicit_max_ttl": ttl,
        },
    )
    response.raise_for_status()
    return str(response.json()["auth"]["client_token"])


def _access_is_denied(response: httpx.Response) -> bool:
    return response.status_code == 403


def _start_proxy(bao: str, config: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [bao, "proxy", f"-config={config}", "-log-level=error"],
        env={
            "HOME": str(config.parent),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _stop(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> None:
    bao = shutil.which("bao")
    if bao is None:
        raise RuntimeError("OpenBao CLI is not installed")
    server_port = _free_port()
    api_proxy_port = _free_port()
    exporter_proxy_port = _free_port()
    server_url = f"http://127.0.0.1:{server_port}"
    root_token = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="agentops-openbao-proxy-") as temp_dir:
        temp_path = Path(temp_dir)
        server = subprocess.Popen(
            [
                bao,
                "server",
                "-dev",
                f"-dev-listen-address=127.0.0.1:{server_port}",
            ],
            env={
                "BAO_DEV_ROOT_TOKEN_ID": root_token,
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proxies: list[subprocess.Popen[bytes]] = []
        try:
            _wait_until_ready(server_url)
            with httpx.Client(
                base_url=server_url,
                timeout=3,
                trust_env=False,
                headers={"X-Vault-Token": root_token},
            ) as administrator:
                _enable_mount(administrator, "secret", "kv")
                _enable_mount(administrator, "transit", "transit")
                key = administrator.post(
                    "/v1/transit/keys/agentops-audit",
                    json={"type": "ed25519", "exportable": False},
                )
                key.raise_for_status()
                _enable_approle(administrator)
                policies = {
                    "agentops-api": ROOT / "deploy/openbao/agentops-api-policy.hcl",
                    "agentops-audit-export": ROOT
                    / "deploy/openbao/agentops-audit-export-policy.hcl",
                    "agentops-api-identity-delivery": ROOT
                    / "deploy/openbao/agentops-api-identity-delivery-policy.hcl",
                    "agentops-audit-export-identity-delivery": ROOT
                    / "deploy/openbao/agentops-audit-export-identity-delivery-policy.hcl",
                }
                for policy_name, policy_path in policies.items():
                    response = administrator.put(
                        f"/v1/sys/policies/acl/{policy_name}",
                        json={"policy": policy_path.read_text(encoding="utf-8")},
                    )
                    response.raise_for_status()

                api_delivery_token = _create_delivery_token(
                    administrator,
                    policy_name="agentops-api-identity-delivery",
                )
                exporter_delivery_token = _create_delivery_token(
                    administrator,
                    policy_name="agentops-audit-export-identity-delivery",
                )
                with (
                    httpx.Client(
                        base_url=server_url,
                        timeout=3,
                        trust_env=False,
                        headers={"X-Vault-Token": api_delivery_token},
                    ) as api_delivery,
                    httpx.Client(
                        base_url=server_url,
                        timeout=3,
                        trust_env=False,
                        headers={"X-Vault-Token": exporter_delivery_token},
                    ) as exporter_delivery,
                ):
                    api_role_id_file = temp_path / "api-role-id"
                    api_wrapping_token_file = temp_path / "api-wrapped-secret-id"
                    _configure_wrapped_role(
                        administrator,
                        api_delivery,
                        role_name="agentops-api",
                        policy_name="agentops-api",
                        role_id_file=api_role_id_file,
                        wrapping_token_file=api_wrapping_token_file,
                    )
                    exporter_role_id_file = temp_path / "exporter-role-id"
                    exporter_wrapping_token_file = temp_path / "exporter-wrapped-secret-id"
                    _configure_wrapped_role(
                        administrator,
                        exporter_delivery,
                        role_name="agentops-audit-export",
                        policy_name="agentops-audit-export",
                        role_id_file=exporter_role_id_file,
                        wrapping_token_file=exporter_wrapping_token_file,
                    )

            api_config = temp_path / "api-proxy.hcl"
            _write_proxy_config(
                api_config,
                server_url=server_url,
                listener_port=api_proxy_port,
                role_name="agentops-api",
                role_id_file=api_role_id_file,
                wrapping_token_file=api_wrapping_token_file,
            )
            exporter_config = temp_path / "exporter-proxy.hcl"
            _write_proxy_config(
                exporter_config,
                server_url=server_url,
                listener_port=exporter_proxy_port,
                role_name="agentops-audit-export",
                role_id_file=exporter_role_id_file,
                wrapping_token_file=exporter_wrapping_token_file,
            )
            proxies.extend(
                [
                    _start_proxy(bao, api_config),
                    _start_proxy(bao, exporter_config),
                ]
            )
            _wait_for_listener(api_proxy_port)
            _wait_for_listener(exporter_proxy_port)

            no_token = ProxyOpenBaoTokenProvider()
            api_store = OpenBaoCredentialStore(
                url=f"http://127.0.0.1:{api_proxy_port}",
                token_provider=no_token,
                timeout=3,
            )
            binding = {
                "credential_ref": "cred_proxy_verification",
                "project_id": "proxy_verification",
                "provider": "verification",
                "status": "active",
                "version": 1,
                "allowed_actor_ids": ["verification-agent"],
                "revoked_at": None,
            }
            provider_secret = secrets.token_urlsafe(24)
            stored = api_store.store_credential("cred_proxy_verification", provider_secret, binding)
            api_credential_round_trip = (
                api_store.resolve_credential(
                    "cred_proxy_verification",
                    stored.secret_ref,
                    stored.binding_proof,
                    binding,
                )
                == provider_secret
            )
            api_signer = OpenBaoTransitSigner(
                url=f"http://127.0.0.1:{api_proxy_port}",
                token_provider=no_token,
                mount="transit",
                key_name="agentops-audit",
                timeout=3,
            )
            api_signature_created = bool(api_signer.sign(b"proxy-verification").signature)

            with (
                httpx.Client(
                    base_url=server_url,
                    timeout=3,
                    trust_env=False,
                    headers={"X-Vault-Token": api_delivery_token},
                ) as api_delivery,
                httpx.Client(
                    base_url=server_url,
                    timeout=3,
                    trust_env=False,
                    headers={"X-Vault-Token": exporter_delivery_token},
                ) as exporter_delivery,
            ):
                delivery_credential_read_denied = all(
                    _access_is_denied(
                        client.get("/v1/secret/data/agentops/cred_proxy_verification")
                    )
                    for client in (api_delivery, exporter_delivery)
                )
                delivery_signing_denied = all(
                    _access_is_denied(
                        client.post(
                            "/v1/transit/sign/agentops-audit",
                            json={"input": "dmVyaWZpY2F0aW9u"},
                        )
                    )
                    for client in (api_delivery, exporter_delivery)
                )
                _rotate_wrapped_secret_id(
                    api_delivery,
                    role_name="agentops-api",
                    wrapping_token_file=api_wrapping_token_file,
                )
                _rotate_wrapped_secret_id(
                    exporter_delivery,
                    role_name="agentops-audit-export",
                    wrapping_token_file=exporter_wrapping_token_file,
                )
            time.sleep(4)
            proxy_reauthentication_succeeded = (
                api_store.resolve_credential(
                    "cred_proxy_verification",
                    stored.secret_ref,
                    stored.binding_proof,
                    binding,
                )
                == provider_secret
            )

            exporter_signer = OpenBaoTransitSigner(
                url=f"http://127.0.0.1:{exporter_proxy_port}",
                token_provider=ProxyOpenBaoTokenProvider(),
                mount="transit",
                key_name="agentops-audit",
                timeout=3,
            )
            exporter_public_key_read = bool(exporter_signer.public_key())
            try:
                exporter_signer.sign(b"must-be-denied")
            except AuditCheckpointUnavailable:
                exporter_signing_denied = True
            else:
                exporter_signing_denied = False
            exporter_store = OpenBaoCredentialStore(
                url=f"http://127.0.0.1:{exporter_proxy_port}",
                token_provider=ProxyOpenBaoTokenProvider(),
                timeout=3,
            )
            try:
                exporter_store.resolve_credential(
                    "cred_proxy_verification",
                    stored.secret_ref,
                    stored.binding_proof,
                    binding,
                )
            except CredentialStoreUnavailable:
                exporter_credential_read_denied = True
            else:
                exporter_credential_read_denied = False

            with httpx.Client(
                base_url=server_url,
                timeout=3,
                trust_env=False,
                headers={"X-Vault-Token": root_token},
            ) as administrator:
                deleted = administrator.delete("/v1/auth/approle/role/agentops-api")
                deleted.raise_for_status()
            time.sleep(4)
            try:
                api_store.resolve_credential(
                    "cred_proxy_verification",
                    stored.secret_ref,
                    stored.binding_proof,
                    binding,
                )
            except CredentialStoreUnavailable:
                revoked_api_identity_denied = True
            else:
                revoked_api_identity_denied = False
        finally:
            for proxy in reversed(proxies):
                _stop(proxy)
            _stop(server)

    results = {
        "openbao_version": subprocess.run(
            [bao, "version"], capture_output=True, text=True, check=True
        ).stdout.split()[1],
        "authentication_owner": "openbao_proxy",
        "secret_id_delivery": "response_wrapped_file",
        "application_received_openbao_token": False,
        "api_credential_round_trip": api_credential_round_trip,
        "api_signature_created": api_signature_created,
        "delivery_credential_read_denied": delivery_credential_read_denied,
        "delivery_signing_denied": delivery_signing_denied,
        "proxy_reauthentication_succeeded": proxy_reauthentication_succeeded,
        "exporter_public_key_read": exporter_public_key_read,
        "exporter_signing_denied": exporter_signing_denied,
        "exporter_credential_read_denied": exporter_credential_read_denied,
        "revoked_api_identity_denied": revoked_api_identity_denied,
    }
    if not all(value is True for value in list(results.values())[4:]):
        raise RuntimeError("OpenBao Proxy verification failed")
    print(json.dumps(results, separators=(",", ":")))


if __name__ == "__main__":
    main()
