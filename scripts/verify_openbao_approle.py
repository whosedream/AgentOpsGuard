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
from agentops_guard.backend.services.openbao_auth import AppRoleOpenBaoTokenProvider


ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_ready(base_url: str) -> None:
    deadline = time.monotonic() + 15
    with httpx.Client(timeout=1, trust_env=False) as client:
        while time.monotonic() < deadline:
            try:
                if client.get(f"{base_url}/v1/sys/health").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    raise RuntimeError("OpenBao did not become ready")


def _write_secret_file(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value.encode("utf-8"))
    finally:
        os.close(descriptor)


def _enable_mount(client: httpx.Client, name: str, mount_type: str) -> None:
    mounts = client.get("/v1/sys/mounts")
    mounts.raise_for_status()
    if f"{name}/" in mounts.json():
        return
    payload: dict[str, object] = {"type": mount_type}
    if mount_type == "kv":
        payload["options"] = {"version": "2"}
    response = client.post(f"/v1/sys/mounts/{name}", json=payload)
    response.raise_for_status()


def _enable_approle(client: httpx.Client) -> None:
    methods = client.get("/v1/sys/auth")
    methods.raise_for_status()
    if "approle/" in methods.json():
        return
    response = client.post("/v1/sys/auth/approle", json={"type": "approle"})
    response.raise_for_status()


def _configure_role(
    client: httpx.Client,
    *,
    role_name: str,
    policy_name: str,
    secret_id_file: Path,
) -> str:
    response = client.post(
        f"/v1/auth/approle/role/{role_name}",
        json={
            "token_policies": [policy_name],
            "token_ttl": "5s",
            "token_max_ttl": "10s",
            "secret_id_ttl": "60s",
            "secret_id_num_uses": 0,
        },
    )
    response.raise_for_status()
    role_id_response = client.get(f"/v1/auth/approle/role/{role_name}/role-id")
    role_id_response.raise_for_status()
    secret_id_response = client.post(f"/v1/auth/approle/role/{role_name}/secret-id")
    secret_id_response.raise_for_status()
    role_id = str(role_id_response.json()["data"]["role_id"])
    secret_id = str(secret_id_response.json()["data"]["secret_id"])
    _write_secret_file(secret_id_file, secret_id)
    return role_id


def main() -> None:
    bao = shutil.which("bao")
    if bao is None:
        raise RuntimeError("OpenBao CLI is not installed")
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    root_token = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="agentops-openbao-approle-") as temp_dir:
        temp_path = Path(temp_dir)
        api_secret_id_file = temp_path / "api-secret-id"
        exporter_secret_id_file = temp_path / "exporter-secret-id"
        process = subprocess.Popen(
            [
                bao,
                "server",
                "-dev",
                f"-dev-listen-address=127.0.0.1:{port}",
            ],
            env={
                "BAO_DEV_ROOT_TOKEN_ID": root_token,
                "LANG": os.environ.get("LANG", "C.UTF-8"),
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_until_ready(base_url)
            with httpx.Client(
                base_url=base_url,
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
                }
                for policy_name, policy_path in policies.items():
                    response = administrator.put(
                        f"/v1/sys/policies/acl/{policy_name}",
                        json={"policy": policy_path.read_text(encoding="utf-8")},
                    )
                    response.raise_for_status()
                api_role_id = _configure_role(
                    administrator,
                    role_name="agentops-api",
                    policy_name="agentops-api",
                    secret_id_file=api_secret_id_file,
                )
                exporter_role_id = _configure_role(
                    administrator,
                    role_name="agentops-audit-export",
                    policy_name="agentops-audit-export",
                    secret_id_file=exporter_secret_id_file,
                )

            api_provider = AppRoleOpenBaoTokenProvider(
                url=base_url,
                role_id=api_role_id,
                secret_id_file=api_secret_id_file,
                timeout=3,
            )
            api_store = OpenBaoCredentialStore(
                url=base_url,
                token_provider=api_provider,
                timeout=3,
            )
            binding = {
                "credential_ref": "cred_approle_verification",
                "project_id": "approle_verification",
                "provider": "verification",
                "status": "active",
                "version": 1,
                "allowed_actor_ids": ["verification-agent"],
                "revoked_at": None,
            }
            provider_secret = secrets.token_urlsafe(24)
            stored = api_store.store_credential(
                "cred_approle_verification", provider_secret, binding
            )
            api_credential_round_trip = (
                api_store.resolve_credential(
                    "cred_approle_verification",
                    stored.secret_ref,
                    stored.binding_proof,
                    binding,
                )
                == provider_secret
            )
            api_signer = OpenBaoTransitSigner(
                url=base_url,
                token_provider=api_provider,
                mount="transit",
                key_name="agentops-audit",
                timeout=3,
            )
            api_signature_created = bool(api_signer.sign(b"approle-verification").signature)
            api_provider.invalidate()
            api_reauthentication_succeeded = (
                api_store.resolve_credential(
                    "cred_approle_verification",
                    stored.secret_ref,
                    stored.binding_proof,
                    binding,
                )
                == provider_secret
            )

            exporter_provider = AppRoleOpenBaoTokenProvider(
                url=base_url,
                role_id=exporter_role_id,
                secret_id_file=exporter_secret_id_file,
                timeout=3,
            )
            exporter_signer = OpenBaoTransitSigner(
                url=base_url,
                token_provider=exporter_provider,
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
                url=base_url,
                token_provider=exporter_provider,
                timeout=3,
            )
            try:
                exporter_store.resolve_credential(
                    "cred_approle_verification",
                    stored.secret_ref,
                    stored.binding_proof,
                    binding,
                )
            except CredentialStoreUnavailable:
                exporter_credential_read_denied = True
            else:
                exporter_credential_read_denied = False
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    results = {
        "openbao_version": subprocess.run(
            [bao, "version"], capture_output=True, text=True, check=True
        ).stdout.split()[1],
        "authentication": "approle_short_lived_token",
        "secret_id_delivery": "read_only_file",
        "api_credential_round_trip": api_credential_round_trip,
        "api_signature_created": api_signature_created,
        "api_reauthentication_succeeded": api_reauthentication_succeeded,
        "exporter_public_key_read": exporter_public_key_read,
        "exporter_signing_denied": exporter_signing_denied,
        "exporter_credential_read_denied": exporter_credential_read_denied,
    }
    if not all(value is True for value in list(results.values())[3:]):
        raise RuntimeError("OpenBao AppRole verification failed")
    print(json.dumps(results, separators=(",", ":")))


if __name__ == "__main__":
    main()
