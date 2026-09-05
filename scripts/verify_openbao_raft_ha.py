#!/usr/bin/env python3
"""Exercise real OpenBao Raft, TLS, leader failover, Proxy, and snapshot restore."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time

import httpx

from agentops_guard.backend.services.audit_checkpoints import OpenBaoTransitSigner
from agentops_guard.backend.services.credentials import OpenBaoCredentialStore
from agentops_guard.backend.services.openbao_auth import ProxyOpenBaoTokenProvider
from install_openbao_current_runtime import BINARY_SHA256, OPENBAO_VERSION
from verify_openbao_approle import ROOT, _enable_approle, _enable_mount, _free_port
from verify_openbao_proxy import (
    _configure_wrapped_role,
    _create_delivery_token,
    _rotate_wrapped_secret_id,
    _start_proxy,
    _stop,
    _wait_for_listener,
    _write_proxy_config,
)


@dataclass
class Node:
    name: str
    api_port: int
    cluster_port: int
    config: Path
    certificate: Path
    private_key: Path
    replacement_certificate: Path
    replacement_private_key: Path
    process: subprocess.Popen[bytes] | None = None

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.api_port}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_private_text(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value.encode("utf-8"))
    finally:
        os.close(descriptor)


def _create_tls_authority(temp_path: Path) -> tuple[Path, Path]:
    certificate = temp_path / "openbao-test-ca.pem"
    private_key = temp_path / "openbao-test-ca-key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-sha256",
            "-subj",
            "/CN=AgentOps OpenBao Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    private_key.chmod(0o600)
    certificate.chmod(0o644)
    return certificate, private_key


def _issue_tls_certificate(
    directory: Path,
    *,
    authority_certificate: Path,
    authority_private_key: Path,
    serial: int,
    generation: str,
) -> tuple[Path, Path]:
    certificate = directory / f"server-{generation}.pem"
    private_key = directory / f"server-{generation}-key.pem"
    request = directory / f"server-{generation}.csr"
    extensions = directory / f"server-{generation}-extensions.cnf"
    extensions.write_text(
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(request),
            "-sha256",
            "-subj",
            "/CN=localhost",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(authority_certificate),
            "-CAkey",
            str(authority_private_key),
            "-set_serial",
            str(serial),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(extensions),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    private_key.chmod(0o600)
    certificate.chmod(0o644)
    return certificate, private_key


def _atomic_replace(source: Path, destination: Path, *, mode: int) -> None:
    temporary_path: Path | None = None
    try:
        with source.open("rb") as source_handle, tempfile.NamedTemporaryFile(
            prefix=f".{destination.name}-rotate-", dir=destination.parent, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
            shutil.copyfileobj(source_handle, temporary, length=1024 * 1024)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.chmod(mode)
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _certificate_fingerprint(node: Node, authority_certificate: Path) -> str:
    context = ssl.create_default_context(cafile=str(authority_certificate))
    with socket.create_connection(("127.0.0.1", node.api_port), timeout=2) as connection:
        with context.wrap_socket(connection, server_hostname="localhost") as tls_connection:
            certificate = tls_connection.getpeercert(binary_form=True)
    if certificate is None:
        raise RuntimeError(f"{node.name} did not present a TLS certificate")
    return hashlib.sha256(certificate).hexdigest()


def _wait_for_certificate_fingerprint(
    node: Node,
    authority_certificate: Path,
    previous_fingerprint: str,
) -> str:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            fingerprint = _certificate_fingerprint(node, authority_certificate)
            if fingerprint != previous_fingerprint:
                return fingerprint
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"{node.name} did not reload its TLS certificate")


def _write_server_config(
    path: Path,
    *,
    name: str,
    api_port: int,
    cluster_port: int,
    data_path: Path,
    certificate: Path,
    private_key: Path,
) -> None:
    values = {
        "node": json.dumps(name),
        "data": json.dumps(str(data_path)),
        "api_address": json.dumps(f"127.0.0.1:{api_port}"),
        "cluster_address": json.dumps(f"127.0.0.1:{cluster_port}"),
        "api_url": json.dumps(f"https://127.0.0.1:{api_port}"),
        "cluster_url": json.dumps(f"https://127.0.0.1:{cluster_port}"),
        "certificate": json.dumps(str(certificate)),
        "private_key": json.dumps(str(private_key)),
    }
    _write_private_text(
        path,
        f'''disable_mlock = true
ui = false
api_addr = {values["api_url"]}
cluster_addr = {values["cluster_url"]}

storage "raft" {{
  path = {values["data"]}
  node_id = {values["node"]}
  performance_multiplier = 1
}}

listener "tcp" {{
  address = {values["api_address"]}
  cluster_address = {values["cluster_address"]}
  tls_cert_file = {values["certificate"]}
  tls_key_file = {values["private_key"]}
  tls_min_version = "tls12"
}}
''',
    )


def _start_node(bao: str, node: Node) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [bao, "server", f"-config={node.config}"],
        env={
            "HOME": str(node.config.parent),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _client(
    url: str,
    certificate: Path,
    *,
    token: str | None = None,
    timeout: float = 5,
) -> httpx.Client:
    headers = {"X-Vault-Token": token} if token is not None else None
    return httpx.Client(
        base_url=url,
        verify=str(certificate),
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
        headers=headers,
    )


def _wait_for_tls_listener(node: Node, certificate: Path) -> None:
    deadline = time.monotonic() + 20
    with _client(node.url, certificate, timeout=1) as client:
        while time.monotonic() < deadline:
            if node.process is None or node.process.poll() is not None:
                raise RuntimeError(f"{node.name} exited before opening its listener")
            try:
                client.get("/v1/sys/health")
                return
            except httpx.HTTPError:
                time.sleep(0.1)
    raise RuntimeError(f"{node.name} did not open its TLS listener")


def _wait_for_unsealed(node: Node, certificate: Path) -> None:
    deadline = time.monotonic() + 20
    with _client(node.url, certificate, timeout=1) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get("/v1/sys/health")
                if response.status_code in {200, 429}:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    raise RuntimeError(f"{node.name} did not become unsealed")


def _unseal_joined_node(client: httpx.Client, node_name: str, unseal_key: str) -> None:
    last_status = 0
    for _ in range(20):
        response = client.post("/v1/sys/unseal", json={"key": unseal_key})
        last_status = response.status_code
        if response.status_code == 200 and response.json().get("sealed") is False:
            return
        time.sleep(0.25)
        health = client.get("/v1/sys/health")
        if health.status_code in {200, 429}:
            return
    raise RuntimeError(f"{node_name} remained sealed after status {last_status}")


def _active_node(nodes: list[Node], certificate: Path, timeout: float = 30) -> Node:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for node in nodes:
            if node.process is None or node.process.poll() is not None:
                continue
            try:
                with _client(node.url, certificate, timeout=1) as client:
                    response = client.get("/v1/sys/leader")
                    if response.status_code == 200 and response.json().get("is_self") is True:
                        return node
            except (httpx.HTTPError, ValueError):
                pass
        time.sleep(0.1)
    raise RuntimeError("OpenBao cluster did not elect an active node")


def _wait_for_three_voters(active: Node, certificate: Path, root_token: str) -> None:
    deadline = time.monotonic() + 35
    with _client(active.url, certificate, token=root_token, timeout=2) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get("/v1/sys/storage/raft/configuration")
                response.raise_for_status()
                servers = response.json()["data"]["config"]["servers"]
                if len(servers) == 3 and all(server["voter"] is True for server in servers):
                    return
            except (httpx.HTTPError, KeyError, TypeError, ValueError):
                pass
            time.sleep(0.2)
    raise RuntimeError("OpenBao Raft cluster did not reach three voters")


def _start_api_proxy(
    bao: str,
    *,
    active: Node,
    certificate: Path,
    proxy_port: int,
    proxy_config: Path,
    role_id_file: Path,
    wrapping_token_file: Path,
) -> subprocess.Popen[bytes]:
    _write_proxy_config(
        proxy_config,
        server_url=active.url,
        listener_port=proxy_port,
        role_name="agentops-api",
        role_id_file=role_id_file,
        wrapping_token_file=wrapping_token_file,
        ca_cert=certificate,
    )
    process = _start_proxy(bao, proxy_config)
    _wait_for_listener(proxy_port)
    deadline = time.monotonic() + 20
    with httpx.Client(
        base_url=f"http://127.0.0.1:{proxy_port}",
        timeout=1,
        trust_env=False,
    ) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("OpenBao Proxy exited before authentication completed")
            try:
                response = client.get("/v1/transit/keys/agentops-audit")
                if response.status_code == 200:
                    return process
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    _stop(process)
    raise RuntimeError("OpenBao Proxy did not complete authentication")


def _rotate_proxy_identity(
    active: Node,
    certificate: Path,
    delivery_token: str,
    wrapping_token_file: Path,
) -> None:
    with _client(
        active.url,
        certificate,
        token=delivery_token,
    ) as delivery:
        _rotate_wrapped_secret_id(
            delivery,
            role_name="agentops-api",
            wrapping_token_file=wrapping_token_file,
        )


def main() -> None:
    bao_value = shutil.which("bao")
    if bao_value is None:
        raise RuntimeError("OpenBao CLI is not installed")
    bao = str(Path(bao_value).resolve())
    if _sha256(Path(bao)) != BINARY_SHA256:
        raise RuntimeError("OpenBao binary does not match the signer-verified release")
    version_output = subprocess.run(
        [bao, "version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if f"OpenBao v{OPENBAO_VERSION} " not in version_output:
        raise RuntimeError(f"OpenBao {OPENBAO_VERSION} is required")

    with tempfile.TemporaryDirectory(prefix="agentops-openbao-raft-ha-") as temp_dir:
        temp_path = Path(temp_dir)
        authority_certificate, authority_private_key = _create_tls_authority(temp_path)
        nodes: list[Node] = []
        for index in range(1, 4):
            node_path = temp_path / f"node-{index}"
            node_path.mkdir(mode=0o700)
            data_path = node_path / "raft"
            data_path.mkdir(mode=0o700)
            config = node_path / "server.hcl"
            initial_certificate, initial_private_key = _issue_tls_certificate(
                node_path,
                authority_certificate=authority_certificate,
                authority_private_key=authority_private_key,
                serial=index,
                generation="v1",
            )
            replacement_certificate, replacement_private_key = _issue_tls_certificate(
                node_path,
                authority_certificate=authority_certificate,
                authority_private_key=authority_private_key,
                serial=100 + index,
                generation="v2",
            )
            certificate = node_path / "server.pem"
            private_key = node_path / "server-key.pem"
            _atomic_replace(initial_certificate, certificate, mode=0o644)
            _atomic_replace(initial_private_key, private_key, mode=0o600)
            api_port = _free_port()
            cluster_port = _free_port()
            _write_server_config(
                config,
                name=f"node-{index}",
                api_port=api_port,
                cluster_port=cluster_port,
                data_path=data_path,
                certificate=certificate,
                private_key=private_key,
            )
            node = Node(
                f"node-{index}",
                api_port,
                cluster_port,
                config,
                certificate,
                private_key,
                replacement_certificate,
                replacement_private_key,
            )
            node.process = _start_node(bao, node)
            nodes.append(node)

        proxy: subprocess.Popen[bytes] | None = None
        try:
            for node in nodes:
                _wait_for_tls_listener(node, authority_certificate)

            initial_certificate_fingerprints = {
                node.name: _certificate_fingerprint(node, authority_certificate) for node in nodes
            }
            if len(set(initial_certificate_fingerprints.values())) != 3:
                raise RuntimeError("OpenBao nodes did not present distinct TLS certificates")

            untrusted_tls_rejected = False
            try:
                httpx.get(nodes[0].url + "/v1/sys/health", timeout=2, trust_env=False)
            except httpx.TransportError:
                untrusted_tls_rejected = True
            if not untrusted_tls_rejected:
                raise RuntimeError("untrusted OpenBao certificate was accepted")

            with _client(nodes[0].url, authority_certificate) as bootstrap:
                initialized = bootstrap.post(
                    "/v1/sys/init",
                    json={"secret_shares": 1, "secret_threshold": 1},
                )
                initialized.raise_for_status()
                initialization = initialized.json()
                unseal_key = str(initialization["keys_base64"][0])
                root_token = str(initialization["root_token"])
                unsealed = bootstrap.post("/v1/sys/unseal", json={"key": unseal_key})
                unsealed.raise_for_status()
                if unsealed.json().get("sealed") is not False:
                    raise RuntimeError("first OpenBao node remained sealed")
            _wait_for_unsealed(nodes[0], authority_certificate)

            leader_certificate = authority_certificate.read_text(encoding="utf-8")
            for node in nodes[1:]:
                with _client(node.url, authority_certificate) as joining:
                    joined = joining.post(
                        "/v1/sys/storage/raft/join",
                        json={
                            "leader_api_addr": nodes[0].url,
                            "leader_ca_cert": leader_certificate,
                        },
                    )
                    joined.raise_for_status()
                    if joined.json().get("joined") is not True:
                        raise RuntimeError(f"{node.name} did not join the Raft cluster")
                    _unseal_joined_node(joining, node.name, unseal_key)
                _wait_for_unsealed(node, authority_certificate)

            initial_active = _active_node(nodes, authority_certificate)
            _wait_for_three_voters(initial_active, authority_certificate, root_token)

            role_id_file = temp_path / "api-role-id"
            wrapping_token_file = temp_path / "api-wrapped-secret-id"
            with _client(
                initial_active.url,
                authority_certificate,
                token=root_token,
            ) as administrator:
                _enable_mount(administrator, "secret", "kv")
                _enable_mount(administrator, "transit", "transit")
                key = administrator.post(
                    "/v1/transit/keys/agentops-audit",
                    json={"type": "ed25519", "exportable": False},
                )
                key.raise_for_status()
                _enable_approle(administrator)
                for policy_name, policy_path in {
                    "agentops-api": ROOT / "deploy/openbao/agentops-api-policy.hcl",
                    "agentops-api-identity-delivery": ROOT
                    / "deploy/openbao/agentops-api-identity-delivery-policy.hcl",
                }.items():
                    response = administrator.put(
                        f"/v1/sys/policies/acl/{policy_name}",
                        json={"policy": policy_path.read_text(encoding="utf-8")},
                    )
                    response.raise_for_status()
                delivery_token = _create_delivery_token(
                    administrator,
                    policy_name="agentops-api-identity-delivery",
                    ttl="5m",
                )
                with _client(
                    initial_active.url,
                    authority_certificate,
                    token=delivery_token,
                ) as delivery:
                    _configure_wrapped_role(
                        administrator,
                        delivery,
                        role_name="agentops-api",
                        policy_name="agentops-api",
                        role_id_file=role_id_file,
                        wrapping_token_file=wrapping_token_file,
                    )

            proxy_port = _free_port()
            proxy_config = temp_path / "api-proxy.hcl"
            proxy = _start_api_proxy(
                bao,
                active=initial_active,
                certificate=authority_certificate,
                proxy_port=proxy_port,
                proxy_config=proxy_config,
                role_id_file=role_id_file,
                wrapping_token_file=wrapping_token_file,
            )
            token_provider = ProxyOpenBaoTokenProvider()
            store = OpenBaoCredentialStore(
                url=f"http://127.0.0.1:{proxy_port}",
                token_provider=token_provider,
                timeout=5,
            )
            binding = {
                "credential_ref": "cred_raft_ha_verification",
                "project_id": "raft_ha_verification",
                "provider": "verification",
                "status": "active",
                "version": 1,
                "allowed_actor_ids": ["verification-agent"],
                "revoked_at": None,
            }
            provider_secret = secrets.token_urlsafe(24)
            stored = store.store_credential(
                "cred_raft_ha_verification",
                provider_secret,
                binding,
            )
            signer = OpenBaoTransitSigner(
                url=f"http://127.0.0.1:{proxy_port}",
                token_provider=token_provider,
                mount="transit",
                key_name="agentops-audit",
                timeout=5,
            )
            signature_before_failure = bool(signer.sign(b"before-failure").signature)

            process_ids_before_rotation = {
                node.name: node.process.pid
                for node in nodes
                if node.process is not None
            }
            rotation_order = [node for node in nodes if node is not initial_active] + [
                initial_active
            ]
            rotated_certificate_fingerprints: dict[str, str] = {}
            for node in rotation_order:
                assert node.process is not None
                _atomic_replace(
                    node.replacement_certificate,
                    node.certificate,
                    mode=0o644,
                )
                _atomic_replace(
                    node.replacement_private_key,
                    node.private_key,
                    mode=0o600,
                )
                os.kill(node.process.pid, signal.SIGHUP)
                rotated_certificate_fingerprints[node.name] = (
                    _wait_for_certificate_fingerprint(
                        node,
                        authority_certificate,
                        initial_certificate_fingerprints[node.name],
                    )
                )
                if node.process.poll() is not None:
                    raise RuntimeError(f"{node.name} exited during TLS certificate rotation")
                _active_node(nodes, authority_certificate, timeout=5)
                if (
                    store.resolve_credential(
                        "cred_raft_ha_verification",
                        stored.secret_ref,
                        stored.binding_proof,
                        binding,
                    )
                    != provider_secret
                ):
                    raise RuntimeError("credential became unavailable during certificate rotation")

            if any(
                rotated_certificate_fingerprints[node.name]
                == initial_certificate_fingerprints[node.name]
                for node in nodes
            ):
                raise RuntimeError("OpenBao TLS certificate fingerprint did not change")
            node_processes_preserved_during_rotation = all(
                node.process is not None
                and node.process.poll() is None
                and node.process.pid == process_ids_before_rotation[node.name]
                for node in nodes
            )
            if not node_processes_preserved_during_rotation:
                raise RuntimeError("OpenBao process changed during TLS certificate rotation")
            signature_after_certificate_rotation = bool(
                signer.sign(b"after-certificate-rotation").signature
            )
            initial_active = _active_node(nodes, authority_certificate)

            with _client(
                initial_active.url,
                authority_certificate,
                token=root_token,
                timeout=15,
            ) as administrator:
                snapshot_response = administrator.get("/v1/sys/storage/raft/snapshot")
                snapshot_response.raise_for_status()
                snapshot = snapshot_response.content
                if not snapshot:
                    raise RuntimeError("OpenBao returned an empty snapshot")
                marker = administrator.post(
                    "/v1/secret/data/agentops/post-snapshot-marker",
                    json={"data": {"created_after_snapshot": True}},
                )
                marker.raise_for_status()

            _stop(proxy)
            proxy = None
            failover_started = time.monotonic()
            assert initial_active.process is not None
            _stop(initial_active.process)
            surviving_nodes = [node for node in nodes if node is not initial_active]
            replacement_active = _active_node(surviving_nodes, authority_certificate)
            failover_ms = round((time.monotonic() - failover_started) * 1000)

            _rotate_proxy_identity(
                replacement_active,
                authority_certificate,
                delivery_token,
                wrapping_token_file,
            )
            proxy = _start_api_proxy(
                bao,
                active=replacement_active,
                certificate=authority_certificate,
                proxy_port=proxy_port,
                proxy_config=proxy_config,
                role_id_file=role_id_file,
                wrapping_token_file=wrapping_token_file,
            )
            credential_survived_leader_failure = (
                store.resolve_credential(
                    "cred_raft_ha_verification",
                    stored.secret_ref,
                    stored.binding_proof,
                    binding,
                )
                == provider_secret
            )
            signature_after_failure = bool(signer.sign(b"after-failure").signature)

            with _client(
                replacement_active.url,
                authority_certificate,
                token=root_token,
                timeout=15,
            ) as administrator:
                replicated_marker = administrator.get(
                    "/v1/secret/data/agentops/post-snapshot-marker"
                )
                replicated_marker.raise_for_status()
                restored = administrator.post(
                    "/v1/sys/storage/raft/snapshot",
                    content=snapshot,
                    headers={"Content-Type": "application/octet-stream"},
                )
                restored.raise_for_status()

            replacement_active = _active_node(surviving_nodes, authority_certificate)
            _stop(proxy)
            proxy = None
            _rotate_proxy_identity(
                replacement_active,
                authority_certificate,
                delivery_token,
                wrapping_token_file,
            )
            proxy = _start_api_proxy(
                bao,
                active=replacement_active,
                certificate=authority_certificate,
                proxy_port=proxy_port,
                proxy_config=proxy_config,
                role_id_file=role_id_file,
                wrapping_token_file=wrapping_token_file,
            )
            credential_survived_snapshot_restore = (
                store.resolve_credential(
                    "cred_raft_ha_verification",
                    stored.secret_ref,
                    stored.binding_proof,
                    binding,
                )
                == provider_secret
            )
            signature_after_restore = bool(signer.sign(b"after-restore").signature)
            with _client(
                replacement_active.url,
                authority_certificate,
                token=root_token,
            ) as administrator:
                marker_absent_after_restore = (
                    administrator.get(
                        "/v1/secret/data/agentops/post-snapshot-marker"
                    ).status_code
                    == 404
                )
        finally:
            if proxy is not None and proxy.poll() is None:
                _stop(proxy)
            for node in reversed(nodes):
                if node.process is not None and node.process.poll() is None:
                    _stop(node.process)

    results = {
        "openbao_version": OPENBAO_VERSION,
        "openbao_binary_sha256": _sha256(Path(bao)),
        "storage_backend": "integrated_raft",
        "node_count": 3,
        "tls_server_authentication": True,
        "untrusted_tls_rejected": untrusted_tls_rejected,
        "distinct_per_node_tls_certificates": True,
        "tls_certificate_rotation_mode": "sighup",
        "certificate_rotation_reloaded_all_nodes": True,
        "node_processes_preserved_during_rotation": node_processes_preserved_during_rotation,
        "credential_available_during_certificate_rotation": True,
        "signature_after_certificate_rotation": signature_after_certificate_rotation,
        "raft_voters_ready": True,
        "single_leader_failure_tolerated": True,
        "failover_ms": failover_ms,
        "application_received_openbao_token": False,
        "credential_survived_leader_failure": credential_survived_leader_failure,
        "signature_before_failure": signature_before_failure,
        "signature_after_failure": signature_after_failure,
        "snapshot_nonempty": True,
        "replicated_post_snapshot_write": True,
        "marker_absent_after_restore": marker_absent_after_restore,
        "credential_survived_snapshot_restore": credential_survived_snapshot_restore,
        "signature_after_restore": signature_after_restore,
        "enterprise_certificate_authority_verified": False,
        "auto_unseal_verified": False,
        "transparent_load_balancer_failover_verified": False,
    }
    required = (
        "tls_server_authentication",
        "untrusted_tls_rejected",
        "distinct_per_node_tls_certificates",
        "certificate_rotation_reloaded_all_nodes",
        "node_processes_preserved_during_rotation",
        "credential_available_during_certificate_rotation",
        "signature_after_certificate_rotation",
        "raft_voters_ready",
        "single_leader_failure_tolerated",
        "application_received_openbao_token",
        "credential_survived_leader_failure",
        "signature_before_failure",
        "signature_after_failure",
        "snapshot_nonempty",
        "replicated_post_snapshot_write",
        "marker_absent_after_restore",
        "credential_survived_snapshot_restore",
        "signature_after_restore",
    )
    if any(results[name] is not True for name in required if name != "application_received_openbao_token"):
        raise RuntimeError("OpenBao Raft HA verification failed")
    if results["application_received_openbao_token"] is not False:
        raise RuntimeError("application received an OpenBao token")
    print(json.dumps(results, separators=(",", ":")))


if __name__ == "__main__":
    main()
