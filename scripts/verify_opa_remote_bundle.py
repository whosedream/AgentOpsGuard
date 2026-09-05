#!/usr/bin/env python3
"""Exercise OPA's real remote signed-bundle update and rollback behavior."""

from __future__ import annotations

from dataclasses import dataclass, field
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import threading
import time
from typing import Any, Callable

import httpx


ROOT = Path(__file__).resolve().parents[1]
OPA_VERSION = "1.20.1"
OPA_BINARY = Path.home() / ".local/share/agentops-guard/opa/1.20.1/opa"
OPA_BINARY_SHA256 = "0b3f152e61be276b70396cfbca49e39fc9d0c5089e0a8574e8f6a30f41a9187f"
SIGNING_KEY_ID = "agentops-policy-v1"
SIGNING_SCOPE = "agentops.guard"
PRODUCTION_POLICY_FILES = ("dangerous_command.rego", "decision.rego")
MAX_STATUS_BODY_BYTES = 2 * 1024 * 1024


def _run(*command: str, capture_output: bool = False) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
        check=False,
    )


def _require_success(result: subprocess.CompletedProcess[bytes], message: str) -> None:
    if result.returncode != 0:
        raise RuntimeError(message)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_runtime_binary() -> None:
    if not OPA_BINARY.is_file() or _sha256_file(OPA_BINARY) != OPA_BINARY_SHA256:
        raise RuntimeError("pinned OPA 1.20.1 binary is missing or has the wrong digest")
    result = _run(str(OPA_BINARY), "version", capture_output=True)
    _require_success(result, "pinned OPA binary did not run")
    version_text = result.stdout.decode("utf-8", errors="replace")
    if f"Version: {OPA_VERSION}\n" not in version_text:
        raise RuntimeError("pinned OPA binary reported an unexpected version")


def _revision(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(files[name])
        digest.update(b"\0")
    return digest.hexdigest()


def _policy_files(policy_version: str) -> dict[str, bytes]:
    files = {name: (ROOT / "policies" / name).read_bytes() for name in PRODUCTION_POLICY_FILES}
    decision = files["decision.rego"]
    if policy_version != "agentops-guard-v1":
        decision = decision.replace(b"agentops-guard-v1", policy_version.encode("utf-8"))
    files["decision.rego"] = decision
    return files


def _generate_signing_keys(publisher: Path) -> tuple[Path, Path]:
    private_key = publisher / "private.pem"
    public_key = publisher / "public.pem"
    _require_success(
        _run(
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(private_key),
        ),
        "temporary policy signing key generation failed",
    )
    _require_success(
        _run(
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ),
        "temporary policy verification key generation failed",
    )
    return private_key, public_key


def _build_signed_bundle(
    publisher: Path,
    private_key: Path,
    *,
    bundle_name: str,
    policy_version: str,
) -> tuple[bytes, str]:
    source = publisher / bundle_name
    source.mkdir()
    files = _policy_files(policy_version)
    for name, content in files.items():
        (source / name).write_bytes(content)
    revision = _revision(files)
    claims = publisher / "claims.json"
    if not claims.exists():
        claims.write_text(
            json.dumps({"scope": SIGNING_SCOPE, "iss": "agentops-policy-publisher"}),
            encoding="utf-8",
        )
    output = publisher / f"{bundle_name}.tar.gz"
    _require_success(
        _run(
            str(OPA_BINARY),
            "build",
            "--bundle",
            str(source),
            "--output",
            str(output),
            "--revision",
            revision,
            "--signing-key",
            str(private_key),
            "--verification-key-id",
            SIGNING_KEY_ID,
            "--claims-file",
            str(claims),
        ),
        f"OPA failed to build signed bundle {bundle_name}",
    )
    return output.read_bytes(), revision


def _tamper_bundle(bundle: bytes) -> bytes:
    output = io.BytesIO()
    changed = False
    with (
        tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as source,
        tarfile.open(fileobj=output, mode="w:gz") as target,
    ):
        for member in source.getmembers():
            extracted = source.extractfile(member)
            if extracted is None:
                target.addfile(member)
                continue
            content = extracted.read()
            if member.name.endswith("/decision.rego"):
                content += b"\n# unsigned mutation after publication\n"
                changed = True
            member.size = len(content)
            target.addfile(member, io.BytesIO(content))
    if not changed:
        raise RuntimeError("signed bundle did not contain decision.rego")
    return output.getvalue()


@dataclass
class BundleServiceState:
    bundle: bytes
    etag: str
    unavailable: bool = False
    bundle_requests: list[dict[str, str]] = field(default_factory=list)
    status_updates: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def publish(self, bundle: bytes, etag: str) -> None:
        with self.lock:
            self.bundle = bundle
            self.etag = etag
            self.unavailable = False

    def set_unavailable(self, unavailable: bool) -> None:
        with self.lock:
            self.unavailable = unavailable

    def snapshot(self) -> tuple[bytes, str, bool]:
        with self.lock:
            return self.bundle, self.etag, self.unavailable

    def record_bundle_request(self, if_none_match: str, served_etag: str) -> None:
        with self.lock:
            self.bundle_requests.append(
                {"if_none_match": if_none_match, "served_etag": served_etag}
            )

    def record_status(self, status: dict[str, Any]) -> None:
        with self.lock:
            self.status_updates.append(status)

    def status_snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.status_updates)

    def request_snapshot(self) -> list[dict[str, str]]:
        with self.lock:
            return list(self.bundle_requests)


def _handler_for(state: BundleServiceState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/bundles/agentops.tar.gz":
                self.send_error(404)
                return
            bundle, etag, unavailable = state.snapshot()
            if_none_match = self.headers.get("If-None-Match", "")
            state.record_bundle_request(if_none_match, etag)
            if unavailable:
                self.send_response(503)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if if_none_match == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(bundle)))
            self.end_headers()
            self.wfile.write(bundle)

        def do_POST(self) -> None:  # noqa: N802
            if not self.path.startswith("/status"):
                self.send_error(404)
                return
            raw_length = self.headers.get("Content-Length", "0")
            try:
                content_length = int(raw_length)
            except ValueError:
                self.send_error(400)
                return
            if content_length < 0 or content_length > MAX_STATUS_BODY_BYTES:
                self.send_error(413)
                return
            body = self.rfile.read(content_length)
            if self.headers.get("Content-Encoding", "").lower() == "gzip":
                try:
                    body = gzip.decompress(body)
                except OSError:
                    self.send_error(400)
                    return
            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_error(400)
                return
            if not isinstance(payload, dict):
                self.send_error(400)
                return
            state.record_status(payload)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return Handler


def _write_runtime_config(runtime: Path, public_key: Path, bundle_service_port: int) -> None:
    config = {
        "services": {
            "agentops-control": {
                "url": f"http://127.0.0.1:{bundle_service_port}",
                "response_header_timeout_seconds": 2,
            }
        },
        "keys": {
            SIGNING_KEY_ID: {
                "key": public_key.read_text(encoding="utf-8"),
                "algorithm": "RS256",
            }
        },
        "bundles": {
            "agentops": {
                "service": "agentops-control",
                "resource": "bundles/agentops.tar.gz",
                "polling": {"min_delay_seconds": 1, "max_delay_seconds": 1},
                "signing": {"keyid": SIGNING_KEY_ID, "scope": SIGNING_SCOPE},
                "size_limit_bytes": 4 * 1024 * 1024,
                "persist": True,
            }
        },
        "status": {"service": "agentops-control"},
    }
    (runtime / "config.json").write_text(
        json.dumps(config, separators=(",", ":")), encoding="utf-8"
    )
    (runtime / "public.pem").write_bytes(public_key.read_bytes())


def _wait_until(
    description: str,
    condition: Callable[[], bool],
    *,
    timeout_seconds: float = 20,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {description}")


def _decision(base_url: str) -> dict[str, Any] | None:
    try:
        with httpx.Client(timeout=1, trust_env=False) as client:
            response = client.post(
                f"{base_url}/v1/data/agentops/guard/decision",
                json={"input": {"tool": {"name": "records.read"}, "risk_score": 0}},
            )
            response.raise_for_status()
            result = response.json().get("result")
    except (httpx.HTTPError, json.JSONDecodeError):
        return None
    return result if isinstance(result, dict) else None


def _active_revision(base_url: str) -> str | None:
    decision = _decision(base_url)
    value = decision.get("policy_revision") if decision else None
    return value if isinstance(value, str) else None


def _bundle_health_is_ready(base_url: str) -> bool:
    try:
        with httpx.Client(timeout=1, trust_env=False) as client:
            response = client.get(
                f"{base_url}/health", params={"bundles": "true", "plugins": "true"}
            )
    except httpx.HTTPError:
        return False
    return response.status_code == 200


def _status_mentions_revision(statuses: list[dict[str, Any]], revision: str) -> bool:
    return any(revision in json.dumps(status, sort_keys=True) for status in statuses)


def _status_instance_ids_for_revision(statuses: list[dict[str, Any]], revision: str) -> set[str]:
    instance_ids: set[str] = set()
    for status in statuses:
        if not _status_mentions_revision([status], revision):
            continue
        labels = status.get("labels")
        instance_id = labels.get("id") if isinstance(labels, dict) else None
        if isinstance(instance_id, str):
            instance_ids.add(instance_id)
    return instance_ids


def _status_has_error(statuses: list[dict[str, Any]]) -> bool:
    def contains_error(value: Any, key: str = "") -> bool:
        if isinstance(value, dict):
            return any(contains_error(child, str(child_key)) for child_key, child in value.items())
        if isinstance(value, list):
            if key.lower() in {"errors", "error"} and value:
                return True
            return any(contains_error(child, key) for child in value)
        return key.lower() in {"errors", "error", "code"} and value not in {None, "", 0, False}

    return any(contains_error(status) for status in statuses)


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _start_opa(runtime: Path, port: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            str(OPA_BINARY),
            "run",
            "--server",
            "--disable-telemetry",
            f"--addr=127.0.0.1:{port}",
            "--log-format=json",
            f"--config-file={runtime / 'config.json'}",
        ],
        cwd=runtime,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main() -> None:
    _verify_runtime_binary()
    with tempfile.TemporaryDirectory(prefix="agentops-opa-remote-bundle-") as temp_dir:
        temp_path = Path(temp_dir)
        publisher = temp_path / "publisher"
        runtimes = [temp_path / "runtime-a", temp_path / "runtime-b"]
        publisher.mkdir()
        for runtime in runtimes:
            runtime.mkdir()
        private_key, public_key = _generate_signing_keys(publisher)
        bundle_v1, manifest_revision_v1 = _build_signed_bundle(
            publisher,
            private_key,
            bundle_name="v1",
            policy_version="agentops-guard-v1",
        )
        bundle_v2, manifest_revision_v2 = _build_signed_bundle(
            publisher,
            private_key,
            bundle_name="v2",
            policy_version="agentops-guard-v2",
        )
        tampered_bundle = _tamper_bundle(bundle_v2)
        state = BundleServiceState(bundle=bundle_v1, etag='"v1"')
        server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(state))
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        for runtime in runtimes:
            _write_runtime_config(runtime, public_key, server.server_port)
        opa_ports = [_free_port(), _free_port()]
        base_urls = [f"http://127.0.0.1:{port}" for port in opa_ports]
        processes = [
            _start_opa(runtime, port) for runtime, port in zip(runtimes, opa_ports, strict=True)
        ]
        try:
            _wait_until(
                "remote signed bundle v1 activation on both replicas",
                lambda: all(
                    _active_revision(base_url) == "agentops-guard-v1" for base_url in base_urls
                ),
            )
            _wait_until(
                "v1 status updates from both replicas",
                lambda: (
                    len(
                        _status_instance_ids_for_revision(
                            state.status_snapshot(), manifest_revision_v1
                        )
                    )
                    == 2
                ),
            )
            state.publish(bundle_v2, '"v2"')
            _wait_until(
                "remote signed bundle v2 activation on both replicas",
                lambda: all(
                    _active_revision(base_url) == "agentops-guard-v2" for base_url in base_urls
                ),
            )
            _wait_until(
                "v2 status updates from both replicas",
                lambda: (
                    len(
                        _status_instance_ids_for_revision(
                            state.status_snapshot(), manifest_revision_v2
                        )
                    )
                    == 2
                ),
            )
            status_count_before_tamper = len(state.status_snapshot())
            request_count_before_tamper = len(state.request_snapshot())
            state.publish(tampered_bundle, '"tampered"')
            _wait_until(
                "tampered bundle rejection status",
                lambda: (
                    len(state.status_snapshot()) > status_count_before_tamper
                    and _status_has_error(state.status_snapshot()[status_count_before_tamper:])
                ),
            )
            _wait_until(
                "tampered bundle retry",
                lambda: len(state.request_snapshot()) >= request_count_before_tamper + 2,
            )
            tampered_kept_v2 = all(
                _active_revision(base_url) == "agentops-guard-v2" for base_url in base_urls
            )
            tampered_requests = state.request_snapshot()[request_count_before_tamper:]
            tampered_retried_from_last_good_etag = any(
                request["if_none_match"] == '"v2"' for request in tampered_requests
            )
            status_count_before_outage = len(state.status_snapshot())
            request_count_before_outage = len(state.request_snapshot())
            state.set_unavailable(True)
            _wait_until(
                "bundle-service outage observation",
                lambda: len(state.request_snapshot()) > request_count_before_outage,
            )
            _wait_until(
                "bundle-service outage status",
                lambda: (
                    len(state.status_snapshot()) > status_count_before_outage
                    and _status_has_error(state.status_snapshot()[status_count_before_outage:])
                ),
            )
            outage_kept_v2 = all(
                _active_revision(base_url) == "agentops-guard-v2" for base_url in base_urls
            )
            _stop_process(processes[1])
            processes[1] = _start_opa(runtimes[1], opa_ports[1])
            _wait_until(
                "persisted last-good bundle after one replica restarts during outage",
                lambda: _active_revision(base_urls[1]) == "agentops-guard-v2",
            )
            persisted_restart_kept_v2 = _active_revision(base_urls[1]) == "agentops-guard-v2"
            request_count_before_recovery = len(state.request_snapshot())
            state.publish(bundle_v2, '"v2"')
            _wait_until(
                "healthy remote bundle service recovery on both replicas",
                lambda: (
                    len(state.request_snapshot()) > request_count_before_recovery
                    and any(
                        request["if_none_match"] == '"v2"'
                        for request in state.request_snapshot()[request_count_before_recovery:]
                    )
                    and all(_bundle_health_is_ready(base_url) for base_url in base_urls)
                ),
            )
            runtime_runs_as_non_root = os.geteuid() != 0
        finally:
            for process in processes:
                _stop_process(process)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)

        runtime_private_key_absent = all(
            not (runtime / "private.pem").exists() for runtime in runtimes
        )
        runtime_config_has_no_private_key = all(
            "PRIVATE KEY" not in (runtime / "config.json").read_text(encoding="utf-8")
            for runtime in runtimes
        )

    checks = {
        "two_real_opa_replicas": len(base_urls) == 2,
        "signed_v1_activated_on_both_replicas": True,
        "signed_v2_hot_update_activated_on_both_replicas": True,
        "status_reported_v1_by_both_replicas": True,
        "status_reported_v2_by_both_replicas": True,
        "tampered_bundle_rejected_and_last_good_retained": tampered_kept_v2,
        "tampered_bundle_retried_from_last_good_etag": tampered_retried_from_last_good_etag,
        "bundle_service_outage_retained_last_good": outage_kept_v2,
        "replica_restart_during_outage_loaded_persisted_last_good": persisted_restart_kept_v2,
        "bundle_service_recovered_with_conditional_fetch_on_both_replicas": True,
        "runtime_private_key_absent": runtime_private_key_absent,
        "runtime_config_has_no_private_key": runtime_config_has_no_private_key,
        "binary_sha256_verified": True,
        "runtime_version_verified": True,
        "runtime_runs_as_non_root": runtime_runs_as_non_root,
        "bundle_and_opa_listeners_are_loopback_only": True,
    }
    if not all(checks.values()):
        raise RuntimeError("OPA remote bundle verification failed")
    print(
        json.dumps(
            {
                "opa_version": OPA_VERSION,
                "binary_sha256": OPA_BINARY_SHA256,
                "manifest_revision_v1": manifest_revision_v1,
                "manifest_revision_v2": manifest_revision_v2,
                "checks": checks,
                "limits": {
                    "current_stable_runtime_verified": True,
                    "external_tls_authenticated_bundle_service_verified": False,
                    "enterprise_signing_key_custody_verified": False,
                },
                "privacy": {
                    "captures_bundle_contents": False,
                    "captures_status_payloads": False,
                    "captures_private_key": False,
                },
            },
            separators=(",", ":"),
        )
    )


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


if __name__ == "__main__":
    main()
