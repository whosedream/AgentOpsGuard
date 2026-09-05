#!/usr/bin/env python3
"""Verify the pinned official OPA image against the real AgentOps policy path."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import secrets
import socket
import subprocess
import tarfile
import tempfile
import time
from unittest.mock import patch

import httpx

from agentops_guard.backend.config import Settings
from agentops_guard.backend.schemas import PolicyContext
from agentops_guard.backend.services import opa as opa_service
from agentops_guard.backend.services import policy as policy_service


ROOT = Path(__file__).resolve().parents[1]
OPA_VERSION = "1.8.0"
OPA_IMAGE_DIGEST = "sha256:0917dda453560b65798d3c78caed0376c4db0708f1e4df5724058a5dfd412948"
OPA_IMAGE = f"openpolicyagent/opa@{OPA_IMAGE_DIGEST}"
SIGNING_KEY_ID = "agentops-policy-v1"
SIGNING_SCOPE = "agentops.guard"
PRODUCTION_POLICY_FILES = ("dangerous_command.rego", "decision.rego")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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


def _verify_policy_tests() -> int:
    result = _run(
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--mount",
        f"type=bind,source={ROOT / 'policies'},target=/policies,readonly",
        OPA_IMAGE,
        "test",
        "/policies",
        "--format=json",
        capture_output=True,
    )
    _require_success(result, "OPA rejected the checked-in Rego tests")
    try:
        tests = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        raise RuntimeError("OPA returned an invalid policy test report") from None
    if not isinstance(tests, list) or len(tests) != 3:
        raise RuntimeError("OPA did not execute the expected Rego tests")
    return len(tests)


def _policy_revision() -> str:
    digest = hashlib.sha256()
    for name in PRODUCTION_POLICY_FILES:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update((ROOT / "policies" / name).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _build_signed_bundle(temp_path: Path) -> tuple[Path, str]:
    publisher = temp_path / "publisher"
    source = publisher / "source"
    runtime = temp_path / "runtime"
    source.mkdir(parents=True)
    runtime.mkdir()
    for name in PRODUCTION_POLICY_FILES:
        (source / name).write_bytes((ROOT / "policies" / name).read_bytes())
    revision = _policy_revision()
    (publisher / "claims.json").write_text(
        json.dumps({"scope": SIGNING_SCOPE, "iss": "agentops-policy-publisher"}),
        encoding="utf-8",
    )
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
    _require_success(
        _run(
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--mount",
            f"type=bind,source={publisher},target=/publisher",
            OPA_IMAGE,
            "build",
            "--bundle",
            "/publisher/source",
            "--output",
            "/publisher/bundle.tar.gz",
            "--revision",
            revision,
            "--signing-key",
            "/publisher/private.pem",
            "--verification-key-id",
            SIGNING_KEY_ID,
            "--claims-file",
            "/publisher/claims.json",
        ),
        "OPA failed to build the signed policy bundle",
    )
    (runtime / "bundle.tar.gz").write_bytes((publisher / "bundle.tar.gz").read_bytes())
    (runtime / "public.pem").write_bytes(public_key.read_bytes())
    return runtime, revision


def _create_tampered_bundle(bundle: Path, output: Path) -> None:
    changed = False
    with (
        tarfile.open(bundle, "r:gz") as source,
        tarfile.open(output, "w:gz") as target,
    ):
        for member in source.getmembers():
            extracted = source.extractfile(member)
            if extracted is None:
                target.addfile(member)
                continue
            content = extracted.read()
            if member.name.endswith("/decision.rego"):
                content += b"\n# unauthorized policy change\n"
                changed = True
            member.size = len(content)
            target.addfile(member, io.BytesIO(content))
    if not changed:
        raise RuntimeError("signed policy bundle did not contain the expected policy")


def _tampered_bundle_is_rejected(runtime: Path) -> bool:
    tampered = runtime / "tampered.tar.gz"
    _create_tampered_bundle(runtime / "bundle.tar.gz", tampered)
    result = _run(
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--mount",
        f"type=bind,source={runtime},target=/policy,readonly",
        OPA_IMAGE,
        "run",
        "--bundle",
        "/policy/tampered.tar.gz",
        "--verification-key",
        "/policy/public.pem",
        "--verification-key-id",
        SIGNING_KEY_ID,
        "--scope",
        SIGNING_SCOPE,
    )
    return result.returncode != 0


def _wait_for_health(base_url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 20
    with httpx.Client(timeout=1, trust_env=False) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("OPA container stopped before becoming healthy")
            try:
                response = client.get(
                    f"{base_url}/health",
                    params={"bundles": "true", "plugins": "true"},
                )
                if response.status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    raise RuntimeError("OPA did not become healthy")


def _inspect_container(name: str) -> dict[str, object]:
    result = _run("docker", "inspect", name, capture_output=True)
    _require_success(result, "OPA container inspection failed")
    try:
        inspected = json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        raise RuntimeError("Docker returned invalid OPA inspection data") from None
    return inspected


def _stop_container(name: str, process: subprocess.Popen[bytes]) -> None:
    _run("docker", "rm", "--force", name)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> None:
    policy_test_count = _verify_policy_tests()
    with tempfile.TemporaryDirectory(prefix="agentops-opa-signed-bundle-") as temp_dir:
        runtime, policy_revision = _build_signed_bundle(Path(temp_dir))
        tampered_bundle_rejected = _tampered_bundle_is_rejected(runtime)
        runtime_private_key_absent = not (runtime / "private.pem").exists()
        port = _free_port()
        base_url = f"http://127.0.0.1:{port}"
        container_name = f"agentops-opa-verification-{secrets.token_hex(6)}"
        process = subprocess.Popen(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--publish",
                f"127.0.0.1:{port}:8181",
                "--mount",
                f"type=bind,source={runtime},target=/policy,readonly",
                OPA_IMAGE,
                "run",
                "--server",
                "--disable-telemetry",
                "--addr=0.0.0.0:8181",
                "--log-format=json",
                "--bundle",
                "/policy/bundle.tar.gz",
                "--verification-key",
                "/policy/public.pem",
                "--verification-key-id",
                SIGNING_KEY_ID,
                "--scope",
                SIGNING_SCOPE,
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stopped = False
        try:
            _wait_for_health(base_url, process)
            inspected = _inspect_container(container_name)
            config = inspected["Config"]
            host_config = inspected["HostConfig"]
            mounts = inspected["Mounts"]
            ports = inspected["NetworkSettings"]["Ports"]["8181/tcp"]
            image_runs_as_non_root = str(config["User"]) not in {"", "0", "root", "0:0"}
            read_only_root = host_config["ReadonlyRootfs"] is True
            capabilities_dropped = "ALL" in (host_config["CapDrop"] or [])
            no_new_privileges = "no-new-privileges" in (host_config["SecurityOpt"] or [])
            policy_mount_read_only = any(
                mount["Destination"] == "/policy" and mount["RW"] is False for mount in mounts
            )
            loopback_only = all(binding["HostIp"] == "127.0.0.1" for binding in ports)

            settings = Settings(
                _env_file=None,
                opa_url=base_url,
                opa_timeout_seconds=2,
                policy_fail_mode="closed_for_high_risk",
            )
            with (
                patch.object(opa_service, "get_settings", return_value=settings),
                patch.object(policy_service, "get_settings", return_value=settings),
            ):
                opa_service.check_opa_health()
                low_risk = opa_service.evaluate_opa(
                    {
                        "tool": {"name": "records.read"},
                        "risk_score": 0,
                        "risk_labels": [],
                    }
                )
                high_risk = opa_service.evaluate_opa(
                    {
                        "tool": {"name": "filesystem.write"},
                        "risk_score": 0,
                        "risk_labels": [],
                    }
                )
                dangerous = opa_service.evaluate_opa(
                    {
                        "tool": {"name": "shell.execute", "command": "rm -rf /"},
                        "risk_score": 0,
                        "risk_labels": [],
                    }
                )
                alignment_context = PolicyContext(
                    tool={"name": "mail.send"},
                    data={
                        "action_alignment": {
                            "required": True,
                            "intent_present": True,
                            "action_aligned": True,
                            "target_aligned": False,
                            "aligned": False,
                        }
                    },
                )
                external_decision = opa_service.evaluate_opa(
                    policy_service._redacted_context(alignment_context)
                )
                merged_decision = policy_service.evaluate_policy(alignment_context)

                _stop_container(container_name, process)
                stopped = True
                outage_high_risk = policy_service.evaluate_policy(
                    PolicyContext(tool={"name": "records.read"}, risk_score=0.5)
                )
                outage_low_risk = policy_service.evaluate_policy(
                    PolicyContext(tool={"name": "records.read"}, risk_score=0)
                )
        finally:
            if not stopped:
                _stop_container(container_name, process)

    results = {
        "opa_version": OPA_VERSION,
        "image_digest": OPA_IMAGE_DIGEST,
        "policy_revision": policy_revision,
        "rego_tests_passed": policy_test_count,
        "signed_bundle_accepted": True,
        "tampered_bundle_rejected": tampered_bundle_rejected,
        "runtime_private_key_absent": runtime_private_key_absent,
        "image_runs_as_non_root": image_runs_as_non_root,
        "read_only_root": read_only_root,
        "capabilities_dropped": capabilities_dropped,
        "no_new_privileges": no_new_privileges,
        "policy_mount_read_only": policy_mount_read_only,
        "loopback_only": loopback_only,
        "low_risk_allowed": low_risk.get("action") == "allow",
        "high_risk_requires_approval": high_risk.get("action") == "require_approval",
        "dangerous_command_denied": dangerous.get("action") == "deny",
        "external_allow_cannot_lower_builtin": (
            external_decision.get("action") == "allow"
            and merged_decision.action == "require_approval"
            and merged_decision.reason_code == "tool_target_not_authorized"
        ),
        "high_risk_outage_requires_approval": (
            outage_high_risk.action == "require_approval"
            and outage_high_risk.reason_code == "opa_unavailable"
        ),
        "low_risk_outage_uses_local_policy": outage_low_risk.action == "allow",
    }
    checks = [
        value
        for key, value in results.items()
        if key not in {"opa_version", "image_digest", "policy_revision", "rego_tests_passed"}
    ]
    if results["rego_tests_passed"] != 3 or not all(value is True for value in checks):
        raise RuntimeError("OPA runtime verification failed")
    print(json.dumps(results, separators=(",", ":")))


if __name__ == "__main__":
    main()
