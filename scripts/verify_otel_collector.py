#!/usr/bin/env python3
"""Verify a digest-pinned official Collector with a real OTLP trace export."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from agentops_guard.backend.telemetry import TelemetryMiddleware


COLLECTOR_VERSION = "0.160.0"
_OFFICIAL_IMAGE = re.compile(
    r"^(?:otel/opentelemetry-collector-contrib|"
    r"ghcr\.io/open-telemetry/opentelemetry-collector-releases/"
    r"opentelemetry-collector-contrib)@sha256:[0-9a-f]{64}$"
)


def validate_image_reference(image: str) -> str:
    if not _OFFICIAL_IMAGE.fullmatch(image):
        raise ValueError(
            "Collector image must use an approved official repository and an immutable SHA-256"
        )
    return image


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _collector_config(output_path: str) -> str:
    return f"""receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
  batch:
    timeout: 100ms

exporters:
  file:
    path: {output_path}
    flush_interval: 100ms

extensions:
  health_check:
    endpoint: 0.0.0.0:13133

service:
  extensions: [health_check]
  telemetry:
    logs:
      level: error
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [file]
"""


def _container_command(
    *,
    image: str,
    name: str,
    config: Path,
    output_dir: Path,
    grpc_port: int,
    health_port: int,
) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--user=10001:10001",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--memory=384m",
        "--cpus=1",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
        "--publish",
        f"127.0.0.1:{grpc_port}:4317",
        "--publish",
        f"127.0.0.1:{health_port}:13133",
        "--mount",
        f"type=bind,source={config},target=/etc/otelcol-contrib/config.yaml,readonly",
        "--mount",
        f"type=bind,source={output_dir},target=/output",
        image,
        "--config=/etc/otelcol-contrib/config.yaml",
    ]


def _run_quiet(*command: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _verify_local_image(image: str) -> None:
    inspected = _run_quiet("docker", "image", "inspect", image)
    if inspected.returncode != 0:
        raise RuntimeError("Digest-pinned Collector image is not available locally")
    version = _run_quiet(
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--user=10001:10001",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        image,
        "--version",
    )
    if version.returncode != 0 or COLLECTOR_VERSION.encode() not in (
        version.stdout + version.stderr
    ):
        raise RuntimeError("Collector image did not report the required version")


def _wait_for_health(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 20
    with httpx.Client(timeout=1, trust_env=False) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Collector stopped before becoming healthy")
            try:
                if client.get(f"http://127.0.0.1:{port}").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
    raise RuntimeError("Collector did not become healthy")


def _emit_trace(endpoint: str) -> str:
    provider = TracerProvider()
    provider.add_span_processor(
        SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True, timeout=5))
    )
    trace.set_tracer_provider(provider)
    app = FastAPI()
    app.add_middleware(TelemetryMiddleware, component="collector-verification")

    @app.post("/records/{record_id}")
    def read_record(record_id: str) -> dict[str, str]:
        return {"status": "ok"}

    private_marker = f"private-record-{secrets.token_hex(16)}"
    with TestClient(app) as client:
        response = client.post(
            f"/records/{private_marker}",
            params={"private": private_marker},
            headers={"X-Private-Metadata": private_marker},
            json={"private": private_marker},
        )
    if response.status_code != 200:
        raise RuntimeError("Instrumented request failed")
    if not provider.force_flush(timeout_millis=5000):
        raise RuntimeError("Trace exporter did not flush")
    provider.shutdown()
    return private_marker


def _wait_for_export(path: Path) -> str:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size:
            return path.read_text(encoding="utf-8")
        time.sleep(0.1)
    raise RuntimeError("Collector did not export the trace")


def _inspect_runtime(name: str) -> None:
    inspected = _run_quiet("docker", "inspect", name)
    if inspected.returncode != 0:
        raise RuntimeError("Collector runtime inspection failed")
    try:
        data = json.loads(inspected.stdout)[0]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        raise RuntimeError("Docker returned invalid Collector inspection data") from None
    host = data["HostConfig"]
    config = data["Config"]
    if config.get("User") != "10001:10001":
        raise RuntimeError("Collector is not running as the required non-root user")
    if not host.get("ReadonlyRootfs"):
        raise RuntimeError("Collector root filesystem is writable")
    if "ALL" not in (host.get("CapDrop") or []):
        raise RuntimeError("Collector Linux capabilities were not dropped")
    if "no-new-privileges" not in " ".join(host.get("SecurityOpt") or []):
        raise RuntimeError("Collector privilege escalation is not disabled")
    if int(host.get("Memory") or 0) <= 0 or int(host.get("NanoCpus") or 0) <= 0:
        raise RuntimeError("Collector CPU or memory limit is missing")


def verify(image: str) -> dict[str, object]:
    image = validate_image_reference(image)
    _verify_local_image(image)
    grpc_port = _free_port()
    health_port = _free_port()
    name = f"agentops-otel-{uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory(prefix="agentops-otel-runtime-") as temp_dir:
        temp_path = Path(temp_dir)
        output_dir = temp_path / "output"
        output_dir.mkdir(mode=0o777)
        config = temp_path / "collector.yaml"
        config.write_text(_collector_config("/output/traces.json"), encoding="utf-8")
        process = subprocess.Popen(
            _container_command(
                image=image,
                name=name,
                config=config,
                output_dir=output_dir,
                grpc_port=grpc_port,
                health_port=health_port,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_health(health_port, process)
            _inspect_runtime(name)
            private_marker = _emit_trace(f"http://127.0.0.1:{grpc_port}")
            exported = _wait_for_export(output_dir / "traces.json")
            if private_marker in exported:
                raise RuntimeError("Private request data entered the exported trace")
            if "/records/{record_id}" not in exported:
                raise RuntimeError("Exported trace did not contain the route template")
            if "collector-verification" not in exported:
                raise RuntimeError("Exported trace did not contain the fixed component label")
        finally:
            _run_quiet("docker", "stop", "--time=5", name)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    return {
        "collector_version": COLLECTOR_VERSION,
        "digest_pinned_image": True,
        "real_otlp_export": True,
        "private_request_data_absent": True,
        "non_root_read_only_runtime": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.image), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
