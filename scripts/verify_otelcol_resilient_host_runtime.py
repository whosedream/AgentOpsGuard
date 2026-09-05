#!/usr/bin/env python3
"""Verify Collector OTLP privacy and persistent-queue restart recovery."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from typing import Any

import grpc
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2_grpc

from verify_otel_collector import _emit_trace, _free_port, _wait_for_health


COLLECTOR_VERSION = "0.160.0"
COLLECTOR_BINARY_SHA256 = "8524ac54f6e1d4d00d9ba5eea91daadec2ebc31e4da80db9c17eba2e859ecdd4"
COLLECTOR_BINARY = (
    Path.home()
    / f".local/share/agentops-guard/otelcol-contrib/{COLLECTOR_VERSION}/otelcol-contrib"
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_runtime_binary() -> None:
    if not COLLECTOR_BINARY.is_file():
        raise RuntimeError("pinned Collector binary is missing")
    if _sha256_file(COLLECTOR_BINARY) != COLLECTOR_BINARY_SHA256:
        raise RuntimeError("pinned Collector binary has the wrong digest")
    result = subprocess.run(
        (str(COLLECTOR_BINARY), "--version"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0 or result.stdout.decode("utf-8", errors="replace").strip() != (
        f"otelcol-contrib version {COLLECTOR_VERSION}"
    ):
        raise RuntimeError("pinned Collector binary reported an unexpected version")


def _collector_config(
    *, receiver_port: int, health_port: int, backend_port: int, queue_dir: Path
) -> str:
    queue_path = json.dumps(str(queue_dir))
    return f"""receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:{receiver_port}

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
  batch:
    timeout: 100ms

exporters:
  otlp:
    endpoint: 127.0.0.1:{backend_port}
    tls:
      insecure: true
    sending_queue:
      enabled: true
      storage: file_storage
      queue_size: 128
    retry_on_failure:
      enabled: true
      initial_interval: 250ms
      max_interval: 1s
      max_elapsed_time: 60s

extensions:
  health_check:
    endpoint: 127.0.0.1:{health_port}
  file_storage:
    directory: {queue_path}

service:
  extensions: [health_check, file_storage]
  telemetry:
    logs:
      level: error
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp]
"""


def _start_collector(config: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        (str(COLLECTOR_BINARY), f"--config={config}"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _stop_collector(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _wait_for_wal(queue_dir: Path) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if any(path.is_file() and path.stat().st_size for path in queue_dir.rglob("*")):
            return
        time.sleep(0.1)
    raise RuntimeError("Collector did not persist the unavailable-backend queue")


class TraceSink(trace_service_pb2_grpc.TraceServiceServicer):
    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.lock = threading.Lock()
        self.received = threading.Event()

    def Export(self, request: Any, _context: grpc.ServicerContext) -> Any:  # noqa: N802
        with self.lock:
            self.requests.append(request)
        self.received.set()
        return trace_service_pb2.ExportTraceServiceResponse()

    def serialized(self) -> bytes:
        with self.lock:
            return b"".join(request.SerializeToString() for request in self.requests)


def _start_backend(port: int) -> tuple[grpc.Server, TraceSink]:
    sink = TraceSink()
    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    trace_service_pb2_grpc.add_TraceServiceServicer_to_server(sink, server)
    if server.add_insecure_port(f"127.0.0.1:{port}") != port:
        raise RuntimeError("local OTLP backend could not bind its loopback port")
    server.start()
    return server, sink


def verify() -> dict[str, object]:
    _verify_runtime_binary()
    receiver_port = _free_port()
    health_port = _free_port()
    backend_port = _free_port()
    if len({receiver_port, health_port, backend_port}) != 3:
        raise RuntimeError("verification ports were not unique")
    with tempfile.TemporaryDirectory(prefix="agentops-otelcol-resilience-") as temp_dir:
        temp_path = Path(temp_dir)
        queue_dir = temp_path / "queue"
        queue_dir.mkdir(mode=0o700)
        config = temp_path / "collector.yaml"
        config.write_text(
            _collector_config(
                receiver_port=receiver_port,
                health_port=health_port,
                backend_port=backend_port,
                queue_dir=queue_dir,
            ),
            encoding="utf-8",
        )
        first = _start_collector(config)
        try:
            _wait_for_health(health_port, first)
            private_marker = _emit_trace(f"http://127.0.0.1:{receiver_port}")
            _wait_for_wal(queue_dir)
        finally:
            _stop_collector(first)

        backend, sink = _start_backend(backend_port)
        second = _start_collector(config)
        try:
            _wait_for_health(health_port, second)
            if not sink.received.wait(timeout=20):
                raise RuntimeError("Collector did not recover the persisted trace after restart")
            exported = sink.serialized()
            if private_marker.encode("utf-8") in exported:
                raise RuntimeError("private request data entered the recovered trace")
            if b"/records/{record_id}" not in exported:
                raise RuntimeError("recovered trace did not contain the fixed route template")
            if b"collector-verification" not in exported:
                raise RuntimeError("recovered trace did not contain the fixed component label")
        finally:
            _stop_collector(second)
            backend.stop(grace=1).wait(timeout=5)

    return {
        "collector_version": COLLECTOR_VERSION,
        "binary_sha256": COLLECTOR_BINARY_SHA256,
        "checks": {
            "binary_sha256_verified": True,
            "runtime_version_verified": True,
            "real_otlp_ingest": True,
            "downstream_outage_wrote_persistent_queue": True,
            "collector_restart_recovered_queued_trace": True,
            "private_request_data_absent": True,
            "route_template_and_fixed_component_present": True,
            "runtime_runs_as_non_root": os.geteuid() != 0,
            "listeners_are_loopback_only": True,
        },
        "limits": {
            "production_backend_verified": False,
            "container_or_kubernetes_runtime_verified": False,
            "container_image_signature_verified": False,
            "production_volume_durability_verified": False,
        },
        "privacy": {
            "captures_trace_payload": False,
            "captures_private_request_marker": False,
            "captures_environment_values": False,
        },
    }


def main() -> None:
    result = verify()
    if not all(result["checks"].values()):
        raise RuntimeError("Collector resilient host-runtime verification failed")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
