import os
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
from threading import Event, Thread, Timer
import time

import httpx
import pytest
import yaml

from agentops_guard.backend.schemas import ScanRequest
from agentops_guard.backend.services.semantic_scanner import (
    RemoteSemanticScanner, SEMANTIC_MODEL_ID, SemanticScannerUnavailable,
)


def render(values):
    helm = shutil.which("helm")
    if not helm:
        pytest.skip("Helm is required for real chart rendering")
    if "semanticScanner" in values:
        values["semanticScanner"].setdefault("modelSha256", "a" * 64)
        values["semanticScanner"].setdefault("existingClaim", "test-model")
    result = subprocess.run([helm, "template", "guard", "deploy/helm/agentops-guard", "--namespace", "test", "-f", "-"],
                            input=yaml.safe_dump(values), text=True, capture_output=True, check=True)
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def test_proxy_renders_pinned_image_readiness_network_paths_and_no_retries():
    docs = render({"gatewayProxy": {"enabled": True}, "ingress": {"enabled": True},
                   "semanticScanner": {"mode": "shadow"}, "opa": {"enabled": True},
                   "networkPolicy": {"enabled": True}})
    cfg = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("gateway-proxy"))["data"]["haproxy.cfg"]
    assert "retries 0" in cfg and "redispatch" not in cfg
    assert "balance leastconn" in cfg and "maxconn 1 maxqueue 2" in cfg
    assert "option httpchk GET /readyz" in cfg
    assert "timeout queue 1000ms" in cfg.split("\nbackend semantic\n")[1]
    assert "timeout queue 200ms" in cfg  # Other backends retain their deadline.
    log = next(line for line in cfg.splitlines() if "log-format" in line)
    assert all(field not in log for field in ("%r", "%HU", "%ci", "%hr", "%[req"))
    assert "on-marked-down shutdown-sessions" not in cfg
    assert "server-template replica 1-16 agentops-guard-proxy-gateway.test.svc.cluster.local:8001 check" in cfg
    deployment = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"].endswith("gateway-proxy"))
    pod = deployment["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert "@sha256:" in pod["containers"][0]["image"]
    assert "env" not in pod["containers"][0]  # No application/database/Vault credentials.
    assert pod["containers"][0]["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert next(d for d in docs if d["kind"] == "Ingress")["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"].endswith("gateway-proxy")
    names = {d["metadata"]["name"] for d in docs if d["kind"] == "NetworkPolicy"}
    assert {"agentops-guard-proxy-client-egress", "agentops-guard-proxy-semantic-ingress",
            "agentops-guard-proxy-opa-ingress", "agentops-guard-proxy-gateway-ingress"} <= names


@pytest.mark.parametrize("upstream", [
    {"name": "gateway", "app": "test", "port": 9091, "healthPath": ""},
    {"name": "test", "app": "test", "port": 8001, "healthPath": ""},
    {"name": "test", "app": "test", "port": 9091, "healthPath": "/ready\nretries 3"},
])
def test_proxy_rejects_ambiguous_or_injected_upstream_configuration(upstream):
    with pytest.raises(subprocess.CalledProcessError):
        render({"gatewayProxy": {"enabled": True, "upstreams": [upstream]}})


def test_real_haproxy_accepts_rendered_config():
    image = os.environ.get("AGENTOPS_TEST_HAPROXY_IMAGE")
    if not image:
        pytest.skip("Set AGENTOPS_TEST_HAPROXY_IMAGE for explicit Docker integration")
    docs = render({"gatewayProxy": {"enabled": True, "upstreams": [{"name": "upstream", "app": "upstream", "port": 8091, "healthPath": ""}]},
                   "semanticScanner": {"mode": "shadow"}, "opa": {"enabled": True}})
    cfg = next(d for d in docs if d["kind"] == "ConfigMap" and "haproxy.cfg" in d.get("data", {}))["data"]["haproxy.cfg"]
    subprocess.run(["docker", "run", "--rm", "-i", "--network=none", "--user", "10001:10001", "--read-only",
                    image, "haproxy", "-c", "-f", "/dev/stdin"], input=cfg, text=True, capture_output=True, check=True)


def test_proxy_is_opt_in_for_existing_deployments():
    assert yaml.safe_load(Path("deploy/helm/agentops-guard/values.yaml").read_text())["gatewayProxy"]["enabled"] is False
    assert all(not d["metadata"]["name"].endswith("gateway-proxy") for d in render({}))


@contextmanager
def controlled_backend(*, healthy=True, blocking=False, scoring=False):
    state = {"healthy": healthy, "calls": 0}
    entered, release, finished = Event(), Event(), Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if state["healthy"] else 503)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            state["calls"] += 1
            entered.set()
            if blocking:
                release.wait(10)
            finished.set()
            try:
                body = json.dumps({"score": .1, "model": SEMANTIC_MODEL_ID}).encode() if scoring else b""
                self.send_response(200 if blocking or state["healthy"] else 503)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (ConnectionResetError, BrokenPipeError):
                # A client may close before this controlled response completes.
                state["response_connection_closed"] = True

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, state, entered, release, finished
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def live_proxy(tmp_path, values, backends, logs=None):
    image = os.environ.get("AGENTOPS_TEST_HAPROXY_IMAGE")
    if not image:
        pytest.skip("Set AGENTOPS_TEST_HAPROXY_IMAGE for explicit Docker integration")
    docs = render(values)
    cfg = next(d for d in docs if d["kind"] == "ConfigMap" and "haproxy.cfg" in d.get("data", {}))["data"]["haproxy.cfg"]
    ports = {}
    reservations = []
    for original in re.findall(r"bind :(\d+)", cfg):
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        reservations.append(reservation)
        ports[int(original)] = reservation.getsockname()[1]
    cfg = re.sub(r"bind :(\d+)", lambda m: f"bind 127.0.0.1:{ports[int(m[1])]}", cfg)
    for backend, targets in backends.items():
        # Retain real server limits; otherwise queue tests silently bypass them.
        original = re.search(r"^  server-template .*proxy-" + backend + r"\..*$", cfg, re.MULTILINE)[0]
        options = original.split(" check", 1)[1]
        cfg = re.sub(r"^  server-template .*proxy-" + backend + r"\..*$",
            "\n".join(f"  server replica{i} 127.0.0.1:{port} check{options}" for i, port in enumerate(targets)),
            cfg, flags=re.MULTILINE)
    path = tmp_path / (secrets.token_hex(4) + ".cfg")
    path.write_text(cfg)
    name = "agentops-proxy-test-" + secrets.token_hex(6)
    for reservation in reservations:
        reservation.close()
    subprocess.run(["docker", "run", "--detach", "--name", name, "--network=host", "--read-only",
        "--user", "10001:10001", "--tmpfs", "/tmp", "--mount", f"type=bind,src={path},dst=/cfg,readonly",
        image, "haproxy", "-W", "-db", "-f", "/cfg"], capture_output=True, check=True)
    try:
        with httpx.Client(trust_env=False, timeout=1) as client:
            deadline = time.monotonic() + 10
            while True:
                try:
                    if client.get(f"http://127.0.0.1:{ports[8404]}/readyz").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert time.monotonic() < deadline, "controlled proxy failed readiness"
                time.sleep(.05)
        yield ports
    finally:
        try:
            if logs is not None:
                logs.append(subprocess.run(["docker", "logs", name], text=True, capture_output=True, check=True).stdout)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=True)


@pytest.mark.parametrize("queue_ms", [200, 1000])
def test_real_scoring_queue_waits_for_one_predecessor_with_same_client_deadline(tmp_path, queue_ms):
    logs = []
    with controlled_backend(blocking=True, scoring=True) as (port, state, entered, release, finished):
        with live_proxy(tmp_path, {"gatewayProxy": {"enabled": True, "semanticQueueTimeoutMs": queue_ms},
                                  "semanticScanner": {"mode": "shadow"}},
                        {"gateway": [port], "semantic": [port]}, logs) as ports:
            with httpx.Client(trust_env=False, timeout=3) as client, ThreadPoolExecutor() as pool:
                target = f"http://127.0.0.1:{ports[8090]}"
                first = pool.submit(client.post, target + "/v1/score", json={"text": "predecessor"})
                assert entered.wait(2)
                timer = Timer(.75, release.set)
                timer.start()
                scanner = RemoteSemanticScanner(target, "shadow", .9, 2)
                start = time.monotonic()
                try:
                    if queue_ms == 200:
                        with pytest.raises(SemanticScannerUnavailable) as caught:
                            scanner.assess(ScanRequest(content="normal private-sentinel-content"))
                        assert caught.value.reason == "proxy_queue_timeout"
                        assert caught.value.attempts == 2
                        assert state["calls"] == 1  # Both failed before reaching model.
                    else:
                        result = scanner.assess(ScanRequest(content="normal private-sentinel-content"))
                        assert result.status == "ok" and result.attempts == 1
                        assert state["calls"] == 2
                    assert time.monotonic() - start < 1.8
                finally:
                    release.set()
                    timer.cancel()
                    timer.join()
                assert first.result(timeout=2).status_code == 200
    log = "".join(logs)
    assert "private-sentinel-content" not in log and "/v1/score" not in log
    assert "SCORING_PROXY status=" in log
    if queue_ms == 200:
        assert "status=503 termination=sQ" in log
    else:
        assert "status=503" not in log


def test_real_scoring_queue_cannot_extend_client_budget_or_block_readiness(tmp_path):
    with controlled_backend(blocking=True, scoring=True) as (port, state, entered, release, finished):
        with live_proxy(tmp_path, {"gatewayProxy": {"enabled": True},
                                  "semanticScanner": {"mode": "shadow"}},
                        {"gateway": [port], "semantic": [port]}) as ports:
            with httpx.Client(trust_env=False, timeout=3) as client, ThreadPoolExecutor() as pool:
                target = f"http://127.0.0.1:{ports[8090]}"
                first = pool.submit(client.post, target + "/v1/score", json={"text": "predecessor"})
                assert entered.wait(2)
                try:
                    scanner = RemoteSemanticScanner(target, "shadow", .9, .6)
                    start = time.monotonic()
                    with pytest.raises(SemanticScannerUnavailable) as caught:
                        scanner.assess(ScanRequest(content="normal text"))
                    assert caught.value.reason == "deadline_exceeded"
                    assert .5 <= time.monotonic() - start < .95
                    assert state["calls"] == 1 and not first.done()
                    assert client.get(target + "/readyz").status_code == 200
                finally:
                    release.set()
                assert first.result(timeout=2).status_code == 200


@pytest.mark.parametrize("queue_ms", [0, 49, 1001, "private\nretries 3"])
def test_proxy_rejects_unsafe_scoring_queue_budget(queue_ms):
    with pytest.raises(subprocess.CalledProcessError):
        render({"gatewayProxy": {"enabled": True, "semanticQueueTimeoutMs": queue_ms}})


def test_probe_failure_does_not_discard_inflight_tool_result_or_replay(tmp_path):
    with controlled_backend(blocking=True) as (port, state, entered, release, finished):
        with live_proxy(tmp_path, {"gatewayProxy": {"enabled": True}}, {"gateway": [port]}) as ports:
            with httpx.Client(trust_env=False, timeout=5) as client, ThreadPoolExecutor() as pool:
                future = pool.submit(client.post, f"http://127.0.0.1:{ports[8001]}/mcp/tools/call")
                assert entered.wait(2)
                state["healthy"] = False
                try:
                    time.sleep(2)  # Allow the probe's fall threshold to expire.
                    assert client.get(f"http://127.0.0.1:{ports[8404]}/readyz").status_code == 503
                    assert not future.done()
                    assert state["calls"] == 1  # No redispatch/retry.
                    assert not finished.is_set()
                finally:
                    release.set()
                assert future.result(timeout=2).status_code == 200


@pytest.mark.parametrize("health_path", ["", "/readyz"])
def test_http_readiness_excludes_dependency_failed_upstream_but_tcp_does_not(tmp_path, health_path):
    with controlled_backend() as good, controlled_backend(healthy=False) as bad:
        values = {"gatewayProxy": {"enabled": True, "upstreams": [
            {"name": "upstream", "app": "upstream", "port": 8091, "healthPath": health_path}]}}
        with live_proxy(tmp_path, values, {"gateway": [good[0]], "upstream": [good[0], bad[0]]}) as ports:
            time.sleep(2)  # Let both fall/rise thresholds settle, outside measurement.
            with httpx.Client(trust_env=False, timeout=2) as client:
                statuses = [client.post(f"http://127.0.0.1:{ports[8091]}/mcp").status_code for _ in range(12)]
        if health_path:
            assert statuses == [200] * 12
            assert bad[1]["calls"] == 0
        else:
            assert 503 in statuses and 200 in statuses
            assert bad[1]["calls"] > 0
