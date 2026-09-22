#!/usr/bin/env python3
"""Single-host, real HAProxy/two-gateway fault soak; never a production SLA claim."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

import httpx

from verify_operational_resilience import (
    ROOT, _free_port, _local_image_id, _remove_containers, _run,
    _safe_environment, _wait_for_postgres, _wait_for_redis,
)


def upstream(port: int, marker: Path) -> None:
    from mcp.server import MCPServer

    server = MCPServer("ha-soak-controlled-upstream")

    @server.tool()
    def read_status(request_id: str) -> str:
        with marker.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(["read", request_id]) + "\n")
        return "Service status is healthy."

    @server.tool()
    def write_file(request_id: str, path: str, content: str) -> str:
        # A receipt is the only side effect: no user files are ever modified.
        with marker.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(["write", request_id]) + "\n")
        return "Controlled write receipt recorded."

    server.run(transport="streamable-http", host="127.0.0.1", port=port,
               stateless_http=True, json_response=True)


def percentile(values: list[float], fraction: float) -> float:
    import math
    return round(sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)], 3)


async def exercise(args, environment, temp, lb_port, gateway_ports, processes):
    # Import after the isolated database environment has been installed.
    from verify_gateway_multi_replica_capacity import _wait_for_port
    from agentops_guard.backend.database import SessionLocal
    from agentops_guard.backend.models import McpServer, McpTool, PolicyDecision, RiskEvent
    from agentops_guard.backend.services.api_keys import create_api_key
    from agentops_guard.backend.services.audit import verify_audit_chain
    from agentops_guard.backend.services.projects import ensure_project
    from agentops_guard.backend.services.scanner_rule_packs import install_scanner_rule_pack

    project_id, server_id = "ha_" + uuid4().hex, "ha_" + uuid4().hex
    upstream_port = _free_port()
    marker = temp / "upstream-receipts.jsonl"
    child = subprocess.Popen([sys.executable, __file__, "--upstream-port", str(upstream_port),
                              "--marker", str(marker)], env=environment,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(child)
    _wait_for_port(child, upstream_port)
    with SessionLocal() as db:
        ensure_project(db, project_id)
        install_scanner_rule_pack(db, project_id=project_id,
            path=ROOT / "policies/scanner/agentdojo-important-instructions-v1.json")
        db.add(McpServer(id=server_id, project_id=project_id, name="soak upstream",
                        transport="streamable_http", url=f"http://127.0.0.1:{upstream_port}/mcp",
                        trust_level="internal", allowed_agents=[], status="active"))
        for name in ("read_status", "write_file"):
            properties = {"request_id": {"type": "string"}}
            if name == "write_file":
                properties.update(path={"type": "string"}, content={"type": "string"})
            db.add(McpTool(id=f"{server_id}:{name}", project_id=project_id, server_id=server_id,
                           name=name, description=name.replace("_", " "),
                           input_schema={"type": "object", "properties": properties,
                                         "required": list(properties)},
                           annotations={"readOnlyHint": name == "read_status"}, status="active"))
        _, token = create_api_key(db, project_id, "ha-soak",
                                 ["mcp:read", "mcp:invoke"], agent_id="ha-agent")
        db.commit()

    def start_gateway(index):
        port = gateway_ports[index]
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "agentops_guard.gateway.app:app", "--host",
             "127.0.0.1", "--port", str(port), "--no-access-log"],
            env={**environment, "AGENTOPS_MCP_PUBLIC_URL": f"http://127.0.0.1:{lb_port}/mcp"},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(process)
        return process

    gateways = [start_gateway(0), start_gateway(1)]
    for process, port in zip(gateways, gateway_ports, strict=True):
        _wait_for_port(process, port)
    config = temp / "haproxy.cfg"
    config.write_text(f"""global
    maxconn 1024
defaults
    mode http
    timeout connect 1s
    timeout client 10s
    timeout server 10s
    retries 0
frontend gateway
    bind 127.0.0.1:{lb_port}
    default_backend gateways
backend gateways
    balance roundrobin
    option httpchk GET /readyz
    http-check expect status 200
    server gateway1 127.0.0.1:{gateway_ports[0]} check inter 200ms fall 1 rise 1
    server gateway2 127.0.0.1:{gateway_ports[1]} check inter 200ms fall 1 rise 1
""", encoding="utf-8")
    lb = subprocess.Popen([str(args.haproxy), "-db", "-f", str(config)], env=environment,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(lb)
    _wait_for_port(lb, lb_port)
    url = f"http://127.0.0.1:{lb_port}/mcp/tools/call"
    rows, faults, decision_ids = [], [], set()
    started = time.monotonic()
    async with httpx.AsyncClient(timeout=10, trust_env=False,
                                 limits=httpx.Limits(max_connections=128)) as client:
        for _ in range(1200):
            response = await client.get(f"http://127.0.0.1:{lb_port}/readyz")
            if response.status_code == 200:
                break
            await asyncio.sleep(0.1)
        else:
            statuses = []
            for port in gateway_ports:
                check = await client.get(f"http://127.0.0.1:{port}/readyz")
                statuses.append(check.status_code)
            raise RuntimeError(f"load balancer did not become ready; replica statuses: {statuses}")
        await asyncio.sleep(1)
        started = time.monotonic()

        async def request(index, scheduled):
            write = index % 100 == 99
            arguments = {"request_id": str(index)}
            if write:
                arguments.update(path="/controlled/probe.txt", content="probe")
            sent = time.monotonic()
            status, allowed, protected, decision = 0, False, False, None
            try:
                response = await client.post(url, headers={"Authorization": f"Bearer {token}"},
                    json={"serverId": server_id, "name": "write_file" if write else "read_status",
                          "arguments": arguments})
                status = response.status_code
                if status == 200:
                    body = response.json()
                    decision = body.get("policyDecision", {}).get("id")
                    allowed = not body.get("isError", False)
                    protected = body.get("policyDecision", {}).get("action") in {
                        "deny", "require_approval", "quarantine"}
            except httpx.TransportError:
                status = 0
            finished = time.monotonic()
            if decision:
                decision_ids.add(decision)
            rows.append({"index": index, "write": write, "status": status,
                         "ok": protected if write else allowed, "decision": decision,
                         "at": finished - started, "sent_at": sent - started,
                         "latency_ms": (finished - sent) * 1000,
                         "scheduled_latency_ms": (finished - scheduled) * 1000,
                         "scheduling_delay_ms": (sent - scheduled) * 1000})

        async def disrupt():
            for index in range(2):
                at = args.seconds * (index + 1) / 3
                await asyncio.sleep(max(0, started + at - time.monotonic()))
                killed_at = time.monotonic() - started
                gateways[index].kill()
                await asyncio.to_thread(gateways[index].wait, timeout=5)
                faults.append({"replica": index + 1, "killed_at_seconds": killed_at})
                print(json.dumps({"progress": "gateway_killed", "replica": index + 1}), flush=True)
                await asyncio.sleep(min(10, args.seconds / 12))
                gateways[index] = start_gateway(index)
                await asyncio.to_thread(_wait_for_port, gateways[index], gateway_ports[index])
                faults[-1]["restarted_at_seconds"] = time.monotonic() - started

        disruption = asyncio.create_task(disrupt())
        pending = []
        total = int(args.seconds * args.rps)
        for index in range(total):
            scheduled = started + index / args.rps
            await asyncio.sleep(max(0, scheduled - time.monotonic()))
            task = asyncio.create_task(request(index, scheduled))
            pending.append(task)
            if index and index % max(1, int(args.rps * 60)) == 0:
                print(json.dumps({"progress": "load", "sent": index, "completed": len(rows),
                                  "failed": sum(not row["ok"] for row in rows)}), flush=True)
        await asyncio.gather(*pending, disruption)
    elapsed = time.monotonic() - started
    receipts = [json.loads(line) for line in marker.read_text().splitlines()]
    reads = Counter(request_id for kind, request_id in receipts if kind == "read")
    successful_reads = {str(row["index"]) for row in rows if row["ok"] and not row["write"]}
    failed_reads_executed = set(reads) - successful_reads
    with SessionLocal() as db:
        stored_ids = {row[0] for row in db.query(PolicyDecision.id).filter_by(project_id=project_id)}
        integrity = verify_audit_chain(db, project_id)
        semantic_errors = db.query(RiskEvent).filter_by(
            project_id=project_id, risk_type="semantic_scanner_error").count()
    for fault in faults:
        after = [row for row in rows if row["sent_at"] >= fault["killed_at_seconds"] and row["ok"]]
        fault["first_success_seconds_after_kill"] = round(
            min(row["at"] for row in after) - fault["killed_at_seconds"], 4)
        fault["failures_before_restart"] = sum(not row["ok"] for row in rows if
            fault["killed_at_seconds"] <= row["sent_at"] < fault["restarted_at_seconds"])
    failed = sum(not row["ok"] for row in rows)
    result = {
        "schema_version": 1, "scope": "single_host_two_gateway_real_load_balancer_fault_soak",
        "transport": "legacy HTTP tools/call through the real MCP upstream and shared policy path",
        "production_sla_verified": False, "business_peak_rps": None,
        "started_at": datetime.fromtimestamp(time.time() - elapsed, UTC).isoformat(),
        "duration_seconds": round(elapsed, 3), "target_rps": args.rps,
        "attempted": len(rows), "planned": total, "completed_rps": round(len(rows) / elapsed, 3),
        "successful": len(rows) - failed, "failed": failed, "error_rate": failed / len(rows),
        "status_counts": dict(Counter(str(row["status"]) for row in rows)),
        "latency_ms": {str(p): percentile([r["latency_ms"] for r in rows], p / 100) for p in (50, 95, 99)},
        "scheduled_latency_ms": {str(p): percentile([r["scheduled_latency_ms"] for r in rows], p / 100) for p in (95, 99)},
        "max_scheduling_delay_ms": round(max(r["scheduling_delay_ms"] for r in rows), 3),
        "faults": faults, "client_retries": 0, "haproxy_retries": 0,
        "write_probes": sum(r["write"] for r in rows),
        "unauthorized_write_executions": sum(kind == "write" for kind, _ in receipts),
        "upstream_reads": sum(reads.values()), "duplicate_upstream_reads": sum(n - 1 for n in reads.values()),
        "acknowledged_read_missing_upstream": len(successful_reads - set(reads)),
        "failed_or_unacknowledged_reads_executed": len(failed_reads_executed),
        "acknowledged_decisions": len(decision_ids),
        "missing_persisted_decisions": len(decision_ids - stored_ids),
        "responses_missing_decision_id": sum(row["status"] == 200 and not row["decision"] for row in rows),
        "semantic_scanner_error_events": semantic_errors,
        "audit_chain_valid": integrity.valid, "audit_chain_entries": integrity.checked_entries,
        "audit_scope": "policy decisions for requests; hash-chain check covers rule-pack installation, not a full trace per read",
        "managed_rule_pack_sha256": hashlib.sha256((ROOT / "policies/scanner/agentdojo-important-instructions-v1.json").read_bytes()).hexdigest(),
        "services": {"gateway_replicas": 2, "postgresql": 16, "redis": 7,
                     "semantic_scanner": environment["AGENTOPS_SEMANTIC_SCANNER_MODE"],
                     "opa": "real_signed_bundle" if args.security_path else "disabled"},
        "limits": ["one WSL host; not independent failure domains", "read-heavy controlled workload",
                   "no representative long-document or attack-heavy capacity claim",
                   "no production business peak, persistent-volume, load-balancer or Redis failover claim"],
    }
    result["passed"] = (failed / len(rows) < 0.001 and len(rows) == total and
        not result["unauthorized_write_executions"] and not result["duplicate_upstream_reads"] and
        not result["acknowledged_read_missing_upstream"] and not result["missing_persisted_decisions"]
        and not result["responses_missing_decision_id"] and not semantic_errors
        and integrity.valid and integrity.checked_entries > 0)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--haproxy", type=Path)
    parser.add_argument("--seconds", type=float, default=1800)
    parser.add_argument("--rps", type=float, default=10)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--security-path", action="store_true", help="Enable signed OPA and local shadow model")
    parser.add_argument("--upstream-port", type=int)
    parser.add_argument("--marker", type=Path)
    args = parser.parse_args()
    if args.upstream_port:
        upstream(args.upstream_port, args.marker)
        return 0
    if not args.haproxy or not args.output or args.seconds < 12 or not 0 < args.rps <= 100:
        parser.error("require --haproxy, --output, seconds >= 12 and 0 < rps <= 100")
    if args.output.exists():
        raise FileExistsError("refusing to overwrite a completed soak report")
    initial_harness_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    initial_source_sha256 = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT / "src").rglob("*.py"))
    }
    pg_image, redis_image = _local_image_id("postgres:16"), _local_image_id("redis:7")
    suffix = uuid4().hex[:12]
    names = (f"agentops-ha-pg-{suffix}", f"agentops-ha-redis-{suffix}", f"agentops-ha-opa-{suffix}")
    pg_port, redis_port, lb_port = _free_port(), _free_port(), _free_port()
    gateway_ports = [_free_port(), _free_port()]
    password = secrets.token_urlsafe(32)
    environment = _safe_environment()
    if os.environ.get("LD_LIBRARY_PATH"):
        environment["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH"]
    environment.update(AGENTOPS_ENV="test", AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP="false",
        AGENTOPS_DATABASE_URL=f"postgresql+psycopg://agentops:{password}@127.0.0.1:{pg_port}/agentops",
        AGENTOPS_REDIS_URL=f"redis://127.0.0.1:{redis_port}/0", AGENTOPS_SEMANTIC_SCANNER_MODE="disabled",
        AGENTOPS_OPA_URL="", AGENTOPS_OTEL_ENABLED="false", AGENTOPS_GATEWAY_CONCURRENCY_BACKEND="redis",
        AGENTOPS_GATEWAY_MAX_CONCURRENCY_PER_SERVER="32", AGENTOPS_GATEWAY_CAPACITY_WAIT_SECONDS="0.05",
        AGENTOPS_MCP_ALLOWED_HOSTS="127.0.0.1,127.0.0.1:*", AGENTOPS_MCP_ALLOWED_ORIGINS="http://127.0.0.1:3000")
    processes = []
    os.environ.update(environment)
    from verify_gateway_multi_replica_capacity import _stop_process
    try:
        _run(["docker", "run", "--detach", "--pull", "never", "--name", names[0],
              "--publish", f"127.0.0.1:{pg_port}:5432", "--env", "POSTGRES_PASSWORD",
              "--env", "POSTGRES_USER=agentops", "--env", "POSTGRES_DB=agentops", pg_image],
             environment={**environment, "POSTGRES_PASSWORD": password})
        _run(["docker", "run", "--detach", "--pull", "never", "--name", names[1],
              "--publish", f"127.0.0.1:{redis_port}:6379", redis_image])
        _wait_for_postgres(environment["AGENTOPS_DATABASE_URL"].replace("+psycopg", ""))
        _wait_for_redis(environment["AGENTOPS_REDIS_URL"])
        _run([sys.executable, "-m", "alembic", "upgrade", "head"], environment=environment)
        os.environ.update(environment)
        with tempfile.TemporaryDirectory(prefix="agentops-ha-soak-") as directory:
            if args.security_path:
                from verify_opa_runtime import _build_signed_bundle, OPA_IMAGE, SIGNING_KEY_ID, SIGNING_SCOPE
                from agentops_guard.benchmarks.llmail_inject import DEFAULT_MODEL_SHA256
                from agentops_guard.backend.config import get_settings
                runtime, _bundle_digest = _build_signed_bundle(Path(directory))
                opa_port = _free_port()
                _run(["docker", "run", "--detach", "--pull", "never", "--name", names[2],
                      "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                      "--publish", f"127.0.0.1:{opa_port}:8181", "--mount",
                      f"type=bind,source={runtime},target=/policy,readonly", OPA_IMAGE,
                      "run", "--server", "--disable-telemetry", "--addr=0.0.0.0:8181",
                      "--bundle", "/policy/bundle.tar.gz", "--verification-key", "/policy/public.pem",
                      "--verification-key-id", SIGNING_KEY_ID, "--scope", SIGNING_SCOPE])
                environment.update(AGENTOPS_OPA_URL=f"http://127.0.0.1:{opa_port}",
                    AGENTOPS_OPA_EXPECTED_POLICY_REVISION="agentops-guard-v1",
                    AGENTOPS_SEMANTIC_SCANNER_MODE="shadow",
                    AGENTOPS_SEMANTIC_MODEL_PATH=str(ROOT / "models/semantic-guard"),
                    AGENTOPS_SEMANTIC_MODEL_SHA256=DEFAULT_MODEL_SHA256,
                    AGENTOPS_SEMANTIC_SCANNER_THRESHOLD="0.9", HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
                os.environ.update(environment)
                get_settings.cache_clear()
            result = asyncio.run(exercise(args, environment, Path(directory), lb_port, gateway_ports, processes))
        result["source_revision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        result["harness_sha256"] = initial_harness_sha256
        result["implementation_sha256"] = initial_source_sha256
        if initial_harness_sha256 != hashlib.sha256(Path(__file__).read_bytes()).hexdigest() or any(
            hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != digest
            for path, digest in initial_source_sha256.items()
        ):
            raise RuntimeError("implementation changed during the soak")
        result["image_ids"] = {"postgres": pg_image, "redis": redis_image}
        result["haproxy_sha256"] = hashlib.sha256(args.haproxy.read_bytes()).hexdigest()
    finally:
        for process in reversed(processes):
            _stop_process(process)
        _remove_containers(names)
    result["temporary_services_removed"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
