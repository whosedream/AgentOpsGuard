from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, int(len(ordered) * quantile) - 1))
    return ordered[rank]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=25)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/benchmarks/gateway_security_path_v1.json"),
    )
    args = parser.parse_args()
    if args.iterations < 1 or args.warmup < 0:
        raise ValueError("iterations must be positive and warmup must not be negative")

    with tempfile.TemporaryDirectory(prefix="agentops-gateway-benchmark-") as directory:
        database_path = Path(directory) / "benchmark.sqlite3"
        os.environ["AGENTOPS_ENV"] = "dev"
        os.environ["AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP"] = "true"
        os.environ["AGENTOPS_DATABASE_URL"] = f"sqlite:///{database_path}"
        os.environ["AGENTOPS_SEMANTIC_SCANNER_MODE"] = "disabled"
        os.environ.pop("AGENTOPS_OPA_URL", None)

        from fastapi.testclient import TestClient

        from agentops_guard.backend.database import SessionLocal
        from agentops_guard.backend.models import McpServer, McpTool
        from agentops_guard.backend.services.projects import ensure_project
        from agentops_guard.gateway.app import create_gateway_app

        project_id = "gateway-security-benchmark"
        server_id = "benchmark-server"
        db = SessionLocal()
        try:
            ensure_project(db, project_id)
            db.add(
                McpServer(
                    id=server_id,
                    project_id=project_id,
                    name="benchmark",
                    transport="stdio",
                    trust_level="internal",
                    allowed_agents=[],
                    status="active",
                )
            )
            db.add(
                McpTool(
                    id=f"{server_id}:records.read",
                    project_id=project_id,
                    server_id=server_id,
                    name="records.read",
                    description="Read one record",
                    input_schema={"type": "object"},
                    annotations={"readOnlyHint": True},
                    status="active",
                )
            )
            db.commit()
        finally:
            db.close()

        client = TestClient(
            create_gateway_app(),
            headers={"X-AgentOps-Api-Key": "dev-agentops-key"},
        )

        def invoke() -> None:
            response = client.post(
                "/mcp/tools/call",
                params={"project_id": project_id},
                json={
                    "serverId": server_id,
                    "name": "records.read",
                    "arguments": {"record_id": "benchmark-record"},
                },
            )
            if response.status_code != 200:
                raise RuntimeError(f"gateway benchmark failed with HTTP {response.status_code}")
            body = response.json()
            if body.get("isError") or body.get("policyDecision", {}).get("action") != "allow":
                raise RuntimeError("gateway benchmark request was not allowed")

        for _ in range(args.warmup):
            invoke()
        latencies: list[float] = []
        started = time.perf_counter()
        for _ in range(args.iterations):
            request_started = time.perf_counter()
            invoke()
            latencies.append((time.perf_counter() - request_started) * 1000)
        elapsed = time.perf_counter() - started

    repository = Path(__file__).resolve().parents[1]
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    report = {
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(),
            "commit": commit,
            "working_tree_dirty": bool(
                subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=repository,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
            ),
            "environment": "single-process TestClient with temporary SQLite",
            "semantic_scanner": "disabled",
            "opa": "disabled",
            "upstream": "in-process demo response",
            "content_retained": False,
        },
        "workload": {
            "warmup": args.warmup,
            "iterations": args.iterations,
            "operation": "authenticated low-risk MCP tool call",
        },
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 3),
            "p50": round(statistics.median(latencies), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "max": round(max(latencies), 3),
        },
        "throughput_requests_per_second": round(args.iterations / elapsed, 3),
        "result": {
            "errors": 0,
            "target_p95_ms": 100,
            "target_p99_ms": 250,
            "target_met": percentile(latencies, 0.95) < 100 and percentile(latencies, 0.99) < 250,
        },
        "limits": [
            "This is a local component benchmark, not a production capacity test.",
            "It does not include network, PostgreSQL, OPA, semantic model, or upstream tool time.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(args.output)


if __name__ == "__main__":
    main()
