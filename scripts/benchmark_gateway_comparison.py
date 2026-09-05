from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sqlite3
import statistics
import subprocess
import time
from typing import Any

import httpx


MCP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}


def rpc(client: httpx.Client, url: str, method: str, params: dict[str, Any]) -> Any:
    response = client.post(
        url,
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": method, "method": method, "params": params},
    )
    response.raise_for_status()
    body = response.json()
    if "error" in body:
        raise RuntimeError(body["error"])
    return body["result"]


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * quantile))]


def latency(run, warmup: int, iterations: int) -> dict[str, float | int]:
    for _ in range(warmup):
        run()
    values = []
    for _ in range(iterations):
        started = time.perf_counter()
        run()
        values.append((time.perf_counter() - started) * 1000)
    return {
        "iterations": iterations,
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "max_ms": round(max(values), 3),
    }


def sqlite_summary(path: Path, selected_tables: tuple[str, ...]) -> dict[str, Any]:
    with sqlite3.connect(path) as db:
        tables = [
            row[0]
            for row in db.execute(
                "select name from sqlite_master where type='table' and name not like 'sqlite_%'"
            )
        ]
        selected = {}
        for table in selected_tables:
            if table not in tables:
                continue
            selected[table] = {
                "rows": db.execute(f"select count(*) from {table}").fetchone()[0],
                "fields": [row[1] for row in db.execute(f"pragma table_info({table})")],
            }
    return {"table_count": len(tables), "selected_tables": selected}


def decision_summary(body: dict[str, Any]) -> dict[str, Any]:
    decision = body.get("policyDecision") or {}
    return {
        "is_error": bool(body.get("isError")),
        "action": decision.get("action"),
        "reason_code": decision.get("reason_code"),
        "approval_created": bool(body.get("approvalRequestId")),
    }


def git_metadata(root: Path) -> dict[str, Any]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    return {"commit": commit, "dirty": dirty}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agentops-url", default="http://127.0.0.1:19092")
    parser.add_argument("--contextforge-url", default="http://127.0.0.1:19091")
    parser.add_argument("--reference-url", default="http://127.0.0.1:19090")
    parser.add_argument("--project-id", default="comparison")
    parser.add_argument("--agentops-internal-server", default="reference")
    parser.add_argument("--agentops-external-server", default="reference-external")
    parser.add_argument("--contextforge-prefix", default="agentops-reference")
    parser.add_argument("--agentops-db", type=Path, required=True)
    parser.add_argument("--contextforge-db", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--agentops-startup-ms", type=float)
    parser.add_argument("--contextforge-startup-ms", type=float)
    parser.add_argument("--agentops-rss-kib", type=int)
    parser.add_argument("--contextforge-rss-kib", type=int)
    parser.add_argument("--agentops-environment-packages", type=int)
    parser.add_argument("--contextforge-environment-packages", type=int)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    agentops_api_key = os.environ.get("AGENTOPS_BENCHMARK_API_KEY")
    if not agentops_api_key:
        raise SystemExit("AGENTOPS_BENCHMARK_API_KEY must be supplied by the trusted runner")

    project_query = {"project_id": args.project_id}
    agentops_headers = {"X-AgentOps-Api-Key": agentops_api_key}
    with httpx.Client(timeout=30.0) as client:
        agentops_tools_response = client.get(
            f"{args.agentops_url}/mcp/tools/list",
            params=project_query,
            headers=agentops_headers,
        )
        agentops_tools_response.raise_for_status()
        agentops_tools = agentops_tools_response.json()["tools"]
        agentops_resources = client.get(
            f"{args.agentops_url}/mcp/resources/list",
            params=project_query,
            headers=agentops_headers,
        ).json()["resources"]
        agentops_prompts = client.get(
            f"{args.agentops_url}/mcp/prompts/list",
            params=project_query,
            headers=agentops_headers,
        ).json()["prompts"]
        standard_probe = client.post(
            f"{args.agentops_url}/mcp",
            headers={**MCP_HEADERS, **agentops_headers},
            json={
                "jsonrpc": "2.0",
                "id": "initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "comparison", "version": "1"},
                },
            },
        )

        contextforge_mcp = f"{args.contextforge_url}/mcp"
        contextforge_init = rpc(
            client,
            contextforge_mcp,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "comparison", "version": "1"},
            },
        )
        contextforge_tools = rpc(client, contextforge_mcp, "tools/list", {})["tools"]
        contextforge_resources = rpc(client, contextforge_mcp, "resources/list", {})["resources"]
        contextforge_prompts = rpc(client, contextforge_mcp, "prompts/list", {})["prompts"]

        def agentops_call(server_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            response = client.post(
                f"{args.agentops_url}/mcp/tools/call",
                params=project_query,
                headers=agentops_headers,
                json={"serverId": server_id, "name": name, "arguments": arguments},
            )
            response.raise_for_status()
            return response.json()

        def contextforge_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            return rpc(
                client,
                contextforge_mcp,
                "tools/call",
                {
                    "name": f"{args.contextforge_prefix}-{name.replace('_', '-')}",
                    "arguments": arguments,
                },
            )

        agentops_external = agentops_call(args.agentops_external_server, "echo", {"text": "probe"})
        agentops_injection = agentops_call(args.agentops_internal_server, "wrapped_instruction", {})
        agentops_write = agentops_call(
            args.agentops_internal_server,
            "mutate_record",
            {"record_id": "record-1", "value": "value-1"},
        )
        agentops_structured = agentops_call(
            args.agentops_internal_server, "structured_echo", {"text": "probe"}
        )
        contextforge_injection = contextforge_call("wrapped_instruction", {})
        contextforge_write = contextforge_call(
            "mutate_record", {"record_id": "record-1", "value": "value-1"}
        )
        contextforge_structured = contextforge_call("structured_echo", {"text": "probe"})

        injection_marker = "PRIORITY MESSAGE"
        report = {
            "metadata": {
                "generated_at": datetime.now(UTC).isoformat(),
                "repository": git_metadata(Path(__file__).resolve().parents[1]),
                "contextforge_version": "1.0.7",
                "contextforge_sdist_sha256": "ee68d3fa609aa7b97da68ca22c9e89a8c5e61395cf9efbea1f0df8015fcc6b55",
                "semantic_scanner": "disabled for protocol and latency parity",
                "rate_limiting": "disabled during latency measurement",
            },
            "protocol": {
                "agentops": {
                    "standard_mcp_initialize_http_status": standard_probe.status_code,
                    "tools": sorted({tool["name"] for tool in agentops_tools}),
                    "resources": len(agentops_resources),
                    "prompts": len(agentops_prompts),
                    "upstream_adapter": "GET /tools/list and POST /tools/call",
                },
                "contextforge": {
                    "protocol_version": contextforge_init["protocolVersion"],
                    "tools": sorted(tool["name"] for tool in contextforge_tools),
                    "resources": len(contextforge_resources),
                    "prompts": len(contextforge_prompts),
                    "upstream_adapter": "MCP Streamable HTTP",
                },
            },
            "policy": {
                "agentops_external_read": decision_summary(agentops_external),
                "agentops_indirect_injection": {
                    **decision_summary(agentops_injection),
                    "attack_text_returned": injection_marker in json.dumps(agentops_injection),
                },
                "agentops_destructive_write": decision_summary(agentops_write),
                "agentops_structured_content_preserved": "structuredContent" in agentops_structured,
                "contextforge_indirect_injection": {
                    "is_error": bool(contextforge_injection.get("isError")),
                    "attack_text_returned": injection_marker in json.dumps(contextforge_injection),
                },
                "contextforge_destructive_write": {
                    "is_error": bool(contextforge_write.get("isError")),
                    "executed": contextforge_write.get("structuredContent", {}).get("status")
                    == "simulated",
                },
                "contextforge_structured_content_preserved": bool(
                    contextforge_structured.get("structuredContent")
                ),
            },
            "latency": {
                "agentops_guard": latency(
                    lambda: agentops_call(
                        args.agentops_internal_server, "echo", {"text": "latency-probe"}
                    ),
                    10,
                    args.iterations,
                ),
                "contextforge": latency(
                    lambda: contextforge_call("echo", {"text": "latency-probe"}),
                    10,
                    args.iterations,
                ),
                "direct_reference_rest": latency(
                    lambda: client.post(
                        f"{args.reference_url}/tools/call",
                        json={"name": "echo", "arguments": {"text": "latency-probe"}},
                    ).raise_for_status(),
                    10,
                    args.iterations,
                ),
            },
            "audit": {
                "agentops": sqlite_summary(
                    args.agentops_db,
                    ("policy_decisions", "risk_events", "approval_requests", "audit_logs"),
                ),
                "contextforge": sqlite_summary(
                    args.contextforge_db,
                    ("tool_metrics", "audit_trails", "observability_traces", "tools"),
                ),
            },
            "deployment": {
                "agentops": {
                    "cold_startup_ms": args.agentops_startup_ms,
                    "rss_kib": args.agentops_rss_kib,
                    "environment_packages": args.agentops_environment_packages,
                },
                "contextforge": {
                    "cold_startup_ms": args.contextforge_startup_ms,
                    "rss_kib": args.contextforge_rss_kib,
                    "environment_packages": args.contextforge_environment_packages,
                },
            },
        }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(args.output)


if __name__ == "__main__":
    main()
