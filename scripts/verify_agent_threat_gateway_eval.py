#!/usr/bin/env python3
"""Run official AgentThreatBench through a real AgentOps Guard decision boundary."""

from __future__ import annotations

from collections import Counter
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

from verify_inspect_agent_eval import (
    EVAL_PYTHON,
    ROOT,
    _contains_token,
    _free_port,
    _run_quiet,
    _safe_environment,
    _stop_process,
    _wait_for_port,
)
from verify_agentdojo_dynamic_gateway_eval import (
    SEMANTIC_MODEL,
    SEMANTIC_MODEL_SHA256,
    _install_scanner_rule_pack,
)
from agentops_guard.backend.services.semantic_scanner import MAX_MODEL_CHARACTERS


EXPORTER = ROOT / "evals" / "inspect" / "export_agent_threat_bench_metadata.py"
RUNNER = ROOT / "evals" / "inspect" / "run_agent_threat_gateway.py"
PROXY_ACTIONS = ("read", "write", "send", "delete", "payment", "permission", "network")
FAILURE_TYPE_PATTERN = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception)):")
EVAL_FAILURE_PATTERN = re.compile(
    r"AgentThreatBench (baseline|guarded) evaluation failed \[([A-Za-z0-9_.-]+)\]"
)
GROUP_FAILURE_PATTERN = re.compile(
    r"AgentThreatBench group "
    r"(memory_poison|autonomy_hijack|data_exfil):(attack|benign) "
    r"status (started|success|cancelled|error|log_count_changed) "
    r"error ([A-Za-z0-9_.-]+)"
)
SAFE_FAILURE_CODES = {
    "Gateway returned no inspected external content": "missing_inspected_content",
    "AgentThreatBench Inspect run did not complete": "inspect_run_incomplete",
    "AgentThreatBench sample count changed during execution": "sample_count_changed",
}
MCP_FAILURE_CODE_PATTERN = re.compile(r"Gateway MCP error code (-?[0-9]+)")


def _eval_environment() -> dict[str, str]:
    return {**_safe_environment(), "PYTHONPATH": str(ROOT / "src")}


def _safe_subprocess_failure(stderr: bytes) -> str:
    text = stderr.decode("utf-8", errors="replace")
    mcp_codes = MCP_FAILURE_CODE_PATTERN.findall(text)
    if mcp_codes:
        return f"gateway_mcp_code_{mcp_codes[-1]}"
    group_matches = GROUP_FAILURE_PATTERN.findall(text)
    if group_matches:
        task_name, kind, status, error_type = group_matches[-1]
        return f"{task_name}_{kind}_{status}_{error_type}"
    for message, code in SAFE_FAILURE_CODES.items():
        if message in text:
            return code
    matches = EVAL_FAILURE_PATTERN.findall(text)
    if matches:
        mode, error_type = matches[-1]
        return f"{mode}_{error_type}"
    for line in reversed(text.splitlines()):
        match = FAILURE_TYPE_PATTERN.match(line.strip())
        if match:
            return match.group(1)
    return "process_exit_nonzero"


def _safe_traceback_failure(stderr: bytes) -> str:
    text = stderr.decode("utf-8", errors="replace")
    error_type = "unclassified_error"
    for line in reversed(text.splitlines()):
        match = FAILURE_TYPE_PATTERN.match(line.strip())
        if match:
            error_type = match.group(1)
            break
    locations: list[str] = []
    frame_pattern = re.compile(
        r'^\s*File "([^"]+)", line [0-9]+, in ([A-Za-z_][A-Za-z0-9_]*)$'
    )
    for line in reversed(text.splitlines()):
        match = frame_pattern.match(line)
        if match:
            locations.append(f"{Path(match.group(1)).name}.{match.group(2)}")
            if len(locations) == 6:
                break
    return ".".join([error_type, *locations])


def _export_metadata(
    environment: dict[str, str], prompt_output: Path | None = None
) -> dict[str, Any]:
    command = [str(EVAL_PYTHON), str(EXPORTER)]
    if prompt_output is not None:
        command.extend(["--prompt-output", str(prompt_output)])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("AgentThreatBench metadata export failed")
    payload = json.loads(completed.stdout)
    if (
        payload.get("package_version") != "0.16.0"
        or payload.get("task_version") != "1-A"
        or payload.get("total") != 24
    ):
        raise RuntimeError("AgentThreatBench source inventory changed")
    counts = payload.get("counts")
    if not isinstance(counts, dict) or set(counts) != {
        "memory_poison",
        "autonomy_hijack",
        "data_exfil",
    }:
        raise RuntimeError("AgentThreatBench task inventory changed")
    return payload


def corpus_metadata() -> dict[str, Any]:
    if not EVAL_PYTHON.is_file():
        raise RuntimeError("Inspect evaluation environment is not installed")
    return _export_metadata(_eval_environment())


def _tool_schema(*, content: bool = False) -> dict[str, Any]:
    if content:
        return {
            "type": "object",
            "properties": {
                "source_tool": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["source_tool", "content"],
            "additionalProperties": False,
        }
    return {
        "type": "object",
        "properties": {
            "source_tool": {"type": "string"},
            "arguments": {"type": "object"},
        },
        "required": ["source_tool", "arguments"],
        "additionalProperties": False,
    }


def _annotations(action: str) -> dict[str, bool]:
    return {
        "readOnlyHint": action == "read",
        "destructiveHint": action == "delete",
        "idempotentHint": action == "read",
        "openWorldHint": action in {"send", "payment", "network"},
    }


def _seed_gateway(
    database_url: str,
    upstream_url: str,
    prompts: dict[str, str],
) -> tuple[str, dict[str, str]]:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from agentops_guard.backend.models import McpServer, McpTool, Run
    from agentops_guard.backend.schemas import ContentIn
    from agentops_guard.backend.services.api_keys import create_api_key
    from agentops_guard.backend.services.content import new_id, persist_content
    from agentops_guard.backend.services.policy import (
        INTENT_MANIFEST_KEY,
        build_user_intent_manifest,
    )
    from agentops_guard.backend.services.projects import ensure_project

    engine = create_engine(database_url)
    session = sessionmaker(bind=engine)()
    try:
        ensure_project(session, "agent-threat-eval")
        session.add(
            McpServer(
                id="agent-threat-proxy",
                project_id="agent-threat-eval",
                name="AgentThreatBench policy adapter",
                transport="streamable_http",
                url=upstream_url,
                trust_level="internal",
                allowed_agents=[],
                status="active",
            )
        )
        tools = [
            McpTool(
                id=f"agent-threat-proxy:{action}_action",
                project_id="agent-threat-eval",
                server_id="agent-threat-proxy",
                name=f"{action}_action",
                description=f"Authorize one {action} action before local benchmark execution.",
                input_schema=_tool_schema(),
                annotations=_annotations(action),
                status="active",
            )
            for action in PROXY_ACTIONS
        ]
        tools.append(
            McpTool(
                id="agent-threat-proxy:scan_external_output",
                project_id="agent-threat-eval",
                server_id="agent-threat-proxy",
                name="scan_external_output",
                description="Scan one untrusted tool result before it enters model context.",
                input_schema=_tool_schema(content=True),
                annotations=_annotations("read"),
                status="active",
            )
        )
        session.add_all(tools)
        _, token = create_api_key(
            session,
            "agent-threat-eval",
            "agent-threat-eval-agent",
            ["mcp:read", "mcp:invoke"],
            agent_id="agent-threat-eval-agent",
        )
        run_ids: dict[str, str] = {}
        for sample_id, prompt in prompts.items():
            run_id = new_id("run")
            input_ref = persist_content(
                session,
                "agent-threat-eval",
                ContentIn(text=prompt, store_raw=False),
            )
            session.add(
                Run(
                    id=run_id,
                    project_id="agent-threat-eval",
                    agent_id="agent-threat-eval-agent",
                    trace_id=new_id("trace"),
                    name="AgentThreatBench guarded sample",
                    input_ref=input_ref,
                    metadata_json={
                        INTENT_MANIFEST_KEY: build_user_intent_manifest(prompt),
                    },
                )
            )
            run_ids[sample_id] = run_id
        session.commit()
        return token, run_ids
    finally:
        session.close()
        engine.dispose()


def _database_summary(database_url: str) -> dict[str, Any]:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from agentops_guard.backend.models import ApprovalRequest, PolicyDecision, RiskEvent

    engine = create_engine(database_url)
    session = sessionmaker(bind=engine)()
    try:
        decisions = session.query(PolicyDecision).all()
        risks = session.query(RiskEvent).all()
        reasons = Counter(row.reason_code for row in decisions)
        action_decisions = [
            row
            for row in decisions
            if isinstance(row.context, dict)
            and isinstance(row.context.get("tool"), dict)
            and str(row.context["tool"].get("name") or "").endswith("_action")
        ]
        content_decisions = [
            row
            for row in decisions
            if isinstance(row.context, dict)
            and isinstance(row.context.get("tool"), dict)
            and row.context["tool"].get("name") == "scan_external_output"
        ]
        content_scan_requests = [
            row
            for row in content_decisions
            if isinstance(row.context.get("data"), dict)
            and row.context["data"].get("content_source") == "mcp_tool_arguments"
        ]
        content_result_decisions = [
            row
            for row in content_decisions
            if isinstance(row.context.get("data"), dict)
            and row.context["data"].get("content_source") == "mcp_tool_result"
        ]
        return {
            "policy_decisions": len(decisions),
            "action_checks": len(action_decisions),
            "action_checks_blocked": sum(row.action != "allow" for row in action_decisions),
            "content_scans": len(content_scan_requests),
            "content_scans_blocked": sum(
                row.action != "allow" for row in content_scan_requests
            ),
            "content_result_decisions": len(content_result_decisions),
            "content_result_non_allow_decisions": sum(
                row.action != "allow" for row in content_result_decisions
            ),
            "approval_requests": session.query(ApprovalRequest).count(),
            "semantic_shadow_hits": sum(
                row.risk_type == "semantic_prompt_injection_shadow" for row in risks
            ),
            "other_risk_events": sum(
                row.risk_type != "semantic_prompt_injection_shadow" for row in risks
            ),
            "reason_codes": dict(sorted(reasons.items())),
        }
    finally:
        session.close()
        engine.dispose()


def _run_mode(
    *,
    mode: str,
    model_url: str,
    model_id: str,
    logs: Path,
    run_ids: dict[str, str],
    environment: dict[str, str],
) -> tuple[dict[str, Any], bytes]:
    completed = subprocess.run(
        [str(EVAL_PYTHON), str(RUNNER)],
        cwd=ROOT,
        env={
            **environment,
            "PYTHONPATH": str(ROOT / "src"),
            "AGENTOPS_EVAL_MODE": mode,
            "AGENTOPS_EVAL_LOCAL_MODEL_URL": model_url,
            "AGENTOPS_EVAL_LOCAL_MODEL_ID": model_id,
            "AGENTOPS_EVAL_LOG_DIR": str(logs / mode),
            "AGENTOPS_EVAL_GENERATION_SEED": "0",
            "AGENTOPS_EVAL_RUN_IDS": json.dumps(run_ids, separators=(",", ":")),
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=7_200,
        check=False,
    )
    if completed.returncode != 0:
        failure = _safe_subprocess_failure(completed.stderr)
        raise RuntimeError(f"AgentThreatBench {mode} evaluation failed [{failure}]")
    return json.loads(completed.stdout.decode("utf-8").splitlines()[-1]), completed.stdout


def _weighted_metric(payload: dict[str, Any], kind: str, metric: str) -> float:
    numerator = 0.0
    denominator = 0
    for key, group in payload["groups"].items():
        if not key.endswith(f":{kind}"):
            continue
        samples = int(group["samples"])
        value = group["metrics"].get(metric)
        if value is not None:
            numerator += samples * float(value)
            denominator += samples
    if denominator == 0:
        raise RuntimeError("AgentThreatBench metric is missing")
    return numerator / denominator


def _gateway_totals(payload: dict[str, Any], kind: str) -> dict[str, int]:
    totals: Counter[str] = Counter()
    for key, group in payload["groups"].items():
        if key.endswith(f":{kind}"):
            totals.update(group["gateway"])
    return dict(sorted(totals.items()))


def _task_breakdown(
    baseline: dict[str, Any], guarded: dict[str, Any]
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for task_name in ("memory_poison", "autonomy_hijack", "data_exfil"):
        attack_key = f"{task_name}:attack"
        benign_key = f"{task_name}:benign"
        baseline_attack = baseline["groups"][attack_key]
        baseline_benign = baseline["groups"][benign_key]
        guarded_attack = guarded["groups"][attack_key]
        guarded_benign = guarded["groups"][benign_key]
        result[task_name] = {
            "attack": {
                "samples": guarded_attack["samples"],
                "baseline_utility_rate": baseline_attack["metrics"]["utility"],
                "baseline_model_resistance_rate": baseline_attack["metrics"]["security"],
                "guarded_utility_rate_by_attempts": guarded_attack["metrics"]["utility"],
                "guarded_model_resistance_rate": guarded_attack["metrics"]["security"],
                "guarded_effect_utility_rate": guarded_attack["metrics"]["effect_utility"],
                "guarded_effect_security_rate": guarded_attack["metrics"]["effect_security"],
                "gateway": guarded_attack["gateway"],
            },
            "benign": {
                "samples": guarded_benign["samples"],
                "baseline_utility_rate": baseline_benign["metrics"]["utility"],
                "guarded_utility_rate_by_attempts": guarded_benign["metrics"]["utility"],
                "guarded_effect_utility_rate": guarded_benign["metrics"]["effect_utility"],
                "gateway": guarded_benign["gateway"],
            },
        }
    return result


def _validate_gateway_execution(
    attack_gateway: dict[str, int],
    benign_gateway: dict[str, int],
    database: dict[str, Any],
) -> None:
    tool_calls = attack_gateway.get("tool_calls", 0) + benign_gateway.get("tool_calls", 0)
    paused_tool_calls = attack_gateway.get(
        "paused_tool_calls", 0
    ) + benign_gateway.get("paused_tool_calls", 0)
    untrusted_scans = attack_gateway.get(
        "untrusted_outputs_scanned", 0
    ) + benign_gateway.get("untrusted_outputs_scanned", 0)
    if tool_calls <= 0:
        raise RuntimeError("guarded evaluation executed no tool calls")
    if database["action_checks"] + paused_tool_calls != tool_calls:
        raise RuntimeError("gateway action-check count does not match guarded tool calls")
    if database["content_scans"] != untrusted_scans:
        raise RuntimeError("gateway content-scan count does not match guarded read outputs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-model-url", required=True)
    parser.add_argument("--local-model-id", required=True)
    parser.add_argument("--guarded-only", action="store_true")
    args = parser.parse_args()
    if not EVAL_PYTHON.is_file():
        raise RuntimeError("Inspect evaluation environment is not installed")
    environment = _eval_environment()
    with tempfile.TemporaryDirectory(prefix="agentops-agent-threat-") as temp_dir:
        temp = Path(temp_dir)
        prompt_file = temp / "trusted-prompts.json"
        metadata = _export_metadata(environment, prompt_file)
        prompts = json.loads(prompt_file.read_text(encoding="utf-8"))
        if len(prompts) != metadata["total"]:
            raise RuntimeError("AgentThreatBench prompt inventory changed")
        logs = temp / "logs"
        upstream_port = _free_port()
        gateway_port = _free_port()
        injector_port = _free_port()
        upstream_script = temp / "policy_adapter_upstream.py"
        upstream_script.write_text(
            f'''from mcp.server import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("agent-threat-policy-adapter")

def register_action(name, read_only=False, destructive=False, open_world=False):
    async def action(source_tool: str, arguments: dict) -> str:
        return "authorized"
    server.add_tool(
        action,
        name=name,
        description="Authorize a benchmark tool action.",
        annotations=ToolAnnotations(
            readOnlyHint=read_only,
            destructiveHint=destructive,
            idempotentHint=read_only,
            openWorldHint=open_world,
        ),
    )

register_action("read_action", read_only=True)
register_action("write_action")
register_action("send_action", open_world=True)
register_action("delete_action", destructive=True)
register_action("payment_action", open_world=True)
register_action("permission_action")
register_action("network_action", open_world=True)

@server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False))
async def scan_external_output(source_tool: str, content: str) -> str:
    return content

server.run(transport="streamable-http", host="127.0.0.1", port={upstream_port}, stateless_http=True, json_response=True)
''',
            encoding="utf-8",
        )
        upstream = subprocess.Popen(
            [sys.executable, str(upstream_script)],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        gateway: subprocess.Popen[Any] | None = None
        injector: subprocess.Popen[Any] | None = None
        gateway_error_path = temp / "gateway-errors.log"
        gateway_error_handle = gateway_error_path.open("xb")
        evaluation_error: RuntimeError | None = None
        token = ""
        database_url = f"sqlite:///{(temp / 'gateway.sqlite3').as_posix()}"
        try:
            _wait_for_port(upstream, upstream_port)
            gateway_environment = {
                **environment,
                "AGENTOPS_ENV": "test",
                "AGENTOPS_COMPONENT": "gateway",
                "AGENTOPS_DATABASE_URL": database_url,
                "AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP": "true",
                "AGENTOPS_API_KEY": "unused-test-bootstrap",
                "AGENTOPS_OPERATOR_API_KEY": "unused-test-operator",
                "AGENTOPS_MCP_PUBLIC_URL": f"http://127.0.0.1:{gateway_port}/mcp",
                "AGENTOPS_MCP_ALLOWED_HOSTS": "127.0.0.1,127.0.0.1:*",
                "AGENTOPS_MCP_ALLOWED_ORIGINS": "http://127.0.0.1:3000",
                "AGENTOPS_SEMANTIC_SCANNER_MODE": "shadow",
                "AGENTOPS_SEMANTIC_MODEL_PATH": str(SEMANTIC_MODEL.resolve()),
                "AGENTOPS_SEMANTIC_MODEL_SHA256": SEMANTIC_MODEL_SHA256,
                "AGENTOPS_SEMANTIC_SCANNER_THRESHOLD": "0.90",
                "AGENTOPS_OPA_URL": "",
                "AGENTOPS_OTEL_ENABLED": "false",
            }
            _run_quiet(
                [sys.executable, "-m", "alembic", "upgrade", "head"],
                gateway_environment,
            )
            token, run_ids = _seed_gateway(
                database_url,
                f"http://127.0.0.1:{upstream_port}/mcp",
                prompts,
            )
            scanner_rule_pack = _install_scanner_rule_pack(database_url)
            gateway = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "agentops_guard.gateway.app:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(gateway_port),
                    "--no-access-log",
                    "--log-level",
                    "error",
                ],
                cwd=ROOT,
                env=gateway_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=gateway_error_handle,
            )
            _wait_for_port(gateway, gateway_port)
            injector_script = temp / "trusted_auth_injector.py"
            injector_script.write_text(
                """import os

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

target = os.environ["AGENTOPS_TRUSTED_MCP_TARGET"]
token = os.environ.pop("AGENTOPS_TRUSTED_MCP_TOKEN")

async def forward(request: Request) -> Response:
    headers = {
        name: value for name, value in request.headers.items()
        if name.lower() not in {"authorization", "content-length", "host"}
    }
    headers["authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(follow_redirects=False, timeout=20) as client:
        upstream = await client.request(
            request.method, target, content=await request.body(), headers=headers
        )
    response_headers = {
        name: value for name, value in upstream.headers.items()
        if name.lower() in {"content-type", "mcp-session-id", "cache-control"}
    }
    return Response(upstream.content, status_code=upstream.status_code, headers=response_headers)

app = Starlette(routes=[Route("/mcp", forward, methods=["GET", "POST", "DELETE"])])
""",
                encoding="utf-8",
            )
            injector = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    f"{injector_script.stem}:app",
                    "--app-dir",
                    str(temp),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(injector_port),
                    "--no-access-log",
                    "--log-level",
                    "error",
                ],
                cwd=ROOT,
                env={
                    **environment,
                    "AGENTOPS_TRUSTED_MCP_TARGET": f"http://127.0.0.1:{gateway_port}/mcp",
                    "AGENTOPS_TRUSTED_MCP_TOKEN": token,
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _wait_for_port(injector, injector_port)
            run_environment = {
                **environment,
                "AGENTOPS_EVAL_MCP_URL": f"http://127.0.0.1:{injector_port}/mcp",
                "AGENTOPS_EVAL_CREDENTIAL_REF": "credential_ref://agent-threat-bench",
            }
            try:
                baseline = None
                baseline_stdout = b""
                if not args.guarded_only:
                    baseline, baseline_stdout = _run_mode(
                        mode="baseline",
                        model_url=args.local_model_url,
                        model_id=args.local_model_id,
                        logs=logs,
                        run_ids=run_ids,
                        environment=run_environment,
                    )
                guarded, guarded_stdout = _run_mode(
                    mode="guarded",
                    model_url=args.local_model_url,
                    model_id=args.local_model_id,
                    logs=logs,
                    run_ids=run_ids,
                    environment=run_environment,
                )
            except RuntimeError as error:
                evaluation_error = error
            if evaluation_error is None:
                if token.encode("utf-8") in baseline_stdout + guarded_stdout or _contains_token(
                    logs, token.encode("utf-8")
                ):
                    raise RuntimeError(
                        "evaluation identity token entered model output or Inspect logs"
                    )
                database = _database_summary(database_url)
        finally:
            if injector is not None:
                _stop_process(injector)
            if gateway is not None:
                _stop_process(gateway)
            _stop_process(upstream)
            gateway_error_handle.close()
        if evaluation_error is not None:
            if token and _contains_token(gateway_error_path, token.encode("utf-8")):
                raise RuntimeError("evaluation identity token entered gateway error logs")
            gateway_failure = _safe_traceback_failure(gateway_error_path.read_bytes())
            raise RuntimeError(f"{evaluation_error} [gateway_{gateway_failure}]") from None
        if token and _contains_token(temp, token.encode("utf-8")):
            raise RuntimeError("evaluation identity token entered a temporary artifact")

    attack_gateway = _gateway_totals(guarded, "attack")
    benign_gateway = _gateway_totals(guarded, "benign")
    _validate_gateway_execution(attack_gateway, benign_gateway, database)
    if args.guarded_only:
        print(
            json.dumps(
                {
                    "diagnostic_mode": "guarded_only",
                    "attack_gateway": attack_gateway,
                    "benign_gateway": benign_gateway,
                    "database": database,
                },
                separators=(",", ":"),
            )
        )
        return 0
    if baseline is None:
        raise RuntimeError("baseline result is missing")
    result = {
        "framework": "inspect-ai",
        "framework_version": "0.3.262",
        "dataset": metadata,
        "baseline": {
            "attack": {
                "utility_rate": _weighted_metric(baseline, "attack", "utility"),
                "model_resistance_rate": _weighted_metric(baseline, "attack", "security"),
            },
            "benign": {
                "utility_rate": _weighted_metric(baseline, "benign", "utility"),
                "security_rate": _weighted_metric(baseline, "benign", "security"),
            },
        },
        "guarded": {
            "attack": {
                "utility_rate_by_attempts": _weighted_metric(guarded, "attack", "utility"),
                "model_resistance_rate": _weighted_metric(guarded, "attack", "security"),
                "effect_utility_rate": _weighted_metric(
                    guarded, "attack", "effect_utility"
                ),
                "effect_security_rate": _weighted_metric(
                    guarded, "attack", "effect_security"
                ),
                "gateway": attack_gateway,
                "unauthorized_high_risk_effects": attack_gateway.get(
                    "high_risk_actions_executed", 0
                ),
            },
            "benign": {
                "utility_rate_by_attempts": _weighted_metric(guarded, "benign", "utility"),
                "security_rate": _weighted_metric(guarded, "benign", "security"),
                "effect_utility_rate": _weighted_metric(
                    guarded, "benign", "effect_utility"
                ),
                "effect_security_rate": _weighted_metric(
                    guarded, "benign", "effect_security"
                ),
                "gateway": benign_gateway,
            },
        },
        "database": database,
        "by_task": _task_breakdown(baseline, guarded),
        "managed_scanner_rule_pack": scanner_rule_pack,
        "semantic_scanner": {
            "mode": "shadow",
            "threshold": 0.9,
            "max_characters": MAX_MODEL_CHARACTERS,
            "model_artifact_sha256": SEMANTIC_MODEL_SHA256,
        },
        "gateway_policy_adapter": True,
        "official_task_environment": True,
        "official_scorer_retained": True,
        "effect_scorer_uses_only_executed_tool_calls": True,
        "real_gateway_process": True,
        "real_standard_mcp_client": True,
        "real_model_execution": False,
        "credential_ref_only_in_agent_context": True,
        "agent_received_raw_identity_token": False,
        "identity_token_in_inspect_logs": False,
        "stores_raw_cases": False,
        "stores_per_case_results": False,
        "stores_model_responses": False,
        "generation_config": baseline["generation_config"],
    }
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
