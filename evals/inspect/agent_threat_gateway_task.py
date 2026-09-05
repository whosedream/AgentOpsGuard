from __future__ import annotations

from collections import Counter
import json
import os
from typing import Any

from inspect_ai import Task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, Target, accuracy, scorer
from inspect_ai.solver import Generate, Solver, TaskState, generate, solver, system_message
from inspect_ai.tool import Tool, ToolCall, ToolDef
from inspect_ai.util import store as inspect_store
from inspect_evals.agent_threat_bench.agent_threat_bench import (
    AUTONOMY_HIJACK_SYSTEM_PROMPT,
    DATA_EXFIL_SYSTEM_PROMPT,
    MEMORY_POISON_SYSTEM_PROMPT,
)
from inspect_evals.agent_threat_bench.dataset import load_agent_threat_bench_dataset
from inspect_evals.agent_threat_bench.scorer import (
    _score_autonomy_hijack,
    _score_data_exfil,
    _score_memory_poison,
    agent_threat_bench_scorer,
)
from inspect_evals.agent_threat_bench.tools import use_agent_threat_bench_tools
from mcp import Client
from mcp.shared.exceptions import MCPError

from agentops_guard.backend.services.content_provenance import render_untrusted_model_data


TASK_NAMES = ("memory_poison", "autonomy_hijack", "data_exfil")
SYSTEM_PROMPTS = {
    "memory_poison": MEMORY_POISON_SYSTEM_PROMPT,
    "autonomy_hijack": AUTONOMY_HIJACK_SYSTEM_PROMPT,
    "data_exfil": DATA_EXFIL_SYSTEM_PROMPT,
}
UNTRUSTED_READ_TOOLS = {"memory_read", "read_inbox", "lookup_customer"}
TOOL_ACTIONS = {
    "categorize_email": "write",
    "draft_summary": "write",
    "memory_write": "write",
    "resolve_ticket": "write",
    "send_message": "send",
}

_GATEWAY_TOOL_NAMES: dict[str, str] | None = None
_METRICS: dict[str, Counter[str]] = {}


def _mcp_error_codes(errors: BaseExceptionGroup[MCPError]) -> list[int]:
    pending: list[BaseException] = list(errors.exceptions)
    codes: set[int] = set()
    while pending:
        error = pending.pop()
        if isinstance(error, MCPError):
            codes.add(error.code)
        elif isinstance(error, BaseExceptionGroup):
            pending.extend(error.exceptions)
        else:
            raise RuntimeError("MCP error group contained an unexpected exception type")
    return sorted(codes)


def is_attack_sample(sample: Sample) -> bool:
    attack_name = str((sample.metadata or {}).get("attack_name") or "").casefold()
    return not attack_name.startswith("clean")


def reset_gateway_metrics() -> None:
    global _GATEWAY_TOOL_NAMES
    _GATEWAY_TOOL_NAMES = None
    _METRICS.clear()


def aggregate_gateway_metrics(sample_ids: set[str]) -> dict[str, Any]:
    aggregate: Counter[str] = Counter()
    for sample_id in sample_ids:
        aggregate.update(_METRICS.get(sample_id, Counter()))
    return {
        "samples": len(sample_ids),
        "tool_calls": aggregate["tool_calls"],
        "untrusted_outputs_scanned": aggregate["untrusted_outputs_scanned"],
        "content_blocks": aggregate["content_blocks"],
        "high_risk_action_attempts": aggregate["high_risk_action_attempts"],
        "high_risk_action_blocks": aggregate["high_risk_action_blocks"],
        "high_risk_actions_executed": aggregate["high_risk_actions_executed"],
        "low_risk_actions_executed": aggregate["low_risk_actions_executed"],
        "paused_tool_calls": aggregate["paused_tool_calls"],
        "gateway_errors": aggregate["gateway_errors"],
    }


async def _gateway_tool_names(url: str) -> dict[str, str]:
    global _GATEWAY_TOOL_NAMES
    if _GATEWAY_TOOL_NAMES is not None:
        return _GATEWAY_TOOL_NAMES
    async with Client(url, read_timeout_seconds=10) as client:
        result = await client.list_tools()
    names: dict[str, str] = {}
    for item in result.tools:
        title = item.title or ""
        if ": " not in title:
            continue
        upstream_name = title.split(": ", 1)[1]
        names[upstream_name] = item.name
    expected = {
        "read_action",
        "write_action",
        "send_action",
        "delete_action",
        "payment_action",
        "permission_action",
        "network_action",
        "scan_external_output",
    }
    if set(names) != expected:
        raise RuntimeError("AgentOps Guard evaluation tool inventory changed")
    _GATEWAY_TOOL_NAMES = names
    return names


async def _call_gateway(
    *,
    upstream_name: str,
    arguments: dict[str, Any],
    run_id: str,
) -> tuple[bool, str | None, str | None]:
    url = os.environ["AGENTOPS_EVAL_MCP_URL"]
    try:
        names = await _gateway_tool_names(url)
        async with Client(url, read_timeout_seconds=10) as client:
            result = await client.call_tool(
                names[upstream_name],
                arguments,
                read_timeout_seconds=10,
                meta={"io.agentops/request": {"runId": run_id}},
            )
    except* MCPError as errors:
        codes = _mcp_error_codes(errors)
        code_text = "_".join(str(code) for code in codes)
        raise RuntimeError(f"Gateway MCP error code {code_text}") from None
    control = (result.meta or {}).get("io.agentops/control") or {}
    policy = control.get("policyDecision") or {}
    reason = policy.get("reason_code")
    allowed = not bool(result.is_error)
    visible_text = "\n".join(
        item.text for item in result.content if getattr(item, "type", None) == "text"
    )
    if not allowed and reason is None and visible_text == "run_awaiting_approval":
        reason = visible_text
    return (
        allowed,
        str(reason) if reason is not None else None,
        visible_text if allowed and visible_text else None,
    )


def _record_executed_call(tool_name: str, arguments: dict[str, Any]) -> None:
    calls = list(inspect_store().get("agentops_guard_executed_calls", []))
    calls.append({"function": tool_name, "arguments": arguments})
    inspect_store().set("agentops_guard_executed_calls", calls)


def _guard_tool(original: Tool, *, sample_id: str, run_id: str) -> Tool:
    definition = ToolDef(original)

    async def execute(**kwargs: Any) -> Any:
        metrics = _METRICS.setdefault(sample_id, Counter())
        metrics["tool_calls"] += 1
        action = TOOL_ACTIONS.get(definition.name, "read")
        if action != "read":
            metrics["high_risk_action_attempts"] += 1
        allowed, _reason, _gateway_text = await _call_gateway(
            upstream_name=f"{action}_action",
            arguments={"source_tool": definition.name, "arguments": kwargs},
            run_id=run_id,
        )
        if not allowed:
            if _reason == "run_awaiting_approval":
                metrics["paused_tool_calls"] += 1
                return "AgentOps Guard kept this run paused for human approval."
            if action == "read":
                metrics["gateway_errors"] += 1
            else:
                metrics["high_risk_action_blocks"] += 1
            return "AgentOps Guard stopped this tool call before it changed any data."

        result = await original(**kwargs)
        _record_executed_call(definition.name, kwargs)
        if action == "read":
            metrics["low_risk_actions_executed"] += 1
        else:
            metrics["high_risk_actions_executed"] += 1

        if definition.name in UNTRUSTED_READ_TOOLS:
            metrics["untrusted_outputs_scanned"] += 1
            if isinstance(result, str):
                content = result
            else:
                content = json.dumps(result, ensure_ascii=False, sort_keys=True, default=str)
            visible, _reason, safe_content = await _call_gateway(
                upstream_name="scan_external_output",
                arguments={"source_tool": definition.name, "content": content},
                run_id=run_id,
            )
            if not visible:
                metrics["content_blocks"] += 1
                return "AgentOps Guard quarantined untrusted content from this source."
            if safe_content is None:
                raise RuntimeError("Gateway returned no inspected external content")
            return render_untrusted_model_data(safe_content, source=definition.name)
        return result

    return ToolDef(
        execute,
        name=definition.name,
        description=definition.description,
        parameters=definition.parameters,
        parallel=False,
    ).as_tool()


@solver
def use_guarded_agent_threat_tools(task_name: str) -> Solver:
    if task_name not in TASK_NAMES:
        raise ValueError("unsupported AgentThreatBench task")
    setup_tools = use_agent_threat_bench_tools(task_name)

    async def solve(state: TaskState, generate_fn: Generate) -> TaskState:
        state = await setup_tools(state, generate_fn)
        sample_id = str(state.sample_id)
        run_ids = json.loads(os.environ["AGENTOPS_EVAL_RUN_IDS"])
        run_id = run_ids.get(sample_id)
        if not isinstance(run_id, str) or not run_id:
            raise RuntimeError("AgentThreatBench sample is not bound to a trusted run")
        inspect_store().set("agentops_guard_executed_calls", [])
        state.tools = [
            _guard_tool(tool, sample_id=sample_id, run_id=run_id) for tool in state.tools
        ]
        return state

    return solve


@scorer(metrics={"effect_utility": [accuracy()], "effect_security": [accuracy()]})
def gateway_effect_scorer():
    async def score(state: TaskState, _target: Target) -> Score:
        metadata = state.metadata or {}
        calls = [
            ToolCall(
                id=str(index),
                function=str(call["function"]),
                arguments=dict(call["arguments"]),
                type="function",
            )
            for index, call in enumerate(
                inspect_store().get("agentops_guard_executed_calls", [])
            )
        ]
        completion = state.output.completion if state.output is not None else ""
        task_type = metadata.get("task_type")
        if task_type == "memory_poison":
            utility, security = _score_memory_poison(completion, calls, metadata)
        elif task_type == "autonomy_hijack":
            utility, security = _score_autonomy_hijack(completion, calls, metadata)
        elif task_type == "data_exfil":
            utility, security = _score_data_exfil(completion, calls, metadata)
        else:
            raise RuntimeError("AgentThreatBench task metadata changed")
        return Score(
            value={
                "effect_utility": CORRECT if utility else INCORRECT,
                "effect_security": CORRECT if security else INCORRECT,
            }
        )

    return score


def build_agent_threat_task(task_name: str, *, kind: str, guarded: bool) -> Task:
    if task_name not in TASK_NAMES or kind not in {"attack", "benign"}:
        raise ValueError("unsupported AgentThreatBench task selection")
    dataset = load_agent_threat_bench_dataset(task_name)
    samples = [
        sample
        for sample in dataset
        if is_attack_sample(sample) == (kind == "attack")
    ]
    if not samples:
        raise RuntimeError("AgentThreatBench selection is empty")
    tool_setup = (
        use_guarded_agent_threat_tools(task_name)
        if guarded
        else use_agent_threat_bench_tools(task_name)
    )
    scorers = [agent_threat_bench_scorer()]
    if guarded:
        scorers.append(gateway_effect_scorer())
    return Task(
        dataset=MemoryDataset(
            samples=samples,
            name=f"agent_threat_bench_{task_name}_{kind}",
        ),
        solver=[
            system_message(SYSTEM_PROMPTS[task_name]),
            tool_setup,
            generate(tool_calls="loop"),
        ],
        scorer=scorers,
        max_messages=20,
        metadata={
            "source": "inspect-evals-0.16.0",
            "guarded": guarded,
            "kind": kind,
        },
    )
