from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
EVAL_PYTHON = ROOT / "evals" / "inspect" / ".venv" / "bin" / "python"
HARNESS = ROOT / "scripts" / "verify_agent_threat_gateway_eval.py"
LAUNCHER = ROOT / "scripts" / "run_agent_threat_gateway_eval.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_inspect_evals_dependency_is_pinned_and_locked():
    project = (ROOT / "evals" / "inspect" / "pyproject.toml").read_text(encoding="utf-8")
    lock = (ROOT / "evals" / "inspect" / "uv.lock").read_text(encoding="utf-8")

    assert '"inspect-evals==0.16.0"' in project
    assert 'name = "inspect-evals"' in lock
    assert 'version = "0.16.0"' in lock


def test_task_adapter_classifies_only_explicit_high_risk_tools():
    completed = subprocess.run(
        [
            str(EVAL_PYTHON),
            "-c",
                (
                    "import json; "
                    "from mcp.shared.exceptions import MCPError; "
                    "from agent_threat_gateway_task import "
                    "TOOL_ACTIONS, UNTRUSTED_READ_TOOLS, _mcp_error_codes; "
                    "print(json.dumps({'actions': TOOL_ACTIONS, "
                    "'reads': sorted(UNTRUSTED_READ_TOOLS), "
                    "'codes': _mcp_error_codes(ExceptionGroup('outer', "
                    "[MCPError(-32000, 'hidden')]))}, sort_keys=True))"
                ),
        ],
        cwd=ROOT / "evals" / "inspect",
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=True,
    )
    payload = json.loads(completed.stdout)

    assert payload["actions"] == {
        "categorize_email": "write",
        "draft_summary": "write",
        "memory_write": "write",
        "resolve_ticket": "write",
        "send_message": "send",
    }
    assert payload["reads"] == ["lookup_customer", "memory_read", "read_inbox"]
    assert payload["codes"] == [-32000]


def test_guarded_tool_wrapper_executes_in_inspect_runtime():
    completed = subprocess.run(
        [
            str(EVAL_PYTHON),
            "-c",
            """
import json
import os

import agent_threat_gateway_task as module
from inspect_ai import Task, eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import ModelOutput, get_model
from inspect_ai.solver import generate, system_message

os.environ["AGENTOPS_EVAL_RUN_IDS"] = '{"synthetic-wrapper":"run-synthetic"}'

async def allow(**_kwargs):
    return True, "synthetic_allow", "synthetic-value"

module._call_gateway = allow

def outputs(messages, _tools, _tool_choice, _config):
    if not any(message.role == "tool" for message in messages):
        return ModelOutput.for_tool_call(
            "mockllm", "memory_read", {"key": "synthetic-key"}
        )
    return ModelOutput.from_content("mockllm", "done")

task = Task(
    dataset=MemoryDataset(
        [
            Sample(
                id="synthetic-wrapper",
                input="Read the synthetic key.",
                metadata={"memory_store": {"synthetic-key": "synthetic-value"}},
            )
        ]
    ),
    solver=[
        system_message("Use the available read tool."),
        module.use_guarded_agent_threat_tools("memory_poison"),
        generate(tool_calls="loop"),
    ],
)
logs = eval(
    task,
    model=get_model("mockllm/model", custom_outputs=outputs),
    display="none",
    log_samples=False,
    log_model_api=False,
)
print(
    json.dumps(
        {
            "status": logs[0].status,
            "metrics": module.aggregate_gateway_metrics({"synthetic-wrapper"}),
        },
        sort_keys=True,
    )
)
""",
        ],
        cwd=ROOT / "evals" / "inspect",
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=True,
    )
    payload = json.loads(completed.stdout)

    assert payload["status"] == "success"
    assert payload["metrics"]["tool_calls"] == 1
    assert payload["metrics"]["low_risk_actions_executed"] == 1
    assert payload["metrics"]["untrusted_outputs_scanned"] == 1
    assert payload["metrics"]["gateway_errors"] == 0


def test_gateway_proxy_schema_is_closed_and_action_specific(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = _load(HARNESS, "agent_threat_gateway_harness_test")

    action = module._tool_schema()
    content = module._tool_schema(content=True)

    assert action["required"] == ["source_tool", "arguments"]
    assert action["additionalProperties"] is False
    assert content["required"] == ["source_tool", "content"]
    assert module._annotations("delete")["destructiveHint"] is True
    assert module._annotations("read")["readOnlyHint"] is True
    assert set(module.PROXY_ACTIONS) == {
        "read",
        "write",
        "send",
        "delete",
        "payment",
        "permission",
        "network",
    }
    assert module.MAX_MODEL_CHARACTERS == 1_024


def test_subprocess_failure_reports_only_stage_and_error_type(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = _load(HARNESS, "agent_threat_gateway_safe_failure_test")
    stderr = (
        b"external attack text must not escape\n"
        b"RuntimeError: AgentThreatBench guarded evaluation failed [McpError]\n"
    )

    assert module._safe_subprocess_failure(stderr) == "guarded_McpError"
    assert (
        module._safe_subprocess_failure(
            b"RuntimeError: Gateway returned no inspected external content\n"
        )
        == "missing_inspected_content"
    )
    assert (
        module._safe_subprocess_failure(
            b"RuntimeError: AgentThreatBench group memory_poison:attack "
            b"status error error ModelError\n"
        )
        == "memory_poison_attack_error_ModelError"
    )
    gateway_stderr = (
        b'Traceback (most recent call last):\n  File "/private/app.py", line 9, '
        b'in tools_call\nRuntimeError: secret text omitted\n'
    )
    assert module._safe_traceback_failure(gateway_stderr) == "RuntimeError.app.py.tools_call"


def test_weighted_metrics_keep_attempts_and_effects_separate(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = _load(HARNESS, "agent_threat_gateway_aggregation_test")
    payload = {
        "groups": {
            "memory_poison:attack": {
                "samples": 2,
                "metrics": {"security": 0.5, "effect_security": 1.0},
                "gateway": {"high_risk_action_blocks": 1},
            },
            "data_exfil:attack": {
                "samples": 3,
                "metrics": {"security": 0.0, "effect_security": 2 / 3},
                "gateway": {"high_risk_action_blocks": 2},
            },
        }
    }

    assert module._weighted_metric(payload, "attack", "security") == 0.2
    assert module._weighted_metric(payload, "attack", "effect_security") == 0.8
    assert module._gateway_totals(payload, "attack") == {"high_risk_action_blocks": 3}


def test_task_breakdown_keeps_threat_categories_separate(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = _load(HARNESS, "agent_threat_gateway_task_breakdown_test")

    def group(utility, security, effect_utility=None, effect_security=None):
        metrics = {"utility": utility, "security": security}
        if effect_utility is not None:
            metrics["effect_utility"] = effect_utility
            metrics["effect_security"] = effect_security
        return {"samples": 1, "metrics": metrics, "gateway": {"tool_calls": 2}}

    baseline = {"groups": {}}
    guarded = {"groups": {}}
    for task_name in ("memory_poison", "autonomy_hijack", "data_exfil"):
        baseline["groups"][f"{task_name}:attack"] = group(0.25, 0.5)
        baseline["groups"][f"{task_name}:benign"] = group(0.75, 1.0)
        guarded["groups"][f"{task_name}:attack"] = group(0.5, 0.75, 0.5, 1.0)
        guarded["groups"][f"{task_name}:benign"] = group(1.0, 1.0, 1.0, 1.0)

    breakdown = module._task_breakdown(baseline, guarded)

    assert set(breakdown) == {"memory_poison", "autonomy_hijack", "data_exfil"}
    assert breakdown["memory_poison"]["attack"]["guarded_effect_security_rate"] == 1.0
    assert breakdown["data_exfil"]["benign"]["gateway"] == {"tool_calls": 2}


def test_gateway_execution_validation_rejects_disconnected_guard(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = _load(HARNESS, "agent_threat_gateway_execution_validation_test")

    try:
        module._validate_gateway_execution(
            {"tool_calls": 0, "untrusted_outputs_scanned": 0},
            {"tool_calls": 0, "untrusted_outputs_scanned": 0},
            {"action_checks": 0, "content_scans": 0},
        )
    except RuntimeError as error:
        assert str(error) == "guarded evaluation executed no tool calls"
    else:
        raise AssertionError("a disconnected guarded evaluation was accepted")


def test_launcher_freezes_public_source_and_security_boundary(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = _load(LAUNCHER, "agent_threat_gateway_launcher_test")
    inputs = module._frozen_inputs(Path("/tmp/model.gguf"), Path("/tmp/runtime.lock"))

    assert module.INSPECT_EVALS_WHEEL_SHA256 == (
        "4976adca87e64b4becdfcd309bae19b7c01a2ee2e3c7a439724301f3d2a45eb7"
    )
    assert module.INSPECT_EVALS_TAG_COMMIT == "3367d26374083aa794600b9c06b0b4f76faad76d"
    assert {
        "model_artifact",
        "runtime_lock",
        "inspect_lock",
        "inspect_project",
        "launcher",
        "harness",
        "metadata_exporter",
        "inspect_task",
        "inspect_runner",
        "model_adapter",
        "gateway",
        "gateway_protocol",
        "gateway_auth",
        "content_provenance",
        "content_redaction",
        "tool_revisions",
        "policy",
        "scanner",
        "semantic_scanner",
        "holdout_registry",
        "scanner_rule_pack",
        "root_lock",
    } == set(inputs)


def test_launcher_requires_regression_anchor_to_match_consumed_holdout(
    monkeypatch, tmp_path
):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    module = _load(LAUNCHER, "agent_threat_gateway_regression_anchor_test")
    anchor = tmp_path / "not-the-first-run.json"
    anchor.write_text("{}", encoding="utf-8")

    try:
        module._regression_anchor(anchor, "0" * 64)
    except ValueError as error:
        assert str(error) == "regression anchor is not an AgentThreatBench report"
    else:
        raise AssertionError("an unrelated regression anchor was accepted")
