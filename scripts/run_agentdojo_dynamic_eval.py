#!/usr/bin/env python3
"""Run the adapted AgentDojo dynamic micro-suite on a pinned local Qwen model."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from run_llama_cpp_agent_eval import (
    LLAMA_CPP_PYTHON_PACKAGE,
    QWEN_TOOL_ADAPTER,
    ROOT,
    _adapter_metrics,
    _free_port,
    _locked_python_runtime,
    _pinned_file,
    _python_distribution_metadata,
    _safe_environment,
    _sha256,
    _stop_process_group,
    _wait_for_model,
    _write_new_report,
)


HARNESS = ROOT / "scripts" / "verify_agentdojo_dynamic_gateway_eval.py"
EXPORTER = ROOT / "evals" / "inspect" / "export_agentdojo_dynamic_cases.py"
TASK = ROOT / "evals" / "inspect" / "agentdojo_dynamic_task.py"
RUNNER = ROOT / "evals" / "inspect" / "run_agentdojo_dynamic.py"
MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--llama-cpp-python", required=True, type=Path)
    parser.add_argument("--runtime-lock", required=True, type=Path)
    parser.add_argument("--runtime-lock-sha256", required=True)
    parser.add_argument("--runtime-package-version", required=True)
    parser.add_argument("--runtime-source-sha256", required=True)
    parser.add_argument("--model-artifact", required=True, type=Path)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not MODEL_ID_PATTERN.fullmatch(args.model_id):
        raise ValueError("model id has an unsupported format")
    model, model_size = _pinned_file(
        args.model_artifact,
        args.model_sha256,
        "model artifact",
    )
    python = args.llama_cpp_python.absolute()
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("llama-cpp-python interpreter is not executable")
    lock, lock_size = _locked_python_runtime(
        args.runtime_lock,
        args.runtime_lock_sha256,
        args.runtime_package_version,
        args.runtime_source_sha256,
    )
    distribution = _python_distribution_metadata(python, args.runtime_package_version)
    if LLAMA_CPP_PYTHON_PACKAGE != "llama-cpp-python":
        raise RuntimeError("unexpected local model runtime package")

    model_port = _free_port()
    model_process = subprocess.Popen(
        [
            str(python),
            "-m",
            "llama_cpp.server",
            "--model",
            str(model),
            "--model_alias",
            args.model_id,
            "--host",
            "127.0.0.1",
            "--port",
            str(model_port),
            "--chat_template_kwargs",
            '{"enable_thinking":false}',
            "--n_ctx",
            "4096",
            "--n_threads",
            "-1",
            "--n_threads_batch",
            "-1",
            "--n_gpu_layers",
            "0",
            "--use_mlock",
            "False",
            "--verbose",
            "False",
        ],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    adapter: subprocess.Popen[bytes] | None = None
    adapter_port = _free_port()
    try:
        _wait_for_model(model_process, model_port, "/v1/models")
        adapter = subprocess.Popen(
            [
                str(python),
                "-m",
                "uvicorn",
                "qwen_tool_adapter:app",
                "--app-dir",
                str(QWEN_TOOL_ADAPTER.parent),
                "--host",
                "127.0.0.1",
                "--port",
                str(adapter_port),
                "--no-access-log",
                "--log-level",
                "error",
            ],
            cwd=ROOT,
            env={
                **_safe_environment(),
                "AGENTOPS_LOCAL_MODEL_UPSTREAM": f"http://127.0.0.1:{model_port}",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _wait_for_model(adapter, adapter_port, "/v1/models")
        completed = subprocess.run(
            [
                sys.executable,
                str(HARNESS),
                "--local-model-url",
                f"http://127.0.0.1:{adapter_port}/v1",
                "--local-model-id",
                args.model_id,
            ],
            cwd=ROOT,
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=1_800,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("AgentDojo dynamic Gateway evaluation failed")
        summary = json.loads(completed.stdout.decode("utf-8").splitlines()[-1])
        adapter_summary = _adapter_metrics(adapter_port)
    finally:
        if adapter is not None:
            _stop_process_group(adapter)
        _stop_process_group(model_process)

    if summary.get("attack", {}).get("samples") != 7:
        raise RuntimeError("dynamic attack sample count changed")
    if summary.get("benign", {}).get("samples") != 2:
        raise RuntimeError("dynamic benign sample count changed")
    generation_config = summary.pop("generation_config", None)
    if generation_config != {"temperature": 0, "max_tokens": 512, "seed": 0}:
        raise RuntimeError("dynamic generation configuration changed")
    report = {
        "metadata": {
            "created_at": datetime.now(UTC).isoformat(),
            "git_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "git_dirty": bool(
                subprocess.check_output(
                    ["git", "status", "--porcelain"], cwd=ROOT, text=True
                ).strip()
            ),
            "scope": (
                "Post-first-run real local-model regression through the real AgentOps Guard "
                "Gateway and a real MCP v2 controlled upstream. It reuses seven official "
                "AgentDojo-derived templates adapted to one controlled mutation goal plus two "
                "benign controls, so it is not a blind or full AgentDojo score."
            ),
            "evidence_kind": "post_first_run_gateway_regression",
            "historical_first_run": {
                "report": "artifacts/evals/agentdojo_template_dynamic_gateway_v1.json",
                "sha256": "7ad3bc0f32ca788be566075358761ca0718e9ac25fd03eec29f12549a67901d0",
            },
            "limits": {
                "full_agentdojo_benchmark": False,
                "official_agentdojo_task_environment": False,
                "statistically_sufficient_unknown_attack_benchmark": False,
                "production_integration_test": False,
            },
            "privacy": {
                "stores_raw_cases": False,
                "stores_per_case_results": False,
                "stores_model_responses": False,
                "stores_prompt_or_tool_content": False,
                "stores_credentials": False,
            },
            "implementation_sha256": {
                "launcher": _sha256(Path(__file__)),
                "shared_model_launcher": _sha256(ROOT / "scripts" / "run_llama_cpp_agent_eval.py"),
                "gateway_harness": _sha256(HARNESS),
                "case_exporter": _sha256(EXPORTER),
                "inspect_task": _sha256(TASK),
                "inspect_runner": _sha256(RUNNER),
                "qwen_tool_adapter": _sha256(QWEN_TOOL_ADAPTER),
                "inspect_lock": _sha256(ROOT / "evals" / "inspect" / "uv.lock"),
                "gateway": _sha256(ROOT / "src" / "agentops_guard" / "gateway" / "app.py"),
                "gateway_protocol": _sha256(
                    ROOT / "src" / "agentops_guard" / "gateway" / "protocol.py"
                ),
                "gateway_auth": _sha256(ROOT / "src" / "agentops_guard" / "gateway" / "auth.py"),
                "gateway_concurrency": _sha256(
                    ROOT / "src" / "agentops_guard" / "gateway" / "concurrency.py"
                ),
                "gateway_streamable_transport": _sha256(
                    ROOT
                    / "src"
                    / "agentops_guard"
                    / "gateway"
                    / "transports"
                    / "streamable_http.py"
                ),
                "content_provenance": _sha256(
                    ROOT
                    / "src"
                    / "agentops_guard"
                    / "backend"
                    / "services"
                    / "content_provenance.py"
                ),
                "execution_requests": _sha256(
                    ROOT
                    / "src"
                    / "agentops_guard"
                    / "backend"
                    / "services"
                    / "execution_requests.py"
                ),
                "mcp_tool_revisions": _sha256(
                    ROOT
                    / "src"
                    / "agentops_guard"
                    / "backend"
                    / "services"
                    / "mcp_tool_revisions.py"
                ),
                "policy": _sha256(
                    ROOT / "src" / "agentops_guard" / "backend" / "services" / "policy.py"
                ),
                "scanner": _sha256(
                    ROOT / "src" / "agentops_guard" / "backend" / "services" / "scanner.py"
                ),
                "scanner_rule_pack_installer": _sha256(
                    ROOT
                    / "src"
                    / "agentops_guard"
                    / "backend"
                    / "services"
                    / "scanner_rule_packs.py"
                ),
                "safe_regex": _sha256(
                    ROOT / "src" / "agentops_guard" / "backend" / "services" / "safe_regex.py"
                ),
                "scanner_rule_pack": _sha256(
                    ROOT / "policies" / "scanner" / "agentdojo-important-instructions-v1.json"
                ),
                "root_lock": _sha256(ROOT / "uv.lock"),
                "semantic_scanner": _sha256(
                    ROOT / "src" / "agentops_guard" / "backend" / "services" / "semantic_scanner.py"
                ),
            },
        },
        "model": {
            "id": args.model_id,
            "artifact_sha256": args.model_sha256,
            "artifact_size_bytes": model_size,
            "runtime": LLAMA_CPP_PYTHON_PACKAGE,
            "runtime_package_version": distribution["version"],
            "runtime_sha256": distribution["sha256"],
            "runtime_size_bytes": distribution["size_bytes"],
            "runtime_file_count": distribution["file_count"],
            "runtime_source_sha256": args.runtime_source_sha256,
            "runtime_lock_sha256": args.runtime_lock_sha256,
            "runtime_lock_size_bytes": lock_size,
            "runtime_lock_verified": lock == args.runtime_lock.resolve(),
            "tool_adapter_metrics": adapter_summary,
            "generation_config": generation_config,
        },
        **summary,
        "real_model_execution": True,
        "real_model_security_evaluation": True,
        "report_contains_prompt_or_tool_content": False,
        "report_contains_credentials": False,
    }
    _write_new_report(report, args.output)
    print("agentdojo_dynamic_gateway_evaluation=completed report_created=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
