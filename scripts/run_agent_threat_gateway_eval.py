#!/usr/bin/env python3
"""Run the pinned AgentThreatBench first-run comparison on a local Qwen model."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from agentops_guard.evals.holdouts import (
    first_run_holdout,
    load_holdout_manifest,
    register_holdout,
    system_snapshot_sha256,
)
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
from verify_agent_threat_gateway_eval import corpus_metadata, _safe_subprocess_failure


HARNESS = ROOT / "scripts" / "verify_agent_threat_gateway_eval.py"
EXPORTER = ROOT / "evals" / "inspect" / "export_agent_threat_bench_metadata.py"
TASK = ROOT / "evals" / "inspect" / "agent_threat_gateway_task.py"
RUNNER = ROOT / "evals" / "inspect" / "run_agent_threat_gateway.py"
MANIFEST = ROOT / "evals" / "holdouts" / "manifest.json"
DATASET_ID = "agent_threat_bench_dynamic_v1"
RUN_REF = "agent_threat_bench_dynamic_first_run_v1"
REGRESSION_RUN_REF = "agent_threat_bench_dynamic_regression_v6"
INSPECT_EVALS_WHEEL_SHA256 = "4976adca87e64b4becdfcd309bae19b7c01a2ee2e3c7a439724301f3d2a45eb7"
INSPECT_EVALS_TAG_COMMIT = "3367d26374083aa794600b9c06b0b4f76faad76d"
MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")


def _installed_distribution(python: Path, name: str, version: str) -> dict[str, Any]:
    script = f'''import hashlib
from importlib.metadata import distribution
import json
dist = distribution({name!r})
digest = hashlib.sha256()
size = 0
count = 0
for entry in sorted(dist.files or [], key=str):
    path = dist.locate_file(entry)
    if not path.is_file():
        continue
    digest.update(str(entry).encode("utf-8"))
    digest.update(b"\\0")
    data = path.read_bytes()
    digest.update(data)
    size += len(data)
    count += 1
print(json.dumps({{"version": dist.version, "sha256": digest.hexdigest(), "size_bytes": size, "file_count": count}}, separators=(",", ":")))
'''
    completed = subprocess.run(
        [str(python), "-c", script],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("evaluation package inspection failed")
    payload = json.loads(completed.stdout)
    if payload.get("version") != version:
        raise RuntimeError("evaluation package version changed")
    return payload


def _frozen_inputs(model: Path, runtime_lock: Path) -> dict[str, Path]:
    return {
        "model_artifact": model,
        "runtime_lock": runtime_lock,
        "inspect_lock": ROOT / "evals" / "inspect" / "uv.lock",
        "inspect_project": ROOT / "evals" / "inspect" / "pyproject.toml",
        "launcher": Path(__file__),
        "harness": HARNESS,
        "metadata_exporter": EXPORTER,
        "inspect_task": TASK,
        "inspect_runner": RUNNER,
        "model_adapter": QWEN_TOOL_ADAPTER,
        "gateway": ROOT / "src" / "agentops_guard" / "gateway" / "app.py",
        "gateway_protocol": ROOT / "src" / "agentops_guard" / "gateway" / "protocol.py",
        "gateway_auth": ROOT / "src" / "agentops_guard" / "gateway" / "auth.py",
        "content_provenance": ROOT
        / "src"
        / "agentops_guard"
        / "backend"
        / "services"
        / "content_provenance.py",
        "content_redaction": ROOT
        / "src"
        / "agentops_guard"
        / "backend"
        / "services"
        / "content.py",
        "tool_revisions": ROOT
        / "src"
        / "agentops_guard"
        / "backend"
        / "services"
        / "mcp_tool_revisions.py",
        "policy": ROOT / "src" / "agentops_guard" / "backend" / "services" / "policy.py",
        "scanner": ROOT / "src" / "agentops_guard" / "backend" / "services" / "scanner.py",
        "semantic_scanner": ROOT
        / "src"
        / "agentops_guard"
        / "backend"
        / "services"
        / "semantic_scanner.py",
        "holdout_registry": ROOT / "src" / "agentops_guard" / "evals" / "holdouts.py",
        "scanner_rule_pack": ROOT
        / "policies"
        / "scanner"
        / "agentdojo-important-instructions-v1.json",
        "root_lock": ROOT / "uv.lock",
    }


def _register_if_needed(
    *, corpus: dict[str, Any], frozen_system_sha256: str
) -> None:
    manifest = load_holdout_manifest(MANIFEST)
    if any(item["id"] == DATASET_ID for item in manifest["datasets"]):
        raise RuntimeError("AgentThreatBench first-run dataset is already registered")
    counts = {
        "attack": sum(group["attack"] for group in corpus["counts"].values()),
        "benign": sum(group["benign"] for group in corpus["counts"].values()),
    }
    register_holdout(
        MANIFEST,
        dataset_id=DATASET_ID,
        corpus_sha256=corpus["corpus_sha256"],
        counts=counts,
        source={
            "name": "UKGovernmentBEIS/inspect_evals",
            "revision": f"v0.16.0-{INSPECT_EVALS_TAG_COMMIT}-agent-threat-1-A",
            "license": "MIT",
        },
        custodian_ref="pypi_pinned_noninteractive_importer",
        frozen_system_sha256=frozen_system_sha256,
    )


def _regression_anchor(path: Path, corpus_sha256: str) -> dict[str, str]:
    anchor = path.absolute()
    if anchor.is_symlink() or not anchor.is_file():
        raise ValueError("regression anchor must be a regular report")
    payload = json.loads(anchor.read_text(encoding="utf-8"))
    holdout = payload.get("metadata", {}).get("holdout", {})
    evidence_kind = payload.get("metadata", {}).get("evidence_kind")
    if (
        evidence_kind
        not in {
            "local_first_run_public_holdout_paired_dynamic",
            "post_failure_public_corpus_regression_dynamic",
        }
        or holdout.get("dataset_id") != DATASET_ID
        or holdout.get("corpus_sha256") != corpus_sha256
    ):
        raise ValueError("regression anchor is not an AgentThreatBench report")
    report_sha256 = _sha256(anchor)
    manifest = load_holdout_manifest(MANIFEST)
    dataset = next((item for item in manifest["datasets"] if item["id"] == DATASET_ID), None)
    first_run_sha256 = dataset.get("firstRun", {}).get("reportSha256") if dataset else None
    anchored_first_run_sha256 = (
        report_sha256
        if evidence_kind == "local_first_run_public_holdout_paired_dynamic"
        else holdout.get("regression_of_report_sha256")
    )
    if (
        dataset is None
        or dataset.get("state") != "consumed"
        or first_run_sha256 != anchored_first_run_sha256
    ):
        raise ValueError("regression anchor does not match the consumed holdout record")
    return {
        "report_sha256": report_sha256,
        "failure": "guarded_tool_adapter_executed_zero_tool_calls",
    }


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
    parser.add_argument("--regression-of", type=Path)
    args = parser.parse_args()
    if not MODEL_ID_PATTERN.fullmatch(args.model_id):
        raise ValueError("model id has an unsupported format")
    output = args.output.absolute()
    if output.exists():
        raise FileExistsError("AgentThreatBench first-run report already exists")
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
    runtime = _python_distribution_metadata(python, args.runtime_package_version)
    if LLAMA_CPP_PYTHON_PACKAGE != "llama-cpp-python":
        raise RuntimeError("unexpected local model runtime package")
    inspect_evals = _installed_distribution(
        ROOT / "evals" / "inspect" / ".venv" / "bin" / "python",
        "inspect-evals",
        "0.16.0",
    )
    corpus = corpus_metadata()
    frozen_system_sha256 = system_snapshot_sha256(_frozen_inputs(model, lock))
    regression = (
        _regression_anchor(args.regression_of, corpus["corpus_sha256"])
        if args.regression_of is not None
        else None
    )
    if regression is None:
        _register_if_needed(corpus=corpus, frozen_system_sha256=frozen_system_sha256)
        evaluation_context = first_run_holdout(
            MANIFEST,
            dataset_id=DATASET_ID,
            run_ref=RUN_REF,
            frozen_system_sha256=frozen_system_sha256,
        )
    else:
        evaluation_context = nullcontext(None)

    with evaluation_context as ticket:
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
                "8192",
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
                stderr=subprocess.PIPE,
                timeout=14_400,
                check=False,
            )
            if completed.returncode != 0:
                failure = _safe_subprocess_failure(completed.stderr)
                raise RuntimeError(f"AgentThreatBench first-run harness failed [{failure}]")
            summary = json.loads(completed.stdout.decode("utf-8").splitlines()[-1])
            adapter_summary = _adapter_metrics(adapter_port)
        finally:
            if adapter is not None:
                _stop_process_group(adapter)
            _stop_process_group(model_process)

        summary["real_model_execution"] = True
        evidence_kind = (
            "local_first_run_public_holdout_paired_dynamic"
            if regression is None
            else "post_failure_public_corpus_regression_dynamic"
        )
        scope = (
            "First local use of the pinned public AgentThreatBench corpus, comparing the "
            "official unguarded Inspect task with the same task behind a real AgentOps "
            "Guard policy adapter and standard MCP client. This is not an independently "
            "custodied blind benchmark or a production deployment test."
            if regression is None
            else "Post-failure regression on the already consumed public AgentThreatBench "
            "corpus after a targeted gateway or scanner correction. It compares the official "
            "unguarded Inspect task with the same task behind a real AgentOps Guard policy "
            "adapter and standard MCP client. It is not a blind benchmark or production test."
        )
        holdout_metadata = {
            "dataset_id": DATASET_ID,
            "run_ref": RUN_REF if regression is None else REGRESSION_RUN_REF,
            "corpus_sha256": corpus["corpus_sha256"],
            "frozen_system_sha256": frozen_system_sha256,
            "independent_custodian": False,
            "first_run": regression is None,
        }
        if regression is not None:
            holdout_metadata["regression_of_report_sha256"] = regression["report_sha256"]
            holdout_metadata["first_run_failure"] = regression["failure"]
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
                "evidence_kind": evidence_kind,
                "scope": scope,
                "holdout": holdout_metadata,
                "source": {
                    "repository": "https://github.com/UKGovernmentBEIS/inspect_evals",
                    "tag": "v0.16.0",
                    "tag_commit": INSPECT_EVALS_TAG_COMMIT,
                    "task_version": "1-A",
                    "wheel_sha256": INSPECT_EVALS_WHEEL_SHA256,
                    "installed_distribution": inspect_evals,
                    "license": "MIT",
                },
                "implementation_sha256": {
                    label: _sha256(path) for label, path in _frozen_inputs(model, lock).items()
                },
                "limits": {
                    "independent_holdout_custody": False,
                    "official_agentdojo_score": False,
                    "production_integration_test": False,
                    "gateway_transparently_hosts_official_tools": False,
                    "semantic_model_enforcement": False,
                },
                "privacy": {
                    "stores_raw_cases": False,
                    "stores_per_case_results": False,
                    "stores_model_responses": False,
                    "stores_prompt_or_tool_content_in_report": False,
                    "stores_credentials": False,
                },
            },
            "model": {
                "id": args.model_id,
                "artifact_sha256": args.model_sha256,
                "artifact_size_bytes": model_size,
                "runtime": LLAMA_CPP_PYTHON_PACKAGE,
                "runtime_package_version": runtime["version"],
                "runtime_sha256": runtime["sha256"],
                "runtime_size_bytes": runtime["size_bytes"],
                "runtime_file_count": runtime["file_count"],
                "runtime_source_sha256": args.runtime_source_sha256,
                "runtime_lock_sha256": args.runtime_lock_sha256,
                "runtime_lock_size_bytes": lock_size,
                "runtime_lock_verified": lock == args.runtime_lock.resolve(),
                "tool_adapter_metrics": adapter_summary,
            },
            **summary,
            "real_model_security_evaluation": True,
            "report_contains_prompt_or_tool_content": False,
            "report_contains_credentials": False,
        }
        _write_new_report(report, output)
        if ticket is not None:
            ticket.record_report(output)
    print("agent_threat_bench_gateway_evaluation=completed report_created=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
