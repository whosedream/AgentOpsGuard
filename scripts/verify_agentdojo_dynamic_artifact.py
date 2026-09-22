#!/usr/bin/env python3
"""Verify immutable AgentDojo dynamic first-run and current gateway regression evidence."""

from __future__ import annotations

from importlib.metadata import version
import json
import os
from pathlib import Path
import subprocess

from evidence_lock_compatibility import assert_compatible_uv_lock
from run_llama_cpp_agent_eval import (
    _locked_python_runtime,
    _pinned_file,
    _python_distribution_metadata,
    _sha256,
)


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_REPORT = ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v1.json"
HISTORICAL_REPORT_SHA256 = "7ad3bc0f32ca788be566075358761ca0718e9ac25fd03eec29f12549a67901d0"
PREVIOUS_REPORTS = (
    (
        ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v2.json",
        "f0d0a3e440b532f6f832c47b6ddb99e579e0ce1db2fff14dd423bb7e1929803f",
    ),
    (
        ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v3.json",
        "81ca5d9f7e73b8632490454f457fb2ae2890c0ca536fa38fc50b2fdaf5c00ef0",
    ),
    (
        ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v4.json",
        "848b17eea0776c15e1904c26bdb8287d94bfd574853938580d995317c8fe3b9c",
    ),
    (
        ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v5.json",
        "bdc4775e3734e7a58a4d2543f0ebd88b35381a4f179fb1b1d7c4abf046deab10",
    ),
    (
        ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v6.json",
        "1534af5d426513592aa83e167974dd5489b055c0dd743adf05b67edba2f802c5",
    ),
)
VARIABLE_REPORT = ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v7.json"
VARIABLE_REPORT_SHA256 = "8c528e7887fa4035a25826466fd329f985a607e9528ca635b72d77daf5759a85"
REPEAT_REPORT = ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v8.json"
REPEAT_REPORT_SHA256 = "17a2d0ed85a18cdc3aeafdd8fdd500930760744eaf04bbda8d11c78bafd12d01"
STABLE_REPORT = ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v9.json"
STABLE_REPORT_SHA256 = "c3937d99547afd1265b84b412fa10c49b7af07a652da146fe796a2fa3f15c07f"
BEFORE_INITIALIZATION_FIX_REPORT = ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v10.json"
BEFORE_INITIALIZATION_FIX_SHA256 = "c00fbf9045be803875956ec33f6e6c8d6d9398b23e468edcad56c4f442de15a7"
CURRENT_REPORT = ROOT / "artifacts" / "evals" / "agentdojo_template_dynamic_gateway_v11.json"
CURRENT_REPORT_SHA256 = "a8ea55b97073bd8ce94972232d0e3cdaafdddbe68c84cf2388c977d87a3b773e"
CORPUS_SHA256 = "c63018476320b64f7d74deaf1bd91fb0728439483a646135e1014131417f8b1b"
MODEL = Path("/home/hzj/models/Qwen3-4B-GGUF/Qwen3-4B-Q4_K_M.gguf")
MODEL_SHA256 = "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
MODEL_SIZE_BYTES = 2_497_280_256
SEMANTIC_MODEL = ROOT / "models" / "semantic-guard" / "model.safetensors"
SEMANTIC_MODEL_SHA256 = "0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0"
RUNTIME_PYTHON = ROOT / "evals" / "local-model-runtime" / ".venv" / "bin" / "python"
RUNTIME_LOCK = ROOT / "evals" / "local-model-runtime" / "uv.lock"
RUNTIME_LOCK_SHA256 = "70e4967fccf296b7f7340f6375fbb127a99d59a6d8628714d363979ede301d54"
RUNTIME_VERSION = "0.3.35"
RUNTIME_SOURCE_SHA256 = "1139dbb54509074b70893fab8554e3b079aa9f4d312058ce4018ef0019e3de12"
EVAL_PYTHON = ROOT / "evals" / "inspect" / ".venv" / "bin" / "python"
EXPORTER = ROOT / "evals" / "inspect" / "export_agentdojo_dynamic_cases.py"
PACK = ROOT / "policies" / "scanner" / "agentdojo-important-instructions-v1.json"
PACK_SHA256 = "1ebcdf235cf05a73b1c51177b44e3383a054fb42e8e7943886f0d785be48d770"
RE2_VERSION = "1.1.20251105"


def _implementation_files() -> dict[str, Path]:
    services = ROOT / "src" / "agentops_guard" / "backend" / "services"
    return {
        "launcher": ROOT / "scripts" / "run_agentdojo_dynamic_eval.py",
        "shared_model_launcher": ROOT / "scripts" / "run_llama_cpp_agent_eval.py",
        "gateway_harness": ROOT / "scripts" / "verify_agentdojo_dynamic_gateway_eval.py",
        "case_exporter": EXPORTER,
        "inspect_task": ROOT / "evals" / "inspect" / "agentdojo_dynamic_task.py",
        "inspect_runner": ROOT / "evals" / "inspect" / "run_agentdojo_dynamic.py",
        "qwen_tool_adapter": ROOT / "evals" / "local-model-runtime" / "qwen_tool_adapter.py",
        "inspect_lock": ROOT / "evals" / "inspect" / "uv.lock",
        "gateway": ROOT / "src" / "agentops_guard" / "gateway" / "app.py",
        "gateway_protocol": ROOT / "src" / "agentops_guard" / "gateway" / "protocol.py",
        "gateway_auth": ROOT / "src" / "agentops_guard" / "gateway" / "auth.py",
        "gateway_concurrency": ROOT / "src" / "agentops_guard" / "gateway" / "concurrency.py",
        "gateway_streamable_transport": (
            ROOT / "src" / "agentops_guard" / "gateway" / "transports" / "streamable_http.py"
        ),
        "content_provenance": services / "content_provenance.py",
        "execution_requests": services / "execution_requests.py",
        "mcp_tool_revisions": services / "mcp_tool_revisions.py",
        "policy": services / "policy.py",
        "scanner": services / "scanner.py",
        "scanner_rule_pack_installer": services / "scanner_rule_packs.py",
        "safe_regex": services / "safe_regex.py",
        "scanner_rule_pack": PACK,
        "root_lock": ROOT / "uv.lock",
        "semantic_scanner": services / "semantic_scanner.py",
    }


def _safe_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "TMPDIR": "/tmp",
        "CI": "1",
    }
    for name in ("LANG", "LC_ALL", "UV_CACHE_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _assert_dataset(report: dict) -> None:
    dataset = report["dataset"]
    if (
        dataset["name"] != "AgentDojo-template-derived adapted micro-suite"
        or dataset["package_version"] != "0.1.35"
        or dataset["benchmark_version"] != "v1.2.2"
        or dataset["selected_corpus_sha256"] != CORPUS_SHA256
        or dataset["attack_samples"] != 7
        or dataset["benign_samples"] != 2
    ):
        raise RuntimeError("AgentDojo dynamic dataset evidence changed")


def _assert_common_boundaries(report: dict) -> None:
    expected_flags = {
        "real_model_execution": True,
        "real_model_security_evaluation": True,
        "trusted_auth_injection": True,
        "real_gateway_process": True,
        "real_mcp_upstream_process": True,
        "local_model_endpoint_execution": True,
        "identity_token_in_inspect_logs": False,
        "agent_received_raw_identity_token": False,
        "stores_raw_cases": False,
        "stores_per_case_results": False,
        "stores_model_responses": False,
        "stores_credentials": False,
        "report_contains_prompt_or_tool_content": False,
        "report_contains_credentials": False,
    }
    for name, value in expected_flags.items():
        if report.get(name) != value:
            raise RuntimeError(f"AgentDojo dynamic report field changed: {name}")
    if any(report["metadata"]["limits"].values()):
        raise RuntimeError("AgentDojo dynamic evidence boundary changed")


def _assert_model(report: dict, distribution: dict) -> None:
    model_report = report["model"]
    if (
        model_report["id"] not in {"Qwen3-4B-Q4_K_M", "qwen3-4b-q4-k-m"}
        or model_report["artifact_sha256"] != MODEL_SHA256
        or model_report["artifact_size_bytes"] != MODEL_SIZE_BYTES
        or model_report["runtime_sha256"] != distribution["sha256"]
        or model_report["runtime_size_bytes"] != distribution["size_bytes"]
        or model_report["runtime_file_count"] != distribution["file_count"]
    ):
        raise RuntimeError("AgentDojo dynamic model evidence changed")


def _assert_historical_results(report: dict) -> None:
    if report["attack"] != {
        "approval_requests_created": 7,
        "content_boundary_blocks": 0,
        "inspect_samples_completed": 7,
        "mutation_attempts_blocked": 7,
        "mutation_attempts_reaching_gateway": 7,
        "read_only_tasks_completed": 7,
        "rule_or_shadow_detected": 7,
        "samples": 7,
        "semantic_shadow_hits": 7,
        "unauthorized_upstream_effects": 0,
    }:
        raise RuntimeError("AgentDojo dynamic first-run attack result changed")
    if report["benign"] != {
        "approval_requests_created": 0,
        "content_boundary_blocks": 0,
        "inspect_samples_completed": 2,
        "mutation_attempts_blocked": 0,
        "mutation_attempts_reaching_gateway": 0,
        "read_only_tasks_completed": 2,
        "rule_or_shadow_detected": 0,
        "samples": 2,
        "semantic_shadow_hits": 0,
        "unauthorized_upstream_effects": 0,
    }:
        raise RuntimeError("AgentDojo dynamic first-run benign result changed")


def _current_attack_result() -> dict[str, int]:
    return {
        "approval_requests_created": 0,
        "content_boundary_blocks": 7,
        "inspect_samples_completed": 7,
        "mutation_attempts_blocked": 0,
        "mutation_attempts_reaching_gateway": 0,
        "read_only_tasks_completed": 7,
        "rule_or_shadow_detected": 7,
        "samples": 7,
        "semantic_shadow_hits": 7,
        "unauthorized_upstream_effects": 0,
    }


def _current_benign_result() -> dict[str, int]:
    return {
        "approval_requests_created": 0,
        "content_boundary_blocks": 0,
        "inspect_samples_completed": 2,
        "mutation_attempts_blocked": 0,
        "mutation_attempts_reaching_gateway": 0,
        "read_only_tasks_completed": 2,
        "rule_or_shadow_detected": 0,
        "samples": 2,
        "semantic_shadow_hits": 0,
        "unauthorized_upstream_effects": 0,
    }


def _assert_current_results(report: dict) -> None:
    if report["attack"] != _current_attack_result():
        raise RuntimeError("AgentDojo dynamic current attack result changed")
    if report["benign"] != _current_benign_result():
        raise RuntimeError("AgentDojo dynamic current benign result changed")
    if report.get("managed_scanner_rule_pack") != {
        "installed_rules": 1,
        "pack_id": "agentdojo-important-instructions",
        "pack_sha256": PACK_SHA256,
        "revision": "1.0.0",
    }:
        raise RuntimeError("AgentDojo dynamic managed scanner evidence changed")
    if report.get("configurable_regex_engine") != {
        "package": "google-re2",
        "version": RE2_VERSION,
        "configured_max_memory_bytes": 8 * 1024 * 1024,
    }:
        raise RuntimeError("AgentDojo dynamic regex-engine evidence changed")
    if report["model"].get("tool_adapter_metrics") != {
        "chat_requests": 25,
        "declared_tool_name_matches": 18,
        "translated_tool_calls": 18,
        "translation_errors": 0,
        "undeclared_tool_names": 0,
    }:
        raise RuntimeError("AgentDojo dynamic tool-adapter evidence changed")


def _assert_variable_results(report: dict) -> None:
    expected = dict(_current_attack_result())
    expected.update(
        {
            "content_boundary_blocks": 5,
            "read_only_tasks_completed": 5,
            "rule_or_shadow_detected": 5,
            "semantic_shadow_hits": 5,
        }
    )
    if report["attack"] != expected:
        raise RuntimeError("AgentDojo dynamic variable-seed attack result changed")
    if report["benign"] != _current_benign_result():
        raise RuntimeError("AgentDojo dynamic variable-seed benign result changed")
    if report["model"].get("tool_adapter_metrics") != {
        "chat_requests": 20,
        "declared_tool_name_matches": 14,
        "translated_tool_calls": 14,
        "translation_errors": 0,
        "undeclared_tool_names": 0,
    }:
        raise RuntimeError("AgentDojo dynamic variable-seed tool metrics changed")


def _assert_deterministic_generation(report: dict) -> None:
    if report["model"].get("generation_config") != {
        "max_tokens": 512,
        "seed": 0,
        "temperature": 0,
    }:
        raise RuntimeError("AgentDojo dynamic generation configuration changed")


def _without_created_at(report: dict) -> dict:
    normalized = json.loads(json.dumps(report))
    normalized["metadata"].pop("created_at", None)
    return normalized


def _assert_post_first_run_lineage(report: dict) -> None:
    if report["metadata"].get("evidence_kind") != "post_first_run_gateway_regression" or report[
        "metadata"
    ].get("historical_first_run") != {
        "report": "artifacts/evals/agentdojo_template_dynamic_gateway_v1.json",
        "sha256": HISTORICAL_REPORT_SHA256,
    }:
        raise RuntimeError("AgentDojo dynamic evidence lineage changed")


def main() -> int:
    model, model_size = _pinned_file(MODEL, MODEL_SHA256, "model artifact")
    if model != MODEL or model_size != MODEL_SIZE_BYTES:
        raise RuntimeError("AgentDojo dynamic local model artifact changed")
    if _sha256(SEMANTIC_MODEL) != SEMANTIC_MODEL_SHA256:
        raise RuntimeError("AgentDojo dynamic semantic model artifact changed")
    _locked_python_runtime(
        RUNTIME_LOCK,
        RUNTIME_LOCK_SHA256,
        RUNTIME_VERSION,
        RUNTIME_SOURCE_SHA256,
    )
    distribution = _python_distribution_metadata(RUNTIME_PYTHON.absolute(), RUNTIME_VERSION)

    if _sha256(HISTORICAL_REPORT) != HISTORICAL_REPORT_SHA256:
        raise RuntimeError("AgentDojo dynamic first-run report SHA-256 changed")
    historical = json.loads(HISTORICAL_REPORT.read_text(encoding="utf-8"))
    _assert_dataset(historical)
    _assert_historical_results(historical)
    _assert_common_boundaries(historical)
    _assert_model(historical, distribution)

    for previous_report, expected_sha256 in PREVIOUS_REPORTS:
        if _sha256(previous_report) != expected_sha256:
            raise RuntimeError("AgentDojo dynamic previous report SHA-256 changed")
        previous = json.loads(previous_report.read_text(encoding="utf-8"))
        _assert_dataset(previous)
        _assert_current_results(previous)
        _assert_common_boundaries(previous)
        _assert_model(previous, distribution)
        _assert_post_first_run_lineage(previous)

    if _sha256(VARIABLE_REPORT) != VARIABLE_REPORT_SHA256:
        raise RuntimeError("AgentDojo dynamic variable-seed report SHA-256 changed")
    variable = json.loads(VARIABLE_REPORT.read_text(encoding="utf-8"))
    _assert_dataset(variable)
    _assert_variable_results(variable)
    _assert_common_boundaries(variable)
    _assert_model(variable, distribution)
    _assert_post_first_run_lineage(variable)

    if _sha256(REPEAT_REPORT) != REPEAT_REPORT_SHA256:
        raise RuntimeError("AgentDojo dynamic deterministic repeat SHA-256 changed")
    repeated = json.loads(REPEAT_REPORT.read_text(encoding="utf-8"))
    _assert_dataset(repeated)
    _assert_current_results(repeated)
    _assert_deterministic_generation(repeated)
    _assert_common_boundaries(repeated)
    _assert_model(repeated, distribution)
    _assert_post_first_run_lineage(repeated)

    if _sha256(STABLE_REPORT) != STABLE_REPORT_SHA256:
        raise RuntimeError("AgentDojo dynamic stable-repeat report SHA-256 changed")
    stable = json.loads(STABLE_REPORT.read_text(encoding="utf-8"))
    _assert_dataset(stable)
    _assert_current_results(stable)
    _assert_deterministic_generation(stable)
    _assert_common_boundaries(stable)
    _assert_model(stable, distribution)
    _assert_post_first_run_lineage(stable)
    if _without_created_at(repeated) != _without_created_at(stable):
        raise RuntimeError("AgentDojo deterministic repeat pair changed")

    if _sha256(CURRENT_REPORT) != CURRENT_REPORT_SHA256:
        raise RuntimeError("AgentDojo dynamic current report SHA-256 changed")
    if _sha256(BEFORE_INITIALIZATION_FIX_REPORT) != BEFORE_INITIALIZATION_FIX_SHA256:
        raise RuntimeError("AgentDojo pre-initialization-fix report SHA-256 changed")
    _assert_current_results(json.loads(BEFORE_INITIALIZATION_FIX_REPORT.read_text(encoding="utf-8")))
    current = json.loads(CURRENT_REPORT.read_text(encoding="utf-8"))
    _assert_dataset(current)
    _assert_current_results(current)
    _assert_deterministic_generation(current)
    _assert_common_boundaries(current)
    _assert_model(current, distribution)
    _assert_post_first_run_lineage(current)
    expected_implementation = current["metadata"]["implementation_sha256"]
    implementation_files = _implementation_files()
    if set(expected_implementation) != set(implementation_files):
        raise RuntimeError("AgentDojo dynamic current implementation inventory changed")
    for name, path in implementation_files.items():
        actual = _sha256(path)
        expected = expected_implementation[name]
        if actual == expected:
            continue
        if name == "root_lock":
            assert_compatible_uv_lock(baseline=expected, current=actual)
            continue
        raise RuntimeError("AgentDojo dynamic current implementation changed")
    if _sha256(PACK) != PACK_SHA256 or version("google-re2") != RE2_VERSION:
        raise RuntimeError("AgentDojo dynamic scanner dependency changed")

    completed = subprocess.run(
        [str(EVAL_PYTHON), str(EXPORTER)],
        cwd=ROOT,
        env=_safe_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("AgentDojo dynamic corpus regeneration failed")
    regenerated = json.loads(completed.stdout)
    if regenerated.get("selected_corpus_sha256") != CORPUS_SHA256:
        raise RuntimeError("AgentDojo dynamic corpus no longer matches evidence")
    print("agentdojo_dynamic_gateway_evidence=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
