#!/usr/bin/env python3
"""Verify the immutable, aggregate-only real local-model Agent smoke evidence."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "artifacts" / "evals" / "qwen3_4b_q4_k_m_agent_smoke_v2.json"
REPORT_SHA256 = "00160953613214898268dc793acc361539282030e248878b90a94a0957e263dc"
MODEL = Path("/home/hzj/models/Qwen3-4B-GGUF/Qwen3-4B-Q4_K_M.gguf")
MODEL_SHA256 = "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
MODEL_SIZE_BYTES = 2_497_280_256
RUNTIME_PYTHON = ROOT / "evals" / "local-model-runtime" / ".venv" / "bin" / "python"
RUNTIME_LOCK = ROOT / "evals" / "local-model-runtime" / "uv.lock"
RUNTIME_LOCK_SHA256 = "70e4967fccf296b7f7340f6375fbb127a99d59a6d8628714d363979ede301d54"
RUNTIME_VERSION = "0.3.35"
RUNTIME_SOURCE_SHA256 = "1139dbb54509074b70893fab8554e3b079aa9f4d312058ce4018ef0019e3de12"
IMPLEMENTATION_FILES = {
    "launcher": ROOT / "scripts" / "run_llama_cpp_agent_eval.py",
    "gateway_harness": ROOT / "scripts" / "verify_inspect_agent_eval.py",
    "inspect_task": ROOT / "evals" / "inspect" / "agentops_guard_task.py",
    "inspect_runner": ROOT / "evals" / "inspect" / "run_local_model_smoke.py",
    "qwen_tool_adapter": ROOT / "evals" / "local-model-runtime" / "qwen_tool_adapter.py",
}


def _load_launcher():
    path = IMPLEMENTATION_FILES["launcher"]
    spec = importlib.util.spec_from_file_location("local_model_agent_launcher", path)
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise RuntimeError("local model launcher cannot be loaded")
    spec.loader.exec_module(module)
    return module


def main() -> int:
    launcher = _load_launcher()
    if launcher._sha256(REPORT) != REPORT_SHA256:
        raise RuntimeError("real local-model report SHA-256 does not match")
    report = json.loads(REPORT.read_text(encoding="utf-8"))

    expected = {
        "framework": "inspect-ai",
        "framework_version": "0.3.262",
        "driver": "real_local_model",
        "samples": 2,
        "read_only_tasks_completed": 2,
        "unauthorized_upstream_effects": 0,
        "identity_token_in_inspect_logs": False,
        "agent_received_raw_identity_token": False,
        "trusted_auth_injection": True,
        "real_gateway_process": True,
        "real_mcp_upstream_process": True,
        "local_model_endpoint_execution": True,
        "real_model_execution": True,
        "real_model_quality_result": False,
        "model_id": "qwen3-4b-q4-k-m",
        "model_artifact_sha256": MODEL_SHA256,
        "model_artifact_size_bytes": MODEL_SIZE_BYTES,
        "runtime": "llama-cpp-python",
        "runtime_package_version": RUNTIME_VERSION,
        "runtime_source_sha256": RUNTIME_SOURCE_SHA256,
        "runtime_lock_sha256": RUNTIME_LOCK_SHA256,
        "runtime_lock_verified": True,
        "report_contains_prompt_or_tool_content": False,
        "report_contains_credentials": False,
    }
    for name, value in expected.items():
        if report.get(name) != value:
            raise RuntimeError(f"real local-model report field does not match: {name}")

    model, model_size = launcher._pinned_file(MODEL, MODEL_SHA256, "model artifact")
    if model_size != MODEL_SIZE_BYTES or model != MODEL:
        raise RuntimeError("real local-model artifact does not match")
    launcher._locked_python_runtime(
        RUNTIME_LOCK,
        RUNTIME_LOCK_SHA256,
        RUNTIME_VERSION,
        RUNTIME_SOURCE_SHA256,
    )
    distribution = launcher._python_distribution_metadata(
        RUNTIME_PYTHON.absolute(), RUNTIME_VERSION
    )
    if report.get("runtime_sha256") != distribution["sha256"]:
        raise RuntimeError("installed local-model runtime SHA-256 does not match")
    if report.get("runtime_size_bytes") != distribution["size_bytes"]:
        raise RuntimeError("installed local-model runtime size does not match")
    if report.get("runtime_file_count") != distribution["file_count"]:
        raise RuntimeError("installed local-model runtime file count does not match")

    current_implementation = {
        name: launcher._sha256(path) for name, path in IMPLEMENTATION_FILES.items()
    }
    if report.get("implementation_sha256") != current_implementation:
        raise RuntimeError("real local-model evaluation implementation changed")
    if report.get("tool_call_adapter_sha256") != current_implementation["qwen_tool_adapter"]:
        raise RuntimeError("real local-model tool adapter SHA-256 does not match")

    print("real_local_model_agent_evidence=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
