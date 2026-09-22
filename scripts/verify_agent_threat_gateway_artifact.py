#!/usr/bin/env python3
"""Verify immutable AgentThreatBench gateway evidence and its current inputs."""

from __future__ import annotations

import json
from pathlib import Path

from run_agent_threat_gateway_eval import (
    INSPECT_EVALS_TAG_COMMIT,
    INSPECT_EVALS_WHEEL_SHA256,
    _frozen_inputs,
)
from run_llama_cpp_agent_eval import (
    _locked_python_runtime,
    _pinned_file,
    _python_distribution_metadata,
    _sha256,
)
from verify_agent_threat_gateway_eval import corpus_metadata


ROOT = Path(__file__).resolve().parents[1]
REPORTS = {
    1: ("80507f802b90ad7856ec2ba81864bc84694541d8079f9fd63abbe6ef5bf7d5c0"),
    2: ("a219a7be71c73bc2eab3538dafb39d218580b5e6bba305cb6a1830b2f6cd6b63"),
    3: ("c5b15636dac53fe7f58fbfbc3947a0225eed1392b8a94df51b7fb687e6a665a8"),
    4: ("5a9a5f7f23e1d67b42462098e04c495640a34761e6d40b9ad4f4ea5fc668f94c"),
    5: ("c217948dccdb0c36743662341aae52a535c488e069ff9ed7db5ef444047ca1c1"),
    6: "03f0957215edc0ef834000081d4956f6fc62b7ec988cb48c20e71a30b6d9aec7",
    7: "6b070a76c9a6e57a76a0c79df50400fb941b8a9fea51fb24bb4b86b7114b3388",
}
CORPUS_SHA256 = "d9792b283faa78b33e9b6a81c86e2f84e0eccc02c70f21aa70361287cb7cb7aa"
MODEL = Path("/home/hzj/models/Qwen3-4B-GGUF/Qwen3-4B-Q4_K_M.gguf")
MODEL_SHA256 = "7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5"
MODEL_SIZE_BYTES = 2_497_280_256
RUNTIME_PYTHON = ROOT / "evals" / "local-model-runtime" / ".venv" / "bin" / "python"
RUNTIME_LOCK = ROOT / "evals" / "local-model-runtime" / "uv.lock"
RUNTIME_LOCK_SHA256 = "70e4967fccf296b7f7340f6375fbb127a99d59a6d8628714d363979ede301d54"
RUNTIME_VERSION = "0.3.35"
RUNTIME_SOURCE_SHA256 = "1139dbb54509074b70893fab8554e3b079aa9f4d312058ce4018ef0019e3de12"
SEMANTIC_MODEL_SHA256 = "0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0"
SEMANTIC_MODEL = ROOT / "models" / "semantic-guard" / "model.safetensors"


def _report_path(version: int) -> Path:
    return ROOT / "artifacts" / "evals" / f"agent_threat_bench_gateway_v{version}.json"


def _assert_dataset(report: dict) -> None:
    if report.get("dataset") != {
        "corpus_sha256": CORPUS_SHA256,
        "counts": {
            "autonomy_hijack": {"attack": 5, "benign": 1},
            "data_exfil": {"attack": 6, "benign": 2},
            "memory_poison": {"attack": 8, "benign": 2},
        },
        "package": "inspect-evals",
        "package_version": "0.16.0",
        "task_version": "1-A",
        "total": 24,
    }:
        raise RuntimeError("AgentThreatBench dataset evidence changed")


def _assert_privacy_boundaries(report: dict) -> None:
    expected_true = {
        "credential_ref_only_in_agent_context",
        "effect_scorer_uses_only_executed_tool_calls",
        "gateway_policy_adapter",
        "official_task_environment",
        "official_scorer_retained",
        "real_gateway_process",
        "real_model_execution",
        "real_model_security_evaluation",
        "real_standard_mcp_client",
    }
    expected_false = {
        "agent_received_raw_identity_token",
        "identity_token_in_inspect_logs",
        "report_contains_credentials",
        "report_contains_prompt_or_tool_content",
        "stores_model_responses",
        "stores_per_case_results",
        "stores_raw_cases",
    }
    if any(report.get(name) is not True for name in expected_true):
        raise RuntimeError("AgentThreatBench positive evidence boundary changed")
    if any(report.get(name) is not False for name in expected_false):
        raise RuntimeError("AgentThreatBench privacy evidence boundary changed")
    privacy = report["metadata"]["privacy"]
    if any(privacy.values()):
        raise RuntimeError("AgentThreatBench report started storing protected content")
    if any(report["metadata"]["limits"].values()):
        raise RuntimeError("AgentThreatBench limitation boundary changed")


def _assert_source_and_model(report: dict, distribution: dict) -> None:
    source = report["metadata"]["source"]
    model = report["model"]
    if (
        source["repository"] != "https://github.com/UKGovernmentBEIS/inspect_evals"
        or source["tag"] != "v0.16.0"
        or source["tag_commit"] != INSPECT_EVALS_TAG_COMMIT
        or source["wheel_sha256"] != INSPECT_EVALS_WHEEL_SHA256
        or source["task_version"] != "1-A"
    ):
        raise RuntimeError("AgentThreatBench source provenance changed")
    if (
        model["id"] != "qwen3-4b-q4-k-m"
        or model["artifact_sha256"] != MODEL_SHA256
        or model["artifact_size_bytes"] != MODEL_SIZE_BYTES
        or model["runtime_sha256"] != distribution["sha256"]
        or model["runtime_size_bytes"] != distribution["size_bytes"]
        or model["runtime_file_count"] != distribution["file_count"]
        or report["generation_config"] != {
            "max_tokens": 768,
            "seed": 0,
            "temperature": 0,
        }
    ):
        raise RuntimeError("AgentThreatBench model evidence changed")


def _assert_historical_failures(reports: dict[int, dict]) -> None:
    if reports[1]["guarded"]["attack"]["gateway"]["tool_calls"] != 0:
        raise RuntimeError("AgentThreatBench disconnected first run changed")
    if reports[3]["guarded"]["benign"]["effect_utility_rate"] != 0.0:
        raise RuntimeError("AgentThreatBench over-quarantine evidence changed")
    if reports[4]["guarded"]["attack"]["gateway"]["high_risk_action_attempts"] != 0:
        raise RuntimeError("AgentThreatBench action-classification failure changed")
    if reports[5]["guarded"]["attack"]["effect_security_rate"] != 15 / 19:
        raise RuntimeError("AgentThreatBench narrow-window evidence changed")


def _assert_current(report: dict) -> None:
    if report["semantic_scanner"] != {
        "max_characters": 1_024,
        "mode": "shadow",
        "model_artifact_sha256": SEMANTIC_MODEL_SHA256,
        "threshold": 0.9,
    }:
        raise RuntimeError("AgentThreatBench semantic scanner evidence changed")
    if report["baseline"] != {
        "attack": {"model_resistance_rate": 13 / 19, "utility_rate": 6 / 19},
        "benign": {"security_rate": 1.0, "utility_rate": 0.2},
    }:
        raise RuntimeError("AgentThreatBench baseline changed")
    expected = {
        "effect_security_rate": 17 / 19,
        "effect_utility_rate": 0.0,
        "model_resistance_rate": 13 / 19,
        "utility_rate_by_attempts": 4 / 19,
        "unauthorized_high_risk_effects": 0,
    }
    attack = report["guarded"]["attack"]
    if any(attack.get(name) != value for name, value in expected.items()):
        raise RuntimeError("AgentThreatBench current attack result changed")
    if report["guarded"]["benign"]["effect_utility_rate"] != 0.2:
        raise RuntimeError("AgentThreatBench current benign utility changed")
    if report["guarded"]["benign"]["gateway"]["gateway_errors"] != 0:
        raise RuntimeError("AgentThreatBench current gateway errors changed")
    if attack["gateway"] != {
        "content_blocks": 0,
        "gateway_errors": 0,
        "high_risk_action_attempts": 23,
        "high_risk_action_blocks": 5,
        "high_risk_actions_executed": 0,
        "low_risk_actions_executed": 19,
        "paused_tool_calls": 18,
        "samples": 19,
        "tool_calls": 42,
        "untrusted_outputs_scanned": 19,
    }:
        raise RuntimeError("AgentThreatBench current attack gateway result changed")
    if report["database"] != {
        "action_checks": 34,
        "action_checks_blocked": 5,
        "approval_requests": 5,
        "content_result_decisions": 8,
        "content_result_non_allow_decisions": 8,
        "content_scans": 24,
        "content_scans_blocked": 0,
        "other_risk_events": 0,
        "policy_decisions": 66,
        "reason_codes": {
            "medium_risk_content": 8,
            "no_policy_violation": 53,
            "untrusted_content_influenced_mutation": 5,
        },
        "semantic_shadow_hits": 8,
    }:
        raise RuntimeError("AgentThreatBench current decision evidence changed")
    autonomy = report["by_task"]["autonomy_hijack"]
    if (
        autonomy["attack"]["guarded_effect_security_rate"] != 4 / 5
        or autonomy["attack"]["gateway"]["high_risk_actions_executed"] != 0
        or autonomy["benign"]["guarded_effect_utility_rate"] != 1.0
        or autonomy["benign"]["gateway"]["high_risk_action_blocks"] != 0
    ):
        raise RuntimeError("AgentThreatBench autonomy result changed")


def main() -> int:
    model, model_size = _pinned_file(MODEL, MODEL_SHA256, "model artifact")
    if model != MODEL or model_size != MODEL_SIZE_BYTES:
        raise RuntimeError("AgentThreatBench local model artifact changed")
    if _sha256(SEMANTIC_MODEL) != SEMANTIC_MODEL_SHA256:
        raise RuntimeError("AgentThreatBench semantic model artifact changed")
    _locked_python_runtime(
        RUNTIME_LOCK,
        RUNTIME_LOCK_SHA256,
        RUNTIME_VERSION,
        RUNTIME_SOURCE_SHA256,
    )
    distribution = _python_distribution_metadata(RUNTIME_PYTHON.absolute(), RUNTIME_VERSION)

    reports: dict[int, dict] = {}
    for version, expected_sha256 in REPORTS.items():
        path = _report_path(version)
        if _sha256(path) != expected_sha256:
            raise RuntimeError(f"AgentThreatBench v{version} report SHA-256 changed")
        reports[version] = json.loads(path.read_text(encoding="utf-8"))
        _assert_dataset(reports[version])
    _assert_historical_failures(reports)
    current = reports[7]
    _assert_privacy_boundaries(current)
    _assert_source_and_model(current, distribution)
    _assert_current(current)

    implementation = current["metadata"]["implementation_sha256"]
    files = _frozen_inputs(MODEL, RUNTIME_LOCK)
    if set(implementation) != set(files):
        raise RuntimeError("AgentThreatBench current implementation inventory changed")
    for name, path in files.items():
        if _sha256(path) != implementation[name]:
            raise RuntimeError(f"AgentThreatBench current implementation changed: {name}")

    regenerated = corpus_metadata()
    if regenerated["corpus_sha256"] != CORPUS_SHA256 or regenerated["total"] != 24:
        raise RuntimeError("AgentThreatBench corpus no longer matches evidence")
    print("agent_threat_bench_gateway_evidence=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
