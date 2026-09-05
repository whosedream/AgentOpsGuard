#!/usr/bin/env python3
"""Run the first frozen static scan over official InjecAgent base cases."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

from agentops_guard.backend.services.semantic_scanner import (
    SEMANTIC_MANIFEST_SHA256,
    SEMANTIC_MODEL_ID,
)
from agentops_guard.benchmarks.injecagent import (
    DEFAULT_REPOSITORY,
    load_injecagent_samples,
    load_source_lock,
    summarize_injecagent_results,
)
from agentops_guard.benchmarks.llmail_inject import (
    DEFAULT_MODEL_PATH,
    DEFAULT_MODEL_SHA256,
    evaluate_samples,
    file_sha256,
)
from agentops_guard.evals.holdouts import (
    first_run_holdout,
    load_holdout_manifest,
    system_snapshot_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "benchmarks" / "injecagent_static_holdout_v1.json"
DEFAULT_HOLDOUT_MANIFEST = ROOT / "evals" / "holdouts" / "manifest.json"
DATASET_ID = "injecagent_static_v1"
RUN_REF = "injecagent_static_first_run_v1"
EXPECTED_ATTACK_ROWS = 1_054
EXPECTED_BENIGN_ROWS = 17
EXPECTED_ATTACK_ROWS_BY_FAMILY = {
    "data_stealing:Financial Data": 102,
    "data_stealing:Others": 255,
    "data_stealing:Physical Data": 187,
    "direct_harm:Data Security Harm": 187,
    "direct_harm:Financial Harm": 153,
    "direct_harm:Physical Harm": 170,
}
SYSTEM_INPUTS = {
    "benchmark_adapter": ROOT / "src/agentops_guard/benchmarks/injecagent.py",
    "benchmark_runner": ROOT / "scripts/benchmark_injecagent_static.py",
    "content_redaction": ROOT / "src/agentops_guard/backend/services/content.py",
    "policy_engine": ROOT / "src/agentops_guard/backend/services/policy.py",
    "project_dependencies": ROOT / "pyproject.toml",
    "python_lock": ROOT / "uv.lock",
    "scan_contract": ROOT / "src/agentops_guard/backend/schemas.py",
    "scanner": ROOT / "src/agentops_guard/backend/services/scanner.py",
    "semantic_scanner": ROOT
    / "src/agentops_guard/backend/services/semantic_scanner.py",
    "source_lock": ROOT / "evals/injecagent-source.json",
}


def current_frozen_system_sha256(
    *,
    model_path: Path,
    model_sha256: str,
    manifest_sha256: str,
    threshold: float,
) -> str:
    resolved_model = model_path.resolve(strict=True)
    manifest = resolved_model / "manifest.json"
    weights = resolved_model / "model.safetensors"
    if file_sha256(manifest) != manifest_sha256:
        raise RuntimeError("semantic model manifest changed before holdout execution")
    if file_sha256(weights) != model_sha256:
        raise RuntimeError("semantic model weights changed before holdout execution")
    file_snapshot = system_snapshot_sha256(
        {
            **SYSTEM_INPUTS,
            "semantic_manifest": manifest,
            "semantic_weights": weights,
        }
    )
    configuration = json.dumps(
        {
            "content_source": "mcp_tool_result",
            "manifest_sha256": manifest_sha256,
            "model_sha256": model_sha256,
            "semantic_mode": "shadow",
            "threshold": threshold,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(bytes.fromhex(file_snapshot))
    digest.update(configuration)
    return digest.hexdigest()


def _implementation_hashes(model_path: Path) -> dict[str, str]:
    paths = {path.relative_to(ROOT).as_posix(): path for path in SYSTEM_INPUTS.values()}
    paths["models/semantic-guard/manifest.json"] = model_path / "manifest.json"
    paths["models/semantic-guard/model.safetensors"] = model_path / "model.safetensors"
    return {name: file_sha256(path) for name, path in sorted(paths.items())}


def _registered_holdout(manifest_path: Path) -> dict[str, Any]:
    manifest = load_holdout_manifest(manifest_path)
    for dataset in manifest["datasets"]:
        if dataset["id"] == DATASET_ID:
            return dataset
    raise RuntimeError("InjecAgent holdout is not registered")


def _validate_inventory(inventory: dict[str, Any]) -> None:
    expected = {
        "attack_rows": EXPECTED_ATTACK_ROWS,
        "benign_rows": EXPECTED_BENIGN_ROWS,
        "attack_rows_by_family": EXPECTED_ATTACK_ROWS_BY_FAMILY,
        "user_tools": 17,
        "first_stage_attacker_tools": 62,
        "unique_attacker_instructions": 62,
        "setting": "base",
        "benign_control": (
            "one matched response template per user tool with a neutral placeholder"
        ),
    }
    for name, value in expected.items():
        if inventory.get(name) != value:
            raise RuntimeError(f"InjecAgent selected inventory changed: {name}")


def _write_new_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the frozen InjecAgent external-content holdout"
    )
    parser.add_argument("--injecagent-repository", type=Path, default=DEFAULT_REPOSITORY)
    parser.add_argument("--holdout-manifest", type=Path, default=DEFAULT_HOLDOUT_MANIFEST)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--model-sha256", default=DEFAULT_MODEL_SHA256)
    parser.add_argument("--manifest-sha256", default=SEMANTIC_MANIFEST_SHA256)
    parser.add_argument("--threshold", type=float, default=0.90)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.workers <= 0:
        parser.error("--workers must be positive")
    if not 0 < args.threshold < 1:
        parser.error("--threshold must be between 0 and 1")
    if args.output.exists():
        parser.error("output already exists; holdout evidence is immutable")

    model_path = args.model_path.resolve(strict=True)
    frozen_system = current_frozen_system_sha256(
        model_path=model_path,
        model_sha256=args.model_sha256,
        manifest_sha256=args.manifest_sha256,
        threshold=args.threshold,
    )
    registered = _registered_holdout(args.holdout_manifest.absolute())
    if (
        registered["role"] != "first_run_holdout"
        or registered["state"] != "sealed"
        or registered["frozenSystemSha256"] != frozen_system
    ):
        raise RuntimeError("InjecAgent holdout is not sealed for this system")

    with first_run_holdout(
        args.holdout_manifest.absolute(),
        dataset_id=DATASET_ID,
        run_ref=RUN_REF,
        frozen_system_sha256=frozen_system,
    ) as ticket:
        samples, inventory = load_injecagent_samples(args.injecagent_repository)
        _validate_inventory(inventory)
        if inventory["selected_corpus_sha256"] != registered["corpusSha256"]:
            raise RuntimeError("InjecAgent corpus does not match the sealed holdout")
        if len(samples) != EXPECTED_ATTACK_ROWS + EXPECTED_BENIGN_ROWS:
            raise RuntimeError("InjecAgent sample count changed")

        results = evaluate_samples(
            samples,
            model_path=model_path,
            model_sha256=args.model_sha256,
            manifest_sha256=args.manifest_sha256,
            threshold=args.threshold,
            workers=args.workers,
        )
        lock = load_source_lock()
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        report = {
            "metadata": {
                "created_at": datetime.now(UTC).isoformat(),
                "git_commit": commit,
                "git_dirty": bool(
                    subprocess.check_output(
                        ["git", "status", "--porcelain"], cwd=ROOT, text=True
                    ).strip()
                ),
                "runtime": {
                    "python": sys.version,
                    "platform": platform.platform(),
                    "workers": args.workers,
                },
                "dataset": {
                    "name": "UIUC InjecAgent",
                    "source": lock["repository"],
                    "commit": lock["commit"],
                    "license": "MIT",
                    "source_blobs": {
                        path: specification["sha256"]
                        for path, specification in sorted(lock["files"].items())
                    },
                    **inventory,
                },
                "model": {
                    "id": SEMANTIC_MODEL_ID,
                    "sha256": args.model_sha256,
                    "manifest_sha256": args.manifest_sha256,
                    "threshold": args.threshold,
                    "mode": "shadow",
                },
                "frozen_system_sha256": frozen_system,
                "implementation_sha256": _implementation_hashes(model_path),
                "evidence_kind": "first_run_pre_tuning_external_holdout",
                "scope": (
                    "First frozen static scan of the official InjecAgent base-setting tool "
                    "responses. This measures external-content scanner generalization, not the "
                    "official prompted-agent attack-success rate and not end-to-end tool blocking."
                ),
                "privacy": {
                    "stores_raw_cases": False,
                    "stores_per_case_results": False,
                    "stores_model_scores": False,
                    "stores_model_outputs": False,
                },
            },
            "summary": summarize_injecagent_results(results),
        }
        _write_new_report(report, args.output)
        ticket.record_report(args.output)

    attack = report["summary"]["attack"]
    benign = report["summary"]["benign"]
    print(
        f"attack_combined={attack['combined_flagged']}/{attack['rows']} "
        f"benign_combined={benign['combined_flagged']}/{benign['rows']} "
        "report_created=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
