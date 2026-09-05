#!/usr/bin/env python3
"""Verify immutable BIPIA static first-run evidence without rerunning inference."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from evidence_lock_compatibility import (
    assert_compatible_uv_lock as _assert_compatible_uv_lock,  # noqa: F401
)

from agentops_guard.benchmarks.bipia import (
    DEFAULT_REPOSITORY,
    load_bipia_samples,
    load_source_lock,
)


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "artifacts" / "benchmarks" / "bipia_static_holdout_v1.json"
REPORT_SHA256 = "4e9bb897996d85cad3e7bc15859abecd6b361a448d1e30a22e9a1063f74e53e6"
CANDIDATE_REPORT = (
    ROOT / "artifacts" / "benchmarks" / "bipia_protectai_candidate_regression_v1.json"
)
CANDIDATE_REPORT_SHA256 = (
    "46dbcba1736ad2feffb7de9da86ce684dcadf59c5abe78d275a74335db91c5a4"
)
CANDIDATE_LOCK = ROOT / "evals" / "protectai-deberta-v3-base-prompt-injection-v2.json"
WINDOWING_REPORT = ROOT / "artifacts" / "benchmarks" / "bipia_windowing_probe_v1.json"
WINDOWING_REPORT_SHA256 = (
    "8be6408086557eacbd285adcb88985e543e5f9cd34d13015b2cd0c60e69b7e66"
)
WINDOWING_CALIBRATION_REPORT = (
    ROOT / "artifacts" / "benchmarks" / "bipia_windowing_calibration_v1.json"
)
WINDOWING_CALIBRATION_REPORT_SHA256 = (
    "a1e2137ea7ef81decbdee1bab78fe3fba7e00c9283049c352e8ec7213222e1df"
)
WINDOWING_SOURCE_LOCK = ROOT / "evals" / "llama-cookbook-prompt-guard-source.json"
CORPUS_SHA256 = "085d4c01c64b7ebbbd52503cabb5adf008032aca73503ed4720e4e62748132c3"
MODEL_SHA256 = "0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0"
MANIFEST_SHA256 = "06bcefdafa24f95cd9901d8a46ec0f295ac144e89c9618197733948987c3bec4"


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _assert_group(
    group: dict,
    *,
    rows: int,
    regex_flagged: int,
    model_flagged: int,
    combined_flagged: int,
) -> None:
    expected = {
        "rows": rows,
        "regex_flagged": regex_flagged,
        "model_flagged": model_flagged,
        "combined_flagged": combined_flagged,
    }
    if any(group.get(key) != value for key, value in expected.items()):
        raise RuntimeError("BIPIA aggregate result changed")


def main() -> int:
    if _sha256(REPORT) != REPORT_SHA256:
        raise RuntimeError("BIPIA first-run report SHA-256 changed")
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    if set(report) != {"metadata", "summary"}:
        raise RuntimeError("BIPIA report schema changed")
    metadata = report["metadata"]
    dataset = metadata["dataset"]
    if (
        metadata.get("evidence_kind") != "first_run_pre_tuning_external_holdout"
        or dataset.get("commit") != "a004b69ec0dd446e0afd461d98cb5e96e120a5d0"
        or dataset.get("selected_corpus_sha256") != CORPUS_SHA256
        or dataset.get("attack_rows") != 13_750
        or dataset.get("benign_rows") != 200
        or metadata.get("privacy")
        != {
            "stores_model_scores": False,
            "stores_per_case_results": False,
            "stores_raw_cases": False,
        }
    ):
        raise RuntimeError("BIPIA dataset or evidence boundary changed")
    model = metadata["model"]
    if (
        model.get("sha256") != MODEL_SHA256
        or model.get("manifest_sha256") != MANIFEST_SHA256
        or model.get("threshold") != 0.9
        or model.get("mode") != "shadow"
    ):
        raise RuntimeError("BIPIA model evidence changed")

    summary = report["summary"]
    _assert_group(
        summary["attack"],
        rows=13_750,
        regex_flagged=491,
        model_flagged=4_786,
        combined_flagged=5_264,
    )
    _assert_group(
        summary["benign"],
        rows=200,
        regex_flagged=1,
        model_flagged=12,
        combined_flagged=13,
    )
    task_results = {
        "email": ((3_750, 0, 1_911, 1_911), (50, 0, 1, 1)),
        "table": ((7_500, 0, 2_804, 2_804), (100, 0, 8, 8)),
        "code": ((2_500, 491, 71, 549), (50, 1, 3, 4)),
    }
    for task, (attack, benign) in task_results.items():
        _assert_group(
            summary["by_task"][task]["attack"],
            rows=attack[0],
            regex_flagged=attack[1],
            model_flagged=attack[2],
            combined_flagged=attack[3],
        )
        _assert_group(
            summary["by_task"][task]["benign"],
            rows=benign[0],
            regex_flagged=benign[1],
            model_flagged=benign[2],
            combined_flagged=benign[3],
        )

    if _sha256(ROOT / "models" / "semantic-guard" / "model.safetensors") != MODEL_SHA256:
        raise RuntimeError("local semantic model no longer matches BIPIA evidence")
    if _sha256(ROOT / "models" / "semantic-guard" / "manifest.json") != MANIFEST_SHA256:
        raise RuntimeError("local semantic manifest no longer matches BIPIA evidence")

    lock = load_source_lock()
    if dataset["source_blobs"] != {
        path: specification["sha256"]
        for path, specification in sorted(lock["files"].items())
    }:
        raise RuntimeError("BIPIA source lock no longer matches the report")
    if not DEFAULT_REPOSITORY.exists():
        raise RuntimeError("prepare the pinned BIPIA source before evidence verification")
    samples, inventory = load_bipia_samples(DEFAULT_REPOSITORY)
    if (
        len(samples) != 13_950
        or inventory.get("selected_corpus_sha256") != CORPUS_SHA256
        or inventory.get("attack_rows") != 13_750
        or inventory.get("benign_rows") != 200
    ):
        raise RuntimeError("current BIPIA corpus no longer matches first-run evidence")

    if _sha256(CANDIDATE_REPORT) != CANDIDATE_REPORT_SHA256:
        raise RuntimeError("BIPIA rejected-candidate report SHA-256 changed")
    candidate = json.loads(CANDIDATE_REPORT.read_text(encoding="utf-8"))
    candidate_metadata = candidate["metadata"]
    candidate_lock = json.loads(CANDIDATE_LOCK.read_text(encoding="utf-8"))
    candidate_model = candidate_metadata["model"]
    if (
        candidate_metadata.get("evidence_kind") != "post_holdout_candidate_comparison"
        or candidate_metadata.get("baseline")
        != {
            "report": "artifacts/benchmarks/bipia_static_holdout_v1.json",
            "sha256": REPORT_SHA256,
        }
        or candidate_model.get("revision") != candidate_lock.get("revision")
        or candidate_model.get("sha256")
        != candidate_lock.get("files", {}).get("model.safetensors")
        or candidate_model.get("manifest_sha256")
        != candidate_lock.get("runtime_manifest_sha256")
        or candidate_model.get("threshold") != 0.9
        or candidate_model.get("mode") != "candidate_shadow_only"
    ):
        raise RuntimeError("BIPIA rejected-candidate provenance changed")
    _assert_group(
        candidate["summary"]["attack"],
        rows=13_750,
        regex_flagged=491,
        model_flagged=3_073,
        combined_flagged=3_564,
    )
    _assert_group(
        candidate["summary"]["benign"],
        rows=200,
        regex_flagged=1,
        model_flagged=39,
        combined_flagged=40,
    )

    if _sha256(WINDOWING_REPORT) != WINDOWING_REPORT_SHA256:
        raise RuntimeError("BIPIA windowing probe report SHA-256 changed")
    windowing = json.loads(WINDOWING_REPORT.read_text(encoding="utf-8"))
    source = json.loads(WINDOWING_SOURCE_LOCK.read_text(encoding="utf-8"))
    if (
        windowing["metadata"].get("evidence_kind")
        != "post_holdout_architecture_probe"
        or windowing["metadata"]["windowing"].get("adapted_from") != source
        or source.get("commit") != "2f22a9eb030f92d0e99227e57e9a1123af1f9532"
        or source.get("reference_file_sha256")
        != "29afa64415b07811c22b3c2e27330ee40f9e8edff0a7faf4940b8cfc1c74d424"
    ):
        raise RuntimeError("BIPIA windowing probe provenance changed")
    _assert_group(
        windowing["legacy"]["attack"],
        rows=200,
        regex_flagged=9,
        model_flagged=117,
        combined_flagged=126,
    )
    _assert_group(
        windowing["legacy"]["benign"],
        rows=200,
        regex_flagged=1,
        model_flagged=12,
        combined_flagged=13,
    )
    _assert_group(
        windowing["windowed"]["attack"],
        rows=200,
        regex_flagged=9,
        model_flagged=150,
        combined_flagged=159,
    )
    _assert_group(
        windowing["windowed"]["benign"],
        rows=200,
        regex_flagged=1,
        model_flagged=27,
        combined_flagged=28,
    )

    if _sha256(WINDOWING_CALIBRATION_REPORT) != WINDOWING_CALIBRATION_REPORT_SHA256:
        raise RuntimeError("BIPIA windowing calibration report SHA-256 changed")
    calibration = json.loads(WINDOWING_CALIBRATION_REPORT.read_text(encoding="utf-8"))
    if (
        calibration["metadata"].get("evidence_kind")
        != "post_holdout_in_sample_threshold_probe"
        or calibration["metadata"].get("parent_probe")
        != {
            "report": "artifacts/benchmarks/bipia_windowing_probe_v1.json",
            "sha256": WINDOWING_REPORT_SHA256,
        }
        or calibration["metadata"].get("thresholds")
        != [0.9, 0.95, 0.99, 0.995, 0.999]
    ):
        raise RuntimeError("BIPIA windowing calibration provenance changed")
    expected_thresholds = {
        "0.9": (150, 159, 27, 28),
        "0.95": (8, 17, 0, 1),
        "0.99": (0, 9, 0, 1),
        "0.995": (0, 9, 0, 1),
        "0.999": (0, 9, 0, 1),
    }
    for threshold, (attack_model, attack_union, benign_model, benign_union) in (
        expected_thresholds.items()
    ):
        threshold_summary = calibration["threshold_summaries"][threshold]
        attack = threshold_summary["attack"]
        benign = threshold_summary["benign"]
        if (
            attack.get("rows") != 200
            or attack.get("model_flagged") != attack_model
            or attack.get("combined_flagged") != attack_union
            or benign.get("rows") != 200
            or benign.get("model_flagged") != benign_model
            or benign.get("combined_flagged") != benign_union
        ):
            raise RuntimeError("BIPIA windowing threshold result changed")
    print("bipia_static_holdout_evidence=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
