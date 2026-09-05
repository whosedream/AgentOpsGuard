#!/usr/bin/env python3
"""Verify immutable InjecAgent first-run evidence without rerunning inference."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentops_guard.benchmarks.injecagent import (
    DEFAULT_REPOSITORY,
    load_injecagent_samples,
    load_source_lock,
)
from agentops_guard.benchmarks.llmail_inject import file_sha256
from agentops_guard.evals.holdouts import load_holdout_manifest
from benchmark_injecagent_static import (
    DATASET_ID,
    DEFAULT_HOLDOUT_MANIFEST,
    DEFAULT_OUTPUT,
    EXPECTED_ATTACK_ROWS_BY_FAMILY,
    RUN_REF,
    _validate_inventory,
)


REPORT_SHA256 = "8280fb906b2fff696ac6b6f05454f367ba0563503c0556d0b9accee0c8298e98"
EXPECTED_GROUPS = {
    "data_stealing": {
        "rows": 544,
        "regex_flagged": 19,
        "model_flagged": 438,
        "combined_flagged": 444,
    },
    "direct_harm": {
        "rows": 510,
        "regex_flagged": 1,
        "model_flagged": 133,
        "combined_flagged": 133,
    },
}
EXPECTED_FAMILIES = {
    "data_stealing:Financial Data": (102, 2, 89, 89),
    "data_stealing:Others": (255, 10, 191, 196),
    "data_stealing:Physical Data": (187, 7, 158, 159),
    "direct_harm:Data Security Harm": (187, 1, 72, 72),
    "direct_harm:Financial Harm": (153, 0, 21, 21),
    "direct_harm:Physical Harm": (170, 0, 40, 40),
}


def _require_counts(group: Any, expected: dict[str, int], label: str) -> None:
    if not isinstance(group, dict):
        raise RuntimeError(f"InjecAgent {label} summary is invalid")
    for name, value in expected.items():
        if group.get(name) != value:
            raise RuntimeError(f"InjecAgent {label} result changed: {name}")
    latency = group.get("latency_ms")
    if not isinstance(latency, dict):
        raise RuntimeError(f"InjecAgent {label} latency is missing")
    for stage in ("regex", "model", "combined_sequential"):
        values = latency.get(stage)
        if (
            not isinstance(values, dict)
            or not isinstance(values.get("p50"), (int, float))
            or not isinstance(values.get("p95"), (int, float))
            or values["p50"] < 0
            or values["p95"] < values["p50"]
        ):
            raise RuntimeError(f"InjecAgent {label} latency is invalid")


def main() -> int:
    if not DEFAULT_OUTPUT.is_file() or file_sha256(DEFAULT_OUTPUT) != REPORT_SHA256:
        raise RuntimeError("InjecAgent first-run report SHA-256 changed")
    report = json.loads(DEFAULT_OUTPUT.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or set(report) != {"metadata", "summary"}:
        raise RuntimeError("InjecAgent report schema changed")
    metadata = report["metadata"]
    summary = report["summary"]
    if (
        not isinstance(metadata, dict)
        or metadata.get("evidence_kind") != "first_run_pre_tuning_external_holdout"
        or metadata.get("frozen_system_sha256")
        != "1cdd4b69586117d2ec375ce8ca1aebb9daae5452f71030a206553d03eaaf198b"
    ):
        raise RuntimeError("InjecAgent first-run evidence boundary changed")
    privacy = metadata.get("privacy")
    if privacy != {
        "stores_raw_cases": False,
        "stores_per_case_results": False,
        "stores_model_scores": False,
        "stores_model_outputs": False,
    }:
        raise RuntimeError("InjecAgent privacy boundary changed")
    serialized = json.dumps(report, ensure_ascii=False)
    for forbidden in (
        '"Attacker Instruction"',
        '"Tool Response"',
        '"User Instruction"',
        '"cases"',
        '"model_responses"',
    ):
        if forbidden in serialized:
            raise RuntimeError("InjecAgent report retained forbidden evaluation content")

    dataset = metadata.get("dataset")
    lock = load_source_lock()
    if (
        not isinstance(dataset, dict)
        or dataset.get("name") != "UIUC InjecAgent"
        or dataset.get("commit") != lock["commit"]
        or dataset.get("license") != "MIT"
        or dataset.get("attack_rows") != 1_054
        or dataset.get("benign_rows") != 17
        or dataset.get("attack_rows_by_family") != EXPECTED_ATTACK_ROWS_BY_FAMILY
    ):
        raise RuntimeError("InjecAgent dataset evidence changed")
    samples, inventory = load_injecagent_samples(DEFAULT_REPOSITORY)
    _validate_inventory(inventory)
    if len(samples) != 1_071 or dataset.get("selected_corpus_sha256") != inventory[
        "selected_corpus_sha256"
    ]:
        raise RuntimeError("InjecAgent corpus no longer matches first-run evidence")

    model = metadata.get("model")
    if not isinstance(model, dict):
        raise RuntimeError("InjecAgent model evidence is missing")
    model_path = Path("models/semantic-guard").resolve(strict=True)
    if (
        file_sha256(model_path / "model.safetensors") != model.get("sha256")
        or file_sha256(model_path / "manifest.json") != model.get("manifest_sha256")
    ):
        raise RuntimeError("InjecAgent model evidence changed")

    _require_counts(
        summary.get("attack"),
        {
            "rows": 1_054,
            "regex_flagged": 20,
            "model_flagged": 571,
            "combined_flagged": 577,
        },
        "attack",
    )
    _require_counts(
        summary.get("benign"),
        {
            "rows": 17,
            "regex_flagged": 0,
            "model_flagged": 1,
            "combined_flagged": 1,
        },
        "benign",
    )
    groups = summary.get("attack_by_group")
    if not isinstance(groups, dict) or set(groups) != set(EXPECTED_GROUPS):
        raise RuntimeError("InjecAgent attack-group inventory changed")
    for name, expected in EXPECTED_GROUPS.items():
        _require_counts(groups[name], expected, name)
    families = summary.get("attack_by_family")
    if not isinstance(families, dict) or set(families) != set(EXPECTED_FAMILIES):
        raise RuntimeError("InjecAgent family inventory changed")
    for name, (rows, regex, model_hits, combined) in EXPECTED_FAMILIES.items():
        _require_counts(
            families[name],
            {
                "rows": rows,
                "regex_flagged": regex,
                "model_flagged": model_hits,
                "combined_flagged": combined,
            },
            name,
        )

    manifest = load_holdout_manifest(DEFAULT_HOLDOUT_MANIFEST)
    registered = next(
        (dataset for dataset in manifest["datasets"] if dataset["id"] == DATASET_ID),
        None,
    )
    if (
        not isinstance(registered, dict)
        or registered.get("role") != "regression"
        or registered.get("state") != "consumed"
        or registered.get("corpusSha256") != inventory["selected_corpus_sha256"]
        or registered.get("frozenSystemSha256") != metadata["frozen_system_sha256"]
        or registered.get("firstRun", {}).get("runRef") != RUN_REF
        or registered.get("firstRun", {}).get("outcome") != "succeeded"
        or registered.get("firstRun", {}).get("reportSha256") != REPORT_SHA256
    ):
        raise RuntimeError("InjecAgent holdout lifecycle evidence changed")
    print("injecagent_static_holdout_evidence=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
