#!/usr/bin/env python3
"""Register InjecAgent aggregate metadata without printing evaluation content."""

from __future__ import annotations

import argparse
from pathlib import Path

from agentops_guard.benchmarks.injecagent import (
    DEFAULT_REPOSITORY,
    load_injecagent_samples,
    load_source_lock,
)
from agentops_guard.benchmarks.llmail_inject import (
    DEFAULT_MODEL_PATH,
    DEFAULT_MODEL_SHA256,
)
from agentops_guard.backend.services.semantic_scanner import SEMANTIC_MANIFEST_SHA256
from agentops_guard.evals.holdouts import register_holdout
from benchmark_injecagent_static import (
    DATASET_ID,
    DEFAULT_HOLDOUT_MANIFEST,
    EXPECTED_ATTACK_ROWS,
    EXPECTED_BENIGN_ROWS,
    _validate_inventory,
    current_frozen_system_sha256,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--injecagent-repository", type=Path, default=DEFAULT_REPOSITORY)
    parser.add_argument("--holdout-manifest", type=Path, default=DEFAULT_HOLDOUT_MANIFEST)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--model-sha256", default=DEFAULT_MODEL_SHA256)
    parser.add_argument("--manifest-sha256", default=SEMANTIC_MANIFEST_SHA256)
    parser.add_argument("--threshold", type=float, default=0.90)
    args = parser.parse_args()

    samples, inventory = load_injecagent_samples(args.injecagent_repository)
    _validate_inventory(inventory)
    if len(samples) != EXPECTED_ATTACK_ROWS + EXPECTED_BENIGN_ROWS:
        raise RuntimeError("InjecAgent sample count changed")
    frozen_system = current_frozen_system_sha256(
        model_path=args.model_path.resolve(strict=True),
        model_sha256=args.model_sha256,
        manifest_sha256=args.manifest_sha256,
        threshold=args.threshold,
    )
    lock = load_source_lock()
    register_holdout(
        args.holdout_manifest.absolute(),
        dataset_id=DATASET_ID,
        corpus_sha256=inventory["selected_corpus_sha256"],
        counts={"attack": inventory["attack_rows"], "benign": inventory["benign_rows"]},
        source={
            "name": "uiuc-kang-lab/injecagent",
            "revision": lock["commit"],
            "license": "MIT",
        },
        custodian_ref="local_noninteractive_importer",
        frozen_system_sha256=frozen_system,
    )
    print(
        f"holdout_registered=true dataset={DATASET_ID} "
        f"attack={inventory['attack_rows']} benign={inventory['benign_rows']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
