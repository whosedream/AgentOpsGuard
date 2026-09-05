#!/usr/bin/env python3
"""Validate or summarize the aggregate-only holdout registry."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from agentops_guard.evals.holdouts import load_holdout_manifest


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "evals" / "holdouts" / "manifest.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("validate", "status"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    manifest = load_holdout_manifest(args.manifest.absolute())
    if args.command == "validate":
        print("holdout_manifest=verified")
        return 0
    roles = Counter(dataset["role"] for dataset in manifest["datasets"])
    states = Counter(dataset["state"] for dataset in manifest["datasets"])
    role_summary = ",".join(f"{name}:{roles[name]}" for name in sorted(roles))
    state_summary = ",".join(f"{name}:{states[name]}" for name in sorted(states))
    print(
        f"holdout_manifest=verified datasets={len(manifest['datasets'])} "
        f"roles={role_summary} states={state_summary}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
