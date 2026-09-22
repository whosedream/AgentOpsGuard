#!/usr/bin/env python3
"""Frozen external English test plus separately labelled Chinese diagnostic pairs."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import UTC, datetime
import json
from pathlib import Path
import time

from agentops_guard.benchmarks.llmail_inject import (
    BenchmarkSample, DEFAULT_MODEL_SHA256, SEMANTIC_MANIFEST_SHA256, SEMANTIC_MODEL_ID,
    evaluate_samples, file_sha256, wilson_interval,
)
from agentops_guard.evals.holdouts import (
    first_run_holdout, register_holdout, system_snapshot_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "evals/boundary-quality-source.json"
CHINESE = ROOT / "tests/fixtures/chinese_boundary_pairs_v1.json"


def frozen_inputs():
    paths = sorted((ROOT / "src").rglob("*.py"))
    paths += sorted((ROOT / "policies").glob("*.rego"))
    paths += [Path(__file__), LOCK, ROOT / "pyproject.toml", ROOT / "uv.lock",
              ROOT / "models/semantic-guard/manifest.json",
              ROOT / "models/semantic-guard/model.safetensors"]
    hashes = {str(path.relative_to(ROOT)): file_sha256(path) for path in paths}
    snapshot = system_snapshot_sha256({f"input_{i}": path for i, path in enumerate(paths)})
    return snapshot, hashes


def load_rows(path: Path, source: dict):
    if file_sha256(path) != source["sha256"]:
        raise ValueError("evaluation source digest changed")
    if source["language"] == "en":
        raw = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows = [{"id": row["id"], "pair_id": row["pair_id"], "family": row["pair_family"],
                 "text": row["text"], "label": row["label"]} for row in raw]
        if any(row["split"] != "test" or row["language"] != "en" for row in raw):
            raise ValueError("external source is not the locked English test split")
    else:
        raw = json.loads(path.read_text(encoding="utf-8"))["pairs"]
        rows = [{"id": pair["id"] + "_" + kind, "pair_id": pair["id"], "family": pair["family"],
                 "text": pair[kind], "label": label} for pair in raw
                for kind, label in (("attack", 1), ("benign", 0))]
    counts = Counter(row["label"] for row in rows)
    if counts != {0: source["benign"], 1: source["attack"]}:
        raise ValueError("source class counts changed")
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError("duplicate sample identifiers")
    normalized = [" ".join(row["text"].casefold().split()) for row in rows]
    if len(set(normalized)) != len(rows):
        raise ValueError("duplicate normalized evaluation text")
    pairs = defaultdict(list)
    for row in rows:
        pairs[row["pair_id"]].append(row["label"])
    if any(sorted(labels) != [0, 1] for labels in pairs.values()):
        raise ValueError("each pair must contain one attack and one benign sample")
    return rows


def metrics(rows, results):
    output = {}
    flags = {
        "rules": lambda result: result.regex_flagged,
        "model": lambda result: result.model_flagged,
        "union": lambda result: result.regex_flagged or result.model_flagged,
    }
    for name, flagged in flags.items():
        tp = fp = tn = fn = 0
        pairs = defaultdict(list)
        for row, result in zip(rows, results, strict=True):
            positive = bool(flagged(result))
            tp += bool(row["label"] and positive)
            fn += bool(row["label"] and not positive)
            fp += bool(not row["label"] and positive)
            tn += bool(not row["label"] and not positive)
            pairs[row["pair_id"]].append(positive == bool(row["label"]))
        output[name] = {
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": tp / (tp + fn), "false_positive_rate": fp / (fp + tn),
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall_wilson_95": wilson_interval(tp, tp + fn),
            "fpr_wilson_95": wilson_interval(fp, fp + tn),
            "pairs_both_correct": sum(all(values) for values in pairs.values()),
            "pairs": len(pairs),
            "meets_point_targets": tp / (tp + fn) >= 0.9 and fp / (fp + tn) <= 0.01,
        }
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--english-path", type=Path, required=True)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--first-run", action="store_true")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--output-directory", type=Path, default=ROOT / "artifacts/benchmarks/boundary-quality-v1")
    parser.add_argument("--manifest", type=Path, default=ROOT / "evals/holdouts/manifest.json")
    args = parser.parse_args()
    if args.prepare == args.first_run:
        parser.error("choose exactly one of --prepare or --first-run")
    lock = json.loads(LOCK.read_text())
    snapshot, hashes = frozen_inputs()
    for source, path in zip(lock["datasets"], (args.english_path, CHINESE), strict=True):
        if args.prepare:
            rows = load_rows(path, source)
            register_holdout(args.manifest, dataset_id=source["id"], corpus_sha256=source["sha256"],
                counts={"attack": source["attack"], "benign": source["benign"]},
                source={key: source[key] for key in ("name", "revision", "license")},
                custodian_ref="automated_source_lock" if source["independent_public_source"] else "self_authored_diagnostic",
                frozen_system_sha256=snapshot)
            print(json.dumps({"registered": source["id"], "rows": len(rows), "frozen_system_sha256": snapshot}), flush=True)
            continue
        with first_run_holdout(args.manifest, dataset_id=source["id"],
                              run_ref=source["id"] + "_first", frozen_system_sha256=snapshot) as ticket:
            started = time.monotonic()
            rows = load_rows(path, source)
            samples = [BenchmarkSample("attack" if row["label"] else "benign", row["text"])
                       for row in rows]
            results = evaluate_samples(samples, model_path=ROOT / "models/semantic-guard",
                model_sha256=DEFAULT_MODEL_SHA256, manifest_sha256=SEMANTIC_MANIFEST_SHA256,
                threshold=lock["threshold"], workers=args.workers)
            if frozen_inputs()[0] != snapshot:
                raise RuntimeError("system changed while scoring the frozen evaluation")
            summary = metrics(rows, results)
            families = {}
            for family in sorted({row["family"] for row in rows}):
                selected = [(row, result) for row, result in zip(rows, results, strict=True)
                            if row["family"] == family]
                families[family] = metrics([row for row, _ in selected], [result for _, result in selected])
            report = {
                "schema_version": 1, "created_at": datetime.now(UTC).isoformat(),
                "scope": "static_external_content_scanning_not_agent_attack_prevention",
                "source": source, "frozen_system_sha256": snapshot, "implementation_hashes": hashes,
                "configuration": {"mode": "shadow", "threshold": lock["threshold"],
                    "source": lock["source_context"], "model": SEMANTIC_MODEL_ID,
                    "model_sha256": DEFAULT_MODEL_SHA256, "managed_policy_packs": False},
                "summary": summary, "by_family": families,
                "duration_seconds": round(time.monotonic() - started, 3),
                "stores_raw_text": False, "stores_credentials": False,
                "independent_human_blind_evaluation": False,
                "notes": ["Public source authors reviewed synthetic pairs; Chinese pairs are locally authored diagnostics.",
                          "No classifier threshold or rule changes after viewing these results.",
                          "No claim of model-pretraining exclusion, live agent safety, or production traffic representativeness.",
                          "Small correlated pairs cannot establish a production false-positive ceiling of 1%."],
            }
            args.output_directory.mkdir(parents=True, exist_ok=True)
            output = args.output_directory / (source["id"] + ".json")
            if output.exists():
                raise RuntimeError("refusing to overwrite a first-run report")
            output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            ticket.record_report(output)
            print(json.dumps({"dataset": source["id"], "summary": summary}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
