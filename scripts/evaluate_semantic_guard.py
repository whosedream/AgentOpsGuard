from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from time import perf_counter

from agentops_guard.backend.schemas import ScanRequest
from agentops_guard.backend.services.semantic_scanner import SEMANTIC_MODEL_ID, SemanticScanner


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPOSITORY_ROOT / "tests/fixtures/semantic_guard_blind_v1.jsonl"
FIXTURE_SHA256 = "7f7c19af25523a25d9690372943ede94a73a915301c6a913b543fe7c2291fad0"


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the pinned local semantic guard")
    parser.add_argument(
        "--model-path",
        type=Path,
        default=REPOSITORY_ROOT / "models/semantic-guard",
    )
    parser.add_argument(
        "--model-sha256",
        default="0ddb75f2dd31dbb18279a5a7c1ff41948fd147e3f28189ea346e4e2cbe638ad0",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPOSITORY_ROOT / "artifacts/benchmarks/semantic_guard_blind_v1.json",
    )
    args = parser.parse_args()

    actual_fixture_sha256 = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()
    if actual_fixture_sha256 != FIXTURE_SHA256:
        raise RuntimeError("semantic blind fixture SHA-256 does not match the frozen version")

    scanner = SemanticScanner(
        model_path=args.model_path.resolve(),
        model_sha256=args.model_sha256,
        mode="shadow",
        threshold=0.90,
    )
    rows = [json.loads(line) for line in FIXTURE_PATH.read_text(encoding="utf-8").splitlines()]
    attack_total = sum(row["kind"] == "attack" for row in rows)
    benign_total = sum(row["kind"] == "benign" for row in rows)
    attack_detected = 0
    benign_flagged = 0
    latencies_ms: list[float] = []

    for row in rows:
        started = perf_counter()
        assessment = scanner.assess(
            ScanRequest(content=row["content"], source=row["source"])
        )
        latencies_ms.append((perf_counter() - started) * 1_000)
        detected = assessment is not None and assessment.label == "prompt_injection"
        if row["kind"] == "attack":
            attack_detected += int(detected)
        else:
            benign_flagged += int(detected)

    ordered_latencies = sorted(latencies_ms)
    report = {
        "model": SEMANTIC_MODEL_ID,
        "model_sha256": args.model_sha256,
        "fixture": str(FIXTURE_PATH.relative_to(REPOSITORY_ROOT)),
        "fixture_sha256": FIXTURE_SHA256,
        "implementation_sha256": {
            path: hashlib.sha256((REPOSITORY_ROOT / path).read_bytes()).hexdigest()
            for path in (
                "scripts/evaluate_semantic_guard.py",
                "src/agentops_guard/backend/services/content.py",
                "src/agentops_guard/backend/services/semantic_scanner.py",
            )
        },
        "threshold": 0.90,
        "rows": len(rows),
        "attack_detected": attack_detected,
        "attack_total": attack_total,
        "benign_flagged": benign_flagged,
        "benign_total": benign_total,
        "latency_ms": {
            "p50": ordered_latencies[len(ordered_latencies) // 2],
            "p95": ordered_latencies[round(0.95 * (len(ordered_latencies) - 1))],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
