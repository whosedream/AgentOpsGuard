from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path

from inspect_evals.agent_threat_bench.dataset import DATA_DIR, load_agent_threat_bench_dataset

from agent_threat_gateway_task import TASK_NAMES, is_attack_sample


def _corpus_sha256() -> str:
    digest = hashlib.sha256()
    for task_name in TASK_NAMES:
        data = (DATA_DIR / f"{task_name}.json").read_bytes()
        label = task_name.encode("ascii")
        digest.update(len(label).to_bytes(4, "big"))
        digest.update(label)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt-output", type=Path)
    args = parser.parse_args()
    counts: dict[str, dict[str, int]] = {}
    prompts: dict[str, str] = {}
    sample_ids: set[str] = set()
    for task_name in TASK_NAMES:
        task_counts = {"attack": 0, "benign": 0}
        for sample in load_agent_threat_bench_dataset(task_name):
            sample_id = str(sample.id)
            if sample_id in sample_ids:
                raise RuntimeError("AgentThreatBench sample id is duplicated")
            sample_ids.add(sample_id)
            kind = "attack" if is_attack_sample(sample) else "benign"
            task_counts[kind] += 1
            if args.prompt_output is not None:
                if not isinstance(sample.input, str):
                    raise RuntimeError("AgentThreatBench sample input contract changed")
                prompts[sample_id] = sample.input
        if not task_counts["attack"] or not task_counts["benign"]:
            raise RuntimeError("AgentThreatBench must include attacks and clean controls")
        counts[task_name] = task_counts
    if args.prompt_output is not None:
        descriptor = os.open(
            args.prompt_output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(prompts, handle, ensure_ascii=False, separators=(",", ":"))
    print(
        json.dumps(
            {
                "package": "inspect-evals",
                "package_version": version("inspect-evals"),
                "task_version": "1-A",
                "counts": counts,
                "total": sum(sum(group.values()) for group in counts.values()),
                "corpus_sha256": _corpus_sha256(),
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
