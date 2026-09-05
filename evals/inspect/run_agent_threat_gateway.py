from __future__ import annotations

import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from inspect_ai import eval
from inspect_ai.model import GenerateConfig, get_model

from agent_threat_gateway_task import (
    TASK_NAMES,
    aggregate_gateway_metrics,
    build_agent_threat_task,
    is_attack_sample,
    reset_gateway_metrics,
)
from inspect_evals.agent_threat_bench.dataset import load_agent_threat_bench_dataset


MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")
ERROR_TYPE_PATTERN = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception)):")
ERROR_FRAME_PATTERN = re.compile(
    r'^\s*File "([^"]+)", line [0-9]+, in ([A-Za-z_][A-Za-z0-9_]*)$'
)
GATEWAY_MCP_CODE_PATTERN = re.compile(r"Gateway MCP error code (-?[0-9_]+)")


def _metric_values(log) -> dict[str, float]:
    if log.results is None:
        raise RuntimeError("AgentThreatBench evaluation has no results")
    values: dict[str, float] = {}
    for score in log.results.scores:
        metric = score.metrics.get("accuracy")
        if metric is not None:
            values[score.name] = float(metric.value)
    return values


def _safe_eval_error_type(log) -> str:
    if log.error is None:
        return "missing_error"
    mcp_codes = GATEWAY_MCP_CODE_PATTERN.findall(log.error.traceback)
    if mcp_codes:
        return f"gateway_mcp_code_{mcp_codes[-1]}"
    error_type = "unclassified_error"
    for line in reversed(log.error.traceback.splitlines()):
        match = ERROR_TYPE_PATTERN.match(line.strip())
        if match:
            error_type = match.group(1)
            break
    locations: list[str] = []
    for line in reversed(log.error.traceback.splitlines()):
        match = ERROR_FRAME_PATTERN.match(line)
        if match:
            filename = Path(match.group(1)).name
            locations.append(f"{filename}.{match.group(2)}")
            if len(locations) == 6:
                break
    return ".".join([error_type, *locations])


def main() -> int:
    model_id = os.environ["AGENTOPS_EVAL_LOCAL_MODEL_ID"]
    if not MODEL_ID_PATTERN.fullmatch(model_id):
        raise RuntimeError("local model id has an unsupported format")
    base_url = os.environ["AGENTOPS_EVAL_LOCAL_MODEL_URL"]
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("local model URL must be credential-free loopback HTTP")
    mode = os.environ["AGENTOPS_EVAL_MODE"]
    if mode not in {"baseline", "guarded"}:
        raise RuntimeError("unsupported AgentThreatBench evaluation mode")
    log_root = Path(os.environ["AGENTOPS_EVAL_LOG_DIR"])
    log_root.mkdir(parents=True, exist_ok=True)
    generation_seed = int(os.environ["AGENTOPS_EVAL_GENERATION_SEED"])
    model = get_model(
        f"openai-api/local/{model_id}",
        base_url=base_url.rstrip("/"),
        api_key="local-no-secret",
        config=GenerateConfig(temperature=0, max_tokens=768, seed=generation_seed),
        responses_api=False,
        stream=False,
        strict_tools=False,
        memoize=False,
    )
    reset_gateway_metrics()
    groups: dict[str, dict[str, object]] = {}
    for task_name in TASK_NAMES:
        for kind in ("attack", "benign"):
            task = build_agent_threat_task(task_name, kind=kind, guarded=mode == "guarded")
            expected_ids = {
                str(sample.id)
                for sample in load_agent_threat_bench_dataset(task_name)
                if is_attack_sample(sample) == (kind == "attack")
            }
            logs = eval(
                task,
                model=model,
                display="none",
                log_dir=str(log_root / task_name / kind),
                log_format="json",
                log_samples=False,
                log_model_api=False,
                fail_on_error=True,
                max_samples=1,
                time_limit=180,
            )
            if len(logs) != 1 or logs[0].status != "success" or logs[0].results is None:
                status = logs[0].status if len(logs) == 1 else "log_count_changed"
                error_type = _safe_eval_error_type(logs[0]) if len(logs) == 1 else "none"
                raise RuntimeError(
                    f"AgentThreatBench group {task_name}:{kind} status {status} "
                    f"error {error_type}"
                )
            results = logs[0].results
            if results.total_samples != len(expected_ids) or results.completed_samples != len(
                expected_ids
            ):
                raise RuntimeError("AgentThreatBench sample count changed during execution")
            group: dict[str, object] = {
                "samples": len(expected_ids),
                "completed": results.completed_samples,
                "metrics": _metric_values(logs[0]),
            }
            if mode == "guarded":
                group["gateway"] = aggregate_gateway_metrics(expected_ids)
            groups[f"{task_name}:{kind}"] = group
    print(
        json.dumps(
            {
                "framework": "inspect-ai",
                "framework_version": "0.3.262",
                "inspect_evals_version": "0.16.0",
                "mode": mode,
                "groups": groups,
                "generation_config": {
                    "temperature": 0,
                    "max_tokens": 768,
                    "seed": generation_seed,
                },
                "stores_sample_transcripts": False,
                "stores_model_api": False,
                "uses_model_api_secret": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
