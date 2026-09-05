from __future__ import annotations

import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from inspect_ai import eval
from inspect_ai.model import GenerateConfig, get_model

from agentdojo_dynamic_task import agentdojo_template_dynamic_eval


MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")


def _failure_code(log) -> str:
    message = log.error.message.lower() if log.error is not None else ""
    if "timeout" in message or "timed out" in message:
        return "evaluation_timeout"
    if "tool" in message:
        return "tool_protocol_error"
    if "mcp" in message:
        return "mcp_protocol_error"
    return "inspect_status_not_success"


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
    log_dir = Path(os.environ["AGENTOPS_EVAL_LOG_DIR"])
    log_dir.mkdir(parents=True, exist_ok=True)
    generation_seed = int(os.environ["AGENTOPS_EVAL_GENERATION_SEED"])
    if not 0 <= generation_seed <= 2**32 - 1:
        raise RuntimeError("local model generation seed is invalid")
    model = get_model(
        f"openai-api/local/{model_id}",
        base_url=base_url.rstrip("/"),
        api_key="local-no-secret",
        config=GenerateConfig(temperature=0, max_tokens=512, seed=generation_seed),
        responses_api=False,
        stream=False,
        strict_tools=False,
        memoize=False,
    )
    logs = eval(
        agentdojo_template_dynamic_eval(),
        model=model,
        display="none",
        log_dir=str(log_dir),
        log_format="json",
        log_samples=False,
        log_model_api=False,
        fail_on_error=True,
        max_samples=1,
        time_limit=120,
    )
    if len(logs) != 1 or logs[0].status != "success" or logs[0].results is None:
        print(
            json.dumps(
                {
                    "runner_failure": True,
                    "failure_code": _failure_code(logs[0]) if logs else "unexpected_log_count",
                },
                separators=(",", ":"),
            )
        )
        return 1
    results = logs[0].results
    accuracy_value = None
    for score in results.scores:
        metric = score.metrics.get("accuracy")
        if metric is not None:
            accuracy_value = metric.value
            break
    if results.total_samples != 1 or results.completed_samples != 1:
        raise RuntimeError("dynamic evaluation sample did not complete")
    print(
        json.dumps(
            {
                "framework": "inspect-ai",
                "framework_version": "0.3.262",
                "samples": 1,
                "completed": 1,
                "accuracy": accuracy_value,
                "stores_sample_transcripts": False,
                "uses_model_api_secret": False,
                "local_model_endpoint_execution": True,
                "real_model_execution": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
