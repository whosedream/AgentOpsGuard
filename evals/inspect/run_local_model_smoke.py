from __future__ import annotations

import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from inspect_ai import eval
from inspect_ai.model import GenerateConfig, get_model

from agentops_guard_task import agentops_guard_gateway_eval


MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/-]{0,127}$")


class SafeRunnerError(RuntimeError):
    def __init__(self, code: str, details: dict[str, object] | None = None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


def _eval_failure_code(log) -> str:
    message = log.error.message.lower() if log.error is not None else ""
    for status in (400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504):
        if str(status) in message:
            return f"model_http_{status}"
    if ("tool" in message and "not found" in message) or "unknown tool" in message:
        return "tool_not_found"
    if "tool_call_id" in message or "tool call id" in message:
        return "tool_call_id_error"
    if ("tool_call" in message or "tool call" in message) and "argument" in message:
        return "tool_call_arguments_error"
    if ("tool_call" in message or "tool call" in message) and "validation" in message:
        return "tool_call_validation_error"
    if "tool_calls" in message or "tool call" in message:
        return "tool_call_protocol_error"
    if "mcp" in message:
        return "mcp_protocol_error"
    if "timeout" in message or "timed out" in message:
        return "evaluation_timeout"
    if "openai" in message or "modelapi" in message or "model api" in message:
        return "model_api_error"
    return "inspect_status_not_success"


def _sample_error_types(log) -> list[str]:
    error_types = []
    for sample in log.samples or []:
        if sample.error is None:
            continue
        matches = re.findall(
            r"(?m)^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception))(?::|$)",
            sample.error.traceback or "",
        )
        error_types.append(matches[-1] if matches else "unknown")
    return sorted(set(error_types))


def _global_error_types(log) -> list[str]:
    if log.error is None:
        return []
    matches = re.findall(
        r"(?m)^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception))(?::|$)",
        log.error.traceback or "",
    )
    return list(dict.fromkeys(matches))


def _local_model_settings() -> tuple[str, str]:
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
    return model_id, base_url.rstrip("/")


def _run() -> int:
    model_id, base_url = _local_model_settings()
    log_dir = Path(os.environ["AGENTOPS_EVAL_LOG_DIR"])
    log_dir.mkdir(parents=True, exist_ok=True)
    model = get_model(
        f"openai-api/local/{model_id}",
        base_url=base_url,
        api_key="local-no-secret",
        config=GenerateConfig(temperature=0, max_tokens=512),
        responses_api=False,
        stream=False,
        strict_tools=False,
        memoize=False,
    )
    logs = eval(
        agentops_guard_gateway_eval(),
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
    if len(logs) != 1:
        raise SafeRunnerError("unexpected_log_count")
    if logs[0].status != "success" or logs[0].results is None:
        raise SafeRunnerError(
            _eval_failure_code(logs[0]),
            {
                "sample_error_count": sum(
                    1 for sample in (logs[0].samples or []) if sample.error is not None
                ),
                "sample_error_types": _sample_error_types(logs[0]),
                "global_error_types": _global_error_types(logs[0]),
            },
        )
    results = logs[0].results
    accuracy_value = None
    for score in results.scores:
        metric = score.metrics.get("accuracy")
        if metric is not None:
            accuracy_value = metric.value
            break
    if results.total_samples != 2 or results.completed_samples != 2:
        raise SafeRunnerError("incomplete_samples")
    print(
        json.dumps(
            {
                "framework": "inspect-ai",
                "framework_version": "0.3.262",
                "driver": "real_local_model",
                "model_id": model_id,
                "samples": results.total_samples,
                "completed": results.completed_samples,
                "accuracy": accuracy_value,
                "stores_sample_transcripts": False,
                "uses_model_api_secret": False,
                "local_model_endpoint_execution": True,
                "real_model_execution": False,
                "real_model_quality_result": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


def main() -> int:
    try:
        return _run()
    except Exception as error:
        error_types = []
        current: BaseException | None = error
        while current is not None and len(error_types) < 5:
            error_types.append(f"{type(current).__module__}.{type(current).__name__}")
            current = current.__cause__ or current.__context__
        print(
            json.dumps(
                {
                    "runner_failure": True,
                    "failure_code": getattr(error, "code", "unexpected_exception"),
                    "failure_details": getattr(error, "details", {}),
                    "error_types": error_types,
                },
                separators=(",", ":"),
            )
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
