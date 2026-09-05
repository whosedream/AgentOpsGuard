from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest


ADAPTER = (
    Path(__file__).resolve().parents[1]
    / "evals"
    / "local-model-runtime"
    / "qwen_tool_adapter.py"
)


def _load_adapter(monkeypatch):
    monkeypatch.setenv("AGENTOPS_LOCAL_MODEL_UPSTREAM", "http://127.0.0.1:8080")
    spec = importlib.util.spec_from_file_location("qwen_tool_adapter_test", ADAPTER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_translates_qwen_tool_tags(monkeypatch):
    adapter = _load_adapter(monkeypatch)
    response = {
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": (
                        '<tool_call>{"name":"read_external",'
                        '"arguments":{"case_id":"benign-001"}}</tool_call>'
                    ),
                },
            }
        ]
    }

    translated = adapter.translate_tool_calls(response)

    choice = translated["choices"][0]
    assert choice["finish_reason"] == "tool_calls"
    assert choice["message"]["content"] is None
    call = choice["message"]["tool_calls"][0]
    assert call["function"]["name"] == "read_external"
    assert json.loads(call["function"]["arguments"]) == {"case_id": "benign-001"}


def test_rejects_non_object_tool_arguments(monkeypatch):
    adapter = _load_adapter(monkeypatch)
    response = {
        "choices": [
            {
                "message": {
                    "content": '<tool_call>{"name":"read_external","arguments":[]}</tool_call>'
                }
            }
        ]
    }

    with pytest.raises(ValueError, match="arguments must be an object"):
        adapter.translate_tool_calls(response)


def test_omitted_stream_field_is_non_streaming(monkeypatch):
    adapter = _load_adapter(monkeypatch)

    class Request:
        async def body(self):
            return b'{"model":"local","messages":[]}'

    monkeypatch.setattr(
        adapter,
        "_forward",
        lambda *_args: {"choices": [{"message": {"content": "done"}}]},
    )

    response = asyncio.run(adapter.chat_completions(Request()))

    assert response.status_code == 200
    assert adapter.METRICS["chat_requests"] == 1
