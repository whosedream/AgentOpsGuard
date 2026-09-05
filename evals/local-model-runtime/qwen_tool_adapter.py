"""Translate Qwen GGUF tool tags into OpenAI-compatible tool calls on loopback."""

from __future__ import annotations

import asyncio
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


TOOL_CALL_PATTERN = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.DOTALL)
TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")


def _fixed_upstream() -> str:
    upstream = os.environ["AGENTOPS_LOCAL_MODEL_UPSTREAM"]
    parsed = urlsplit(upstream)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("model adapter upstream must be credential-free loopback HTTP")
    return upstream.rstrip("/")


UPSTREAM = _fixed_upstream()
METRICS = {
    "chat_requests": 0,
    "translated_tool_calls": 0,
    "declared_tool_name_matches": 0,
    "undeclared_tool_names": 0,
    "translation_errors": 0,
}


def translate_tool_calls(response: dict[str, object]) -> dict[str, object]:
    choices = response.get("choices")
    if not isinstance(choices, list):
        raise ValueError("model response choices are invalid")
    for choice_index, choice in enumerate(choices):
        if not isinstance(choice, dict):
            raise ValueError("model response choice is invalid")
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, str) or "<tool_call>" not in content:
            continue
        matches = list(TOOL_CALL_PATTERN.finditer(content))
        if not matches:
            raise ValueError("model returned an incomplete tool call")
        tool_calls = []
        for call_index, match in enumerate(matches):
            call = json.loads(match.group(1))
            if not isinstance(call, dict):
                raise ValueError("model tool call must be an object")
            name = call.get("name")
            arguments = call.get("arguments")
            if not isinstance(name, str) or not TOOL_NAME_PATTERN.fullmatch(name):
                raise ValueError("model tool name is invalid")
            if not isinstance(arguments, dict):
                raise ValueError("model tool arguments must be an object")
            tool_calls.append(
                {
                    "id": f"call_qwen_{choice_index}_{call_index}",
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": json.dumps(arguments, separators=(",", ":")),
                    },
                }
            )
        remaining = TOOL_CALL_PATTERN.sub("", content).strip()
        message["content"] = remaining or None
        message["tool_calls"] = tool_calls
        choice["finish_reason"] = "tool_calls"
    return response


def _forward(method: str, path: str, body: bytes | None) -> dict[str, object]:
    request = UrlRequest(
        f"{UPSTREAM}{path}",
        data=body,
        method=method,
        headers={"content-type": "application/json"} if body is not None else {},
    )
    try:
        with urlopen(request, timeout=180) as upstream_response:  # noqa: S310
            return json.load(upstream_response)
    except (HTTPError, URLError, TimeoutError) as error:
        raise HTTPException(status_code=502, detail="local model request failed") from error


async def models(_request: Request) -> JSONResponse:
    response = await asyncio.to_thread(_forward, "GET", "/v1/models", None)
    return JSONResponse(response)


async def chat_completions(request: Request) -> JSONResponse:
    METRICS["chat_requests"] += 1
    body = await request.body()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=400, detail="request body must be JSON") from error
    if payload.get("stream", False) is not False:
        raise HTTPException(status_code=400, detail="streaming is not supported")
    response = await asyncio.to_thread(
        _forward,
        "POST",
        "/v1/chat/completions",
        json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    try:
        translated = translate_tool_calls(response)
    except (json.JSONDecodeError, ValueError) as error:
        METRICS["translation_errors"] += 1
        raise HTTPException(status_code=502, detail="local model tool call is invalid") from error
    declared_names = {
        tool["function"]["name"]
        for tool in payload.get("tools", [])
        if isinstance(tool, dict)
        and isinstance(tool.get("function"), dict)
        and isinstance(tool["function"].get("name"), str)
    }
    for choice in translated.get("choices", []):
        message = choice.get("message", {}) if isinstance(choice, dict) else {}
        for tool_call in message.get("tool_calls", []) if isinstance(message, dict) else []:
            METRICS["translated_tool_calls"] += 1
            name = tool_call["function"]["name"]
            if name in declared_names:
                METRICS["declared_tool_name_matches"] += 1
            else:
                METRICS["undeclared_tool_names"] += 1
    return JSONResponse(translated)


async def adapter_metrics(_request: Request) -> JSONResponse:
    return JSONResponse(METRICS)


app = Starlette(
    routes=[
        Route("/v1/models", models, methods=["GET"]),
        Route("/v1/chat/completions", chat_completions, methods=["POST"]),
        Route("/adapter-metrics", adapter_metrics, methods=["GET"]),
    ]
)
