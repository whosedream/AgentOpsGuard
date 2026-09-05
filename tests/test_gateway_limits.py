import sys
import json
from pathlib import Path
import time

import httpx
import pytest

from agentops_guard.backend.models import McpServer
from agentops_guard.gateway import app as gateway_module
from agentops_guard.gateway.app import (
    _call_upstream_tool,
    _complete_upstream,
    _stdio_list_all,
)
from agentops_guard.gateway.transports.legacy_http import LegacyHttpTransport
from agentops_guard.gateway.transports.stdio import StdioTransport


def test_SPEC_P0_004_stdio_transport_returns_standardized_upstream_error_on_timeout(tmp_path: Path):
    server = tmp_path / "slow_mcp.py"
    server.write_text(
        """
import time

time.sleep(2)
""".strip(),
        encoding="utf-8",
    )
    started = time.monotonic()
    result = StdioTransport(sys.executable, [str(server)], timeout=0.05).call_tool("bad", {})
    elapsed = time.monotonic() - started
    assert result["isError"] is True
    assert "upstreamError" in result
    assert result["upstreamError"]["code"] in {"stdio_error", "timeout", "empty_response"}
    assert elapsed < 1


def test_stdio_transport_does_not_return_child_stderr(tmp_path: Path):
    canary = "secret-value-that-must-not-be-returned"
    server = tmp_path / "stderr_mcp.py"
    server.write_text(
        f"import sys\nsys.stderr.write({canary!r})\n",
        encoding="utf-8",
    )

    result = StdioTransport(sys.executable, [str(server)], timeout=1).call_tool("bad", {})

    assert result["isError"] is True
    assert canary not in json.dumps(result)


def test_http_transport_exception_message_is_not_returned(monkeypatch):
    canary = "secret-value-that-must-not-be-returned"

    def fail_call(*_args, **_kwargs):
        raise httpx.ConnectError(canary)

    monkeypatch.setattr(LegacyHttpTransport, "call_tool", fail_call)
    server = McpServer(
        id="safe-errors",
        project_id="default",
        name="safe-errors",
        transport="legacy_http",
        url="https://upstream.invalid",
    )

    result = _call_upstream_tool(server, "read", {})

    assert result["upstreamError"] == {"code": "http_error"}
    assert canary not in json.dumps(result)


def test_stdio_list_consumes_all_pages_without_exposing_cursor() -> None:
    class Manager:
        calls: list[tuple[str, dict[str, str]]]

        def __init__(self) -> None:
            self.calls = []

        def request(self, method: str, params: dict[str, str]):
            self.calls.append((method, params))
            if params == {}:
                return {
                    "result": {
                        "resources": [{"uri": "demo://one"}],
                        "nextCursor": "opaque-next",
                    }
                }
            return {"result": {"resources": [{"uri": "demo://two"}]}}

    manager = Manager()

    assert _stdio_list_all(
        manager,
        method="resources/list",
        result_key="resources",
    ) == [{"uri": "demo://one"}, {"uri": "demo://two"}]
    assert manager.calls == [
        ("resources/list", {}),
        ("resources/list", {"cursor": "opaque-next"}),
    ]


@pytest.mark.parametrize(
    "response",
    [
        {"error": {"code": -32000}},
        {"result": {"resources": "not-a-list"}},
        {"result": {"resources": [], "nextCursor": ""}},
    ],
)
def test_stdio_list_rejects_invalid_pages(response: dict) -> None:
    class Manager:
        def request(self, _method: str, _params: dict[str, str]):
            return response

    with pytest.raises(RuntimeError, match="MCP stdio"):
        _stdio_list_all(
            Manager(),
            method="resources/list",
            result_key="resources",
        )


def test_stdio_list_rejects_replayed_cursor() -> None:
    class Manager:
        def request(self, _method: str, _params: dict[str, str]):
            return {"result": {"resources": [], "nextCursor": "repeated"}}

    with pytest.raises(RuntimeError, match="pagination cursor"):
        _stdio_list_all(
            Manager(),
            method="resources/list",
            result_key="resources",
        )


def test_optional_stdio_resource_templates_treat_method_not_found_as_empty() -> None:
    class Manager:
        def request(self, _method: str, _params: dict[str, str]):
            return {"error": {"code": -32601, "message": "Method not found"}}

    assert (
        _stdio_list_all(
            Manager(),
            method="resources/templates/list",
            result_key="resourceTemplates",
            method_not_found_is_empty=True,
        )
        == []
    )


def test_stdio_completion_uses_standard_request_shape(monkeypatch) -> None:
    class Manager:
        def request(self, method: str, params: dict):
            assert method == "completion/complete"
            assert params == {
                "ref": {
                    "type": "ref/resource",
                    "uri": "demo://articles/{slug}{?locale}",
                },
                "argument": {"name": "locale", "value": "z"},
                "context": {"arguments": {"slug": "release"}},
            }
            return {"result": {"completion": {"values": ["zh-CN"]}}}

    monkeypatch.setattr(gateway_module, "get_stdio_manager", lambda *_args, **_kwargs: Manager())
    server = McpServer(
        id="completion-stdio",
        project_id="default",
        name="completion stdio",
        transport="stdio",
        command="unused",
        args=[],
    )

    result = _complete_upstream(
        server,
        ref_type="resource",
        ref_value="demo://articles/{slug}{?locale}",
        argument={"name": "locale", "value": "z"},
        context_arguments={"slug": "release"},
    )

    assert result == {"completion": {"values": ["zh-CN"]}}


def test_optional_stdio_completion_treats_method_not_found_as_empty(monkeypatch) -> None:
    class Manager:
        def request(self, _method: str, _params: dict):
            return {"error": {"code": -32601, "message": "Method not found"}}

    monkeypatch.setattr(gateway_module, "get_stdio_manager", lambda *_args, **_kwargs: Manager())
    server = McpServer(
        id="completion-stdio-empty",
        project_id="default",
        name="completion stdio empty",
        transport="stdio",
        command="unused",
        args=[],
    )

    result = _complete_upstream(
        server,
        ref_type="prompt",
        ref_value="greeting",
        argument={"name": "name", "value": "a"},
        context_arguments={},
    )

    assert result == {"completion": {"values": []}}
