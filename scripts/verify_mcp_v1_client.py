from __future__ import annotations

import anyio
from datetime import timedelta
from importlib.metadata import version
import json
import os
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client import streamable_http


async def _run_session(transport: Any, package_version: str) -> dict[str, object]:
    async with transport as (read_stream, write_stream, _session_id):
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=5),
        ) as client:
            initialized = await client.initialize()
            tools = await client.list_tools()
            if len(tools.tools) != 1:
                raise RuntimeError("MCP 1.x client received an unexpected tool list")
            called = await client.call_tool(
                tools.tools[0].name,
                {"text": "v1-client"},
            )
            if called.isError:
                raise RuntimeError("MCP 1.x tool call failed")
            return {
                "client_package": package_version,
                "protocol_version": initialized.protocolVersion,
                "tool_count": len(tools.tools),
                "tool_call_succeeded": True,
            }


async def _verify() -> dict[str, object]:
    package_version = version("mcp")
    if not package_version.startswith("1."):
        raise RuntimeError("This verification requires an MCP 1.x client package")
    url = os.environ["AGENTOPS_TEST_MCP_URL"]
    token = os.environ["AGENTOPS_TEST_MCP_TOKEN"]
    transport_factory = getattr(streamable_http, "streamable_http_client", None)
    if transport_factory is None:
        legacy_factory = getattr(streamable_http, "streamablehttp_client")
        return await _run_session(
            legacy_factory(
                url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
                sse_read_timeout=5,
            ),
            package_version,
        )
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
        follow_redirects=False,
        trust_env=False,
    ) as http_client:
        return await _run_session(
            transport_factory(url, http_client=http_client),
            package_version,
        )


def main() -> None:
    print(json.dumps(anyio.run(_verify), separators=(",", ":")))


if __name__ == "__main__":
    main()
