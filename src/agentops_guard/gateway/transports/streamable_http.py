from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any

import anyio
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic import AnyUrl

from agentops_guard.backend.telemetry import inject_trace_headers


class StreamableHttpTransport:
    """Standards-compliant MCP Streamable HTTP client transport."""

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url = url
        self.timeout = timeout

    def list_tools(self) -> list[dict[str, Any]]:
        return anyio.run(self._list_tools)

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return anyio.run(self._call_tool, tool_name, arguments)

    def list_resources(self) -> list[dict[str, Any]]:
        return anyio.run(self._list_resources)

    def read_resource(self, uri: str) -> dict[str, Any]:
        return anyio.run(self._read_resource, uri)

    def list_prompts(self) -> list[dict[str, Any]]:
        return anyio.run(self._list_prompts)

    def get_prompt(self, name: str, arguments: dict[str, str]) -> dict[str, Any]:
        return anyio.run(self._get_prompt, name, arguments)

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[ClientSession]:
        timeout = httpx.Timeout(self.timeout)
        headers: dict[str, str] = {}
        inject_trace_headers(headers)
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, headers=headers
        ) as client:
            async with streamable_http_client(self.url, http_client=client) as (
                read_stream,
                write_stream,
                _,
            ):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(seconds=self.timeout),
                ) as session:
                    await session.initialize()
                    yield session

    async def _list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        async with self._session() as session:
            while True:
                result = await session.list_tools(cursor)
                tools.extend(_json_value(tool) for tool in result.tools)
                cursor = result.nextCursor
                if cursor is None:
                    return tools

    async def _call_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.call_tool(tool_name, arguments)
            return _json_value(result)

    async def _list_resources(self) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        cursor: str | None = None
        async with self._session() as session:
            while True:
                result = await session.list_resources(cursor)
                resources.extend(_json_value(resource) for resource in result.resources)
                cursor = result.nextCursor
                if cursor is None:
                    return resources

    async def _read_resource(self, uri: str) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.read_resource(AnyUrl(uri))
            return _json_value(result)

    async def _list_prompts(self) -> list[dict[str, Any]]:
        prompts: list[dict[str, Any]] = []
        cursor: str | None = None
        async with self._session() as session:
            while True:
                result = await session.list_prompts(cursor)
                prompts.extend(_json_value(prompt) for prompt in result.prompts)
                cursor = result.nextCursor
                if cursor is None:
                    return prompts

    async def _get_prompt(self, name: str, arguments: dict[str, str]) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.get_prompt(name, arguments)
            return _json_value(result)


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return value
