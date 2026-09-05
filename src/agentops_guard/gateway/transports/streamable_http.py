from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
import httpx2
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

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

    def list_resource_templates(self) -> list[dict[str, Any]]:
        return anyio.run(self._list_resource_templates)

    def read_resource(self, uri: str) -> dict[str, Any]:
        return anyio.run(self._read_resource, uri)

    def list_prompts(self) -> list[dict[str, Any]]:
        return anyio.run(self._list_prompts)

    def get_prompt(self, name: str, arguments: dict[str, str]) -> dict[str, Any]:
        return anyio.run(self._get_prompt, name, arguments)

    def complete(
        self,
        ref_type: str,
        ref_value: str,
        argument: dict[str, str],
        context_arguments: dict[str, str],
    ) -> dict[str, Any]:
        return anyio.run(
            self._complete,
            ref_type,
            ref_value,
            argument,
            context_arguments,
        )

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[Client]:
        timeout = httpx2.Timeout(self.timeout)
        headers: dict[str, str] = {}
        inject_trace_headers(headers)
        async with httpx2.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers=headers,
            trust_env=False,
        ) as client:
            transport = streamable_http_client(self.url, http_client=client)
            async with Client(
                transport,
                read_timeout_seconds=self.timeout,
            ) as session:
                yield session

    async def _list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        async with self._session() as session:
            while True:
                result = await session.list_tools(cursor=cursor)
                tools.extend(_json_value(tool) for tool in result.tools)
                cursor = result.next_cursor
                if cursor is None:
                    return tools

    async def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.call_tool(tool_name, arguments)
            return _json_value(result)

    async def _list_resources(self) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        cursor: str | None = None
        async with self._session() as session:
            while True:
                result = await session.list_resources(cursor=cursor)
                resources.extend(_json_value(resource) for resource in result.resources)
                cursor = result.next_cursor
                if cursor is None:
                    return resources

    async def _read_resource(self, uri: str) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.read_resource(uri)
            return _json_value(result)

    async def _list_resource_templates(self) -> list[dict[str, Any]]:
        templates: list[dict[str, Any]] = []
        cursor: str | None = None
        try:
            async with self._session() as session:
                if session.server_capabilities.resources is None:
                    return []
                while True:
                    result = await session.list_resource_templates(cursor=cursor)
                    templates.extend(
                        _json_value(template) for template in result.resource_templates
                    )
                    cursor = result.next_cursor
                    if cursor is None:
                        return templates
        except MCPError as exc:
            if exc.error.code == -32601:
                return []
            raise

    async def _list_prompts(self) -> list[dict[str, Any]]:
        prompts: list[dict[str, Any]] = []
        cursor: str | None = None
        async with self._session() as session:
            while True:
                result = await session.list_prompts(cursor=cursor)
                prompts.extend(_json_value(prompt) for prompt in result.prompts)
                cursor = result.next_cursor
                if cursor is None:
                    return prompts

    async def _get_prompt(self, name: str, arguments: dict[str, str]) -> dict[str, Any]:
        async with self._session() as session:
            result = await session.get_prompt(name, arguments)
            return _json_value(result)

    async def _complete(
        self,
        ref_type: str,
        ref_value: str,
        argument: dict[str, str],
        context_arguments: dict[str, str],
    ) -> dict[str, Any]:
        try:
            async with self._session() as session:
                if session.server_capabilities.completions is None:
                    return {"completion": {"values": []}}
                ref: types.ResourceTemplateReference | types.PromptReference
                if ref_type == "resource":
                    ref = types.ResourceTemplateReference(uri=ref_value)
                elif ref_type == "prompt":
                    ref = types.PromptReference(name=ref_value)
                else:
                    raise ValueError("unsupported MCP completion reference")
                result = await session.complete(
                    ref,
                    argument,
                    context_arguments or None,
                )
                return _json_value(result)
        except MCPError as exc:
            if exc.error.code == -32601:
                return {"completion": {"values": []}}
            raise


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return value
