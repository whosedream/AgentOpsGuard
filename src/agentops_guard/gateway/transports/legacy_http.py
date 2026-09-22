from typing import Any

import anyio
import httpx

from agentops_guard.gateway.transports.errors import UpstreamTransportError


class LegacyHttpTransport:
    """Compatibility transport for the pre-MCP AgentOps HTTP contract."""

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout

    def list_tools(self) -> list[dict[str, Any]]:
        with httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = client.get(f"{self.url}/tools/list")
            response.raise_for_status()
            return response.json().get("tools", [])

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            return anyio.run(self._call_tool, tool_name, arguments)
        except (TimeoutError, httpx.TimeoutException):
            raise UpstreamTransportError("timeout") from None
        except httpx.HTTPError:
            raise UpstreamTransportError("http_error") from None

    async def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        with anyio.fail_after(self.timeout):
            return await self._post_tool(tool_name, arguments)

    async def _post_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(
                f"{self.url}/tools/call",
                json={"name": tool_name, "arguments": arguments},
            )
            response.raise_for_status()
            return response.json()
