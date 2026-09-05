from typing import Any

import httpx


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
        with httpx.Client(
            timeout=max(self.timeout, 30.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = client.post(
                f"{self.url}/tools/call",
                json={"name": tool_name, "arguments": arguments},
            )
            response.raise_for_status()
            return response.json()
