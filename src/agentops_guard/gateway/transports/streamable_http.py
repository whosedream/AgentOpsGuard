from typing import Any

import httpx


class StreamableHttpTransport:
    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout

    def list_tools(self) -> list[dict[str, Any]]:
        response = httpx.get(f"{self.url}/tools/list", timeout=self.timeout)
        response.raise_for_status()
        return response.json().get("tools", [])

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = httpx.post(
            f"{self.url}/tools/call",
            json={"name": tool_name, "arguments": arguments},
            timeout=max(self.timeout, 30.0),
        )
        response.raise_for_status()
        return response.json()

