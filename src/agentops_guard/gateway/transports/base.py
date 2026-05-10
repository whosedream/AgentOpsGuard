from typing import Any, Protocol


class GatewayTransport(Protocol):
    def list_tools(self) -> list[dict[str, Any]]:
        ...

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        ...

