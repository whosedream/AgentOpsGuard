from typing import Any, Protocol


class GatewayTransport(Protocol):
    def list_tools(self) -> list[dict[str, Any]]:
        ...

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        ...

    def list_resources(self) -> list[dict[str, Any]]:
        ...

    def read_resource(self, uri: str) -> dict[str, Any]:
        ...

    def list_prompts(self) -> list[dict[str, Any]]:
        ...

    def get_prompt(self, name: str, arguments: dict[str, str]) -> dict[str, Any]:
        ...
