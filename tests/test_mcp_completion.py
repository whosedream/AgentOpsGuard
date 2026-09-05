from __future__ import annotations

from mcp import types
from mcp.shared.exceptions import MCPError
import pytest

from agentops_guard.gateway import protocol
from agentops_guard.gateway.auth import GatewayIdentity


IDENTITY = GatewayIdentity(
    project_id="project-a",
    auth_kind="api_key",
    actor_id="agent-a",
    agent_id="agent-a",
    role=None,
)


@pytest.mark.anyio
async def test_standard_prompt_completion_resolves_protected_name(monkeypatch) -> None:
    prompt = {
        "serverId": "catalog",
        "name": "greeting",
        "arguments": [{"name": "name"}],
    }
    protected_name = protocol._stable_name(
        "prompt",
        IDENTITY.project_id,
        prompt["serverId"],
        prompt["name"],
    )
    calls: list[tuple[str, dict | None]] = []
    monkeypatch.setattr(protocol, "_require_identity", lambda _scope: IDENTITY)

    async def call_gateway(handler_name: str, **kwargs):
        calls.append((handler_name, kwargs.get("payload")))
        if handler_name == "prompts_list":
            return {"prompts": [prompt]}
        return {
            "completion": {
                "values": ["AgentOps"],
                "total": 1,
                "hasMore": False,
            }
        }

    monkeypatch.setattr(protocol, "_call_gateway", call_gateway)
    result = await protocol._complete(
        None,
        types.CompleteRequestParams(
            ref=types.PromptReference(name=protected_name),
            argument=types.CompletionArgument(name="name", value="Agent"),
        ),
    )

    assert result.completion.values == ["AgentOps"]
    assert calls == [
        ("prompts_list", None),
        (
            "completion_complete",
            {
                "serverId": "catalog",
                "refType": "prompt",
                "refValue": "greeting",
                "argument": {"name": "name", "value": "Agent"},
                "context": {},
            },
        ),
    ]


@pytest.mark.anyio
async def test_standard_resource_completion_resolves_exact_protected_template(
    monkeypatch,
) -> None:
    template = {
        "serverId": "catalog",
        "name": "article",
        "uriTemplate": "demo://articles/{slug}{?locale}",
    }
    protected_template = protocol._resource_template_reference(
        IDENTITY.project_id,
        template["serverId"],
        template["uriTemplate"],
    )
    monkeypatch.setattr(protocol, "_require_identity", lambda _scope: IDENTITY)

    async def call_gateway(handler_name: str, **kwargs):
        if handler_name == "resource_templates_list":
            return {"resourceTemplates": [template]}
        assert handler_name == "completion_complete"
        assert kwargs["payload"] == {
            "serverId": "catalog",
            "refType": "resource",
            "refValue": "demo://articles/{slug}{?locale}",
            "argument": {"name": "locale", "value": "z"},
            "context": {"slug": "release"},
        }
        return {"completion": {"values": ["zh-CN"]}}

    monkeypatch.setattr(protocol, "_call_gateway", call_gateway)
    result = await protocol._complete(
        None,
        types.CompleteRequestParams(
            ref=types.ResourceTemplateReference(uri=protected_template),
            argument=types.CompletionArgument(name="locale", value="z"),
            context=types.CompletionContext(arguments={"slug": "release"}),
        ),
    )

    assert result.completion.values == ["zh-CN"]


def test_resource_completion_rejects_forged_protected_template() -> None:
    template = {
        "serverId": "catalog",
        "uriTemplate": "demo://records/{record_id}",
    }
    protected = protocol._resource_template_reference(
        IDENTITY.project_id,
        template["serverId"],
        template["uriTemplate"],
    )

    with pytest.raises(MCPError, match="resource template not found"):
        protocol._find_resource_template_definition_source(
            "other-project",
            protected,
            [template],
        )
