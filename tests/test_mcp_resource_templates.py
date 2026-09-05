from __future__ import annotations

from mcp import types
from mcp.shared.exceptions import MCPError
from mcp.shared.uri_template import UriTemplate
import pytest

from agentops_guard.gateway.auth import GatewayIdentity
from agentops_guard.gateway import protocol


CURSOR_KEY = b"resource-template-test-key"
IDENTITY = GatewayIdentity(
    project_id="project-a",
    auth_kind="api_key",
    actor_id="agent-a",
    agent_id="agent-a",
    role=None,
)
TEMPLATES = [
    {
        "serverId": "catalog",
        "name": "record",
        "uriTemplate": "demo://records/{record_id}",
        "description": "Read one record",
        "riskScore": 0.0,
        "riskLabels": [],
        "provenance": {"trust": "untrusted"},
    },
    {
        "serverId": "catalog",
        "name": "article",
        "uriTemplate": "demo://articles/{slug}{?locale}",
        "description": "Read one article",
        "riskScore": 0.0,
        "riskLabels": [],
        "provenance": {"trust": "untrusted"},
    },
]


def test_protected_template_resolves_required_and_optional_values() -> None:
    protected_record = protocol._resource_template_reference(
        "project-a",
        "catalog",
        TEMPLATES[0]["uriTemplate"],
    )
    record_uri = UriTemplate.parse(protected_record).expand({"record_id": "customer/17"})
    source, upstream_uri = protocol._find_resource_template_source(
        "project-a",
        record_uri,
        TEMPLATES,
    )
    assert source is TEMPLATES[0]
    assert upstream_uri == "demo://records/customer%2F17"

    protected_article = protocol._resource_template_reference(
        "project-a",
        "catalog",
        TEMPLATES[1]["uriTemplate"],
    )
    default_uri = UriTemplate.parse(protected_article).expand({"slug": "release"})
    _, default_upstream = protocol._find_resource_template_source(
        "project-a",
        default_uri,
        TEMPLATES,
    )
    assert default_upstream == "demo://articles/release"

    localized_uri = UriTemplate.parse(protected_article).expand(
        {"slug": "release", "locale": "zh-CN"}
    )
    _, localized_upstream = protocol._find_resource_template_source(
        "project-a",
        localized_uri,
        TEMPLATES,
    )
    assert localized_upstream == "demo://articles/release?locale=zh-CN"


@pytest.mark.parametrize(
    ("uri_builder", "message"),
    [
        (lambda root: root, "Missing resource template parameter"),
        (
            lambda root: f"{root}?record_id=ok&extra=value",
            "Invalid protected resource URI",
        ),
        (
            lambda root: f"{root}?record_id=first&record_id=second",
            "Invalid protected resource URI",
        ),
        (
            lambda root: f"{root}?record_id={'x' * 8_192}",
            "Invalid protected resource URI",
        ),
    ],
)
def test_protected_template_rejects_noncanonical_requests(uri_builder, message) -> None:
    protected = protocol._resource_template_reference(
        "project-a",
        "catalog",
        TEMPLATES[0]["uriTemplate"],
    )
    root = protected.split("{", 1)[0]
    with pytest.raises(MCPError, match=message):
        protocol._find_resource_template_source(
            "project-a",
            uri_builder(root),
            TEMPLATES,
        )


@pytest.mark.parametrize(
    "template",
    [
        "demo://fixed",
        "demo://{record_id}/{record_id}",
        "demo://records/{" + ",".join(f"v{index}" for index in range(33)) + "}",
        "demo://records/" + "x" * 4_096 + "{record_id}",
    ],
)
def test_protected_template_rejects_unsupported_upstream_templates(
    template: str,
) -> None:
    with pytest.raises(MCPError, match="unsupported resource template"):
        protocol._resource_template_reference("project-a", "catalog", template)


@pytest.mark.anyio
async def test_standard_template_list_uses_pagination_and_protected_references(
    monkeypatch,
) -> None:
    monkeypatch.setattr(protocol, "_require_identity", lambda _scope: IDENTITY)

    async def call_gateway(handler_name: str, **_kwargs):
        assert handler_name == "resource_templates_list"
        return {"resourceTemplates": TEMPLATES}

    monkeypatch.setattr(protocol, "_call_gateway", call_gateway)
    first = await protocol._list_resource_templates(
        None,
        None,
        page_size=1,
        cursor_key=CURSOR_KEY,
    )
    assert len(first.resource_templates) == 1
    assert first.resource_templates[0].uri_template.startswith("agentops://resource-template/")
    assert first.next_cursor is not None

    second = await protocol._list_resource_templates(
        None,
        types.PaginatedRequestParams(cursor=first.next_cursor),
        page_size=1,
        cursor_key=CURSOR_KEY,
    )
    assert len(second.resource_templates) == 1
    assert second.next_cursor is None


@pytest.mark.anyio
async def test_standard_template_read_resolves_before_gateway_call(monkeypatch) -> None:
    monkeypatch.setattr(protocol, "_require_identity", lambda _scope: IDENTITY)
    protected = protocol._resource_template_reference(
        "project-a",
        "catalog",
        TEMPLATES[0]["uriTemplate"],
    )
    protected_uri = UriTemplate.parse(protected).expand({"record_id": "record-1"})
    calls: list[tuple[str, dict | None]] = []

    async def call_gateway(handler_name: str, **kwargs):
        calls.append((handler_name, kwargs.get("payload")))
        if handler_name == "resources_list":
            return {"resources": []}
        if handler_name == "resource_templates_list":
            return {"resourceTemplates": TEMPLATES}
        assert handler_name == "resources_read"
        assert kwargs["payload"] == {
            "serverId": "catalog",
            "uri": "demo://records/record-1",
        }
        return {
            "contents": [{"uri": "demo://records/record-1", "text": "record-1"}],
            "provenance": {"source": "mcp_resource", "trust": "untrusted"},
        }

    monkeypatch.setattr(protocol, "_call_gateway", call_gateway)
    result = await protocol._read_resource(
        None,
        types.ReadResourceRequestParams(uri=protected_uri),
    )

    assert result.contents[0].uri == protected_uri
    assert result.contents[0].text == "record-1"
    assert result.meta == {
        "io.agentops/provenance": {
            "source": "mcp_resource",
            "trust": "untrusted",
        }
    }
    assert [call[0] for call in calls] == [
        "resources_list",
        "resource_templates_list",
        "resources_read",
    ]
