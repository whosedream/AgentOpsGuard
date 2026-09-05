from __future__ import annotations

from mcp import types
from mcp.shared.exceptions import MCPError
import pytest
from pydantic import ValidationError

from agentops_guard.backend.config import Settings
from agentops_guard.gateway.auth import GatewayIdentity
from agentops_guard.gateway.protocol import _paginate


CURSOR_KEY = b"test-only-pagination-key"


def _identity(*, actor_id: str = "agent-a") -> GatewayIdentity:
    return GatewayIdentity(
        project_id="project-a",
        auth_kind="api_key",
        actor_id=actor_id,
        agent_id=actor_id,
        role=None,
    )


def test_cursor_pages_are_stable_and_bound_to_the_visible_snapshot() -> None:
    items = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
    first, cursor = _paginate(
        items,
        None,
        kind="tools",
        identity=_identity(),
        page_size=2,
        cursor_key=CURSOR_KEY,
    )

    assert first == items[:2]
    assert cursor is not None
    second, final_cursor = _paginate(
        items,
        types.PaginatedRequestParams(cursor=cursor),
        kind="tools",
        identity=_identity(),
        page_size=2,
        cursor_key=CURSOR_KEY,
    )
    assert second == items[2:]
    assert final_cursor is None

    prefix, body, signature = cursor.split(".")
    tampered_body = ("A" if body[0] != "A" else "B") + body[1:]
    with pytest.raises(MCPError, match="Invalid pagination cursor"):
        _paginate(
            items,
            types.PaginatedRequestParams(
                cursor=f"{prefix}.{tampered_body}.{signature}"
            ),
            kind="tools",
            identity=_identity(),
            page_size=2,
            cursor_key=CURSOR_KEY,
        )

    with pytest.raises(MCPError, match="Invalid pagination cursor"):
        _paginate(
            [*items, {"name": "d"}],
            types.PaginatedRequestParams(cursor=cursor),
            kind="tools",
            identity=_identity(),
            page_size=2,
            cursor_key=CURSOR_KEY,
        )


@pytest.mark.parametrize(
    ("kind", "identity", "cursor"),
    [
        ("resources", _identity(), None),
        ("tools", _identity(actor_id="agent-b"), None),
        ("tools", _identity(), "not-an-agentops-cursor"),
        ("tools", _identity(), "x" * 513),
        ("tools", _identity(), ""),
    ],
)
def test_cursor_rejects_wrong_scope_and_malformed_values(
    kind: str,
    identity: GatewayIdentity,
    cursor: str | None,
) -> None:
    items = (
        [{"uri": "agentops://resource/a"}, {"uri": "agentops://resource/b"}]
        if kind == "resources"
        else [{"name": "a"}, {"name": "b"}]
    )
    if cursor is None:
        _, cursor = _paginate(
            [{"name": "a"}, {"name": "b"}],
            None,
            kind="tools",
            identity=_identity(),
            page_size=1,
            cursor_key=CURSOR_KEY,
        )
    assert cursor is not None

    with pytest.raises(MCPError, match="Invalid pagination cursor"):
        _paginate(
            items,
            types.PaginatedRequestParams(cursor=cursor),
            kind=kind,
            identity=identity,
            page_size=1,
            cursor_key=CURSOR_KEY,
        )


def test_page_size_is_bounded_by_configuration() -> None:
    assert Settings(mcp_page_size=1).mcp_page_size == 1
    assert Settings(mcp_page_size=1_000).mcp_page_size == 1_000
    with pytest.raises(ValidationError):
        Settings(mcp_page_size=0)
    with pytest.raises(ValidationError):
        Settings(mcp_page_size=1_001)
