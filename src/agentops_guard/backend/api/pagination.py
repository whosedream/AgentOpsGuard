from typing import Any

from agentops_guard.backend.schemas import PageOut


def page(items: list[Any], limit: int, offset: int, has_more: bool | None = None) -> PageOut:
    more = len(items) == limit if has_more is None else has_more
    next_cursor = str(offset + limit) if more else None
    return PageOut(items=items, next_cursor=next_cursor)
