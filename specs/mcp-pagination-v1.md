# MCP pagination v1

Date: 2026-09-04

## Outcome

The standard Streamable HTTP endpoint paginates tool, fixed-resource, resource-template, and prompt lists with the official
MCP `cursor` and `nextCursor` fields. The implementation is stateless and uses the official MCP
Python SDK request and result types; it does not add a private pagination protocol.

## Cursor contract

- The server chooses a page size from `AGENTOPS_MCP_PAGE_SIZE`; the accepted range is 1 to 1,000 and
  the default is 100.
- The client treats the cursor as opaque. The encoded token contains only a version, list kind,
  offset, and SHA-256 digests. It contains no credential, raw project or actor identifier, upstream
  server identifier, tool arguments, prompt text, resource address, or model content.
- The Gateway authenticates the cursor with HMAC-SHA-256 using a domain-separated key derived inside
  the trusted process from its existing API credential. The credential itself is never encoded in a
  cursor. Changing an offset, digest, list kind, or signature therefore fails before the payload is
  accepted; rotating the Gateway credential intentionally invalidates outstanding cursors.
- The scope digest binds the cursor to the authenticated project, actor, Agent, and list kind. A
  cursor from another identity or another list returns MCP invalid params (`-32602`).
- The snapshot digest covers the ordered stable identifiers of every currently visible item. An
  added, removed, or renamed visible item invalidates an older cursor instead of silently skipping
  or duplicating entries. Dynamic scan and content-reference metadata does not invalidate an
  otherwise stable page traversal.
- Tokens are bounded to 512 UTF-8 bytes, use one canonical base64url/JSON representation, reject
  duplicate or unexpected fields, and require an offset that points to an existing next item.

This is cursor validation, not an authorization shortcut. Every page rebuilds the authenticated
identity and calls the same project-filtered Gateway list path before a cursor is accepted.

## Verification

The real-process contract test sets the page size to one and uses the official MCP client to fetch
two pages each of tools, fixed resources, resource templates, and prompts through the real Gateway and a real MCP v2 upstream.
It also verifies malformed, cross-list, and cross-identity cursor rejection. Unit tests cover final
page behavior, authenticated-payload tampering, snapshot drift, length bounds, empty tokens, and
configuration bounds.

## Remaining MCP scope

Resource templates now use this pagination contract and have a separate protected-reference contract.
Subscriptions and experimental task-based workflows remain explicit follow-up work. Completion is
not paginated and has its own bounded contract in `specs/mcp-completion-v1.md`.

Reference: [MCP pagination specification](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination).
