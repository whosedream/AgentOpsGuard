# MCP resource template boundary v1

Date: 2026-09-04

## Outcome

The standard Gateway supports MCP `resources/templates/list` and reading the concrete URI produced
from a listed template. It directly reuses the official MCP Python SDK `ResourceTemplate` types and
its bounded RFC 6570 `UriTemplate` parser, matcher, and expander. AgentOps Guard does not maintain a
second URI-template implementation.

## Protected reference contract

- The Gateway scans each upstream template descriptor as untrusted MCP resource metadata. A
  quarantined, malformed, credential-bearing, zero-variable, duplicate-variable, over-4,096-character,
  or over-32-variable template is not advertised.
- A standard client receives an `agentops://resource-template/<digest>{?...}` template. The digest
  binds the project, upstream server, and exact upstream template. The upstream scheme, host, path,
  and literal identifiers are not exposed in that reference.
- The protected template contains only the variable names needed by the client. When a client reads
  an expanded reference, the Gateway matches it against the current visible template, rejects
  unknown, duplicate, reordered, missing-required, non-canonical, or oversized parameters, and uses
  the official SDK to expand the original upstream template.
- The expanded upstream URI is accepted only if the same server still advertises that concrete URI
  or matching safe template. This check also applies to the older HTTP compatibility endpoint, so a
  caller cannot select an arbitrary unadvertised resource on an MCP server.
- Recognizable credential material in a listed or requested URI is rejected before the read request
  reaches the upstream. The rejection contains no URI or matched value.
- `allowed_agents` applies consistently to tool, fixed-resource, resource-template, and prompt
  discovery, plus resource reads and prompt retrieval. A disallowed Agent receives no descriptor and
  cannot use a previously learned resource or prompt reference as an oracle.

Template lists use the same identity- and snapshot-bound pagination contract as tools, fixed
resources, and prompts. An upstream stdio list is also consumed page by page with a 1,000-page cap,
512-character cursor limit, replay detection, and fail-closed response validation. An older stdio
server that explicitly returns MCP method-not-found for this optional list contributes no templates
instead of breaking other discovery.

## Verification

The real-process test uses the official current MCP client, a real Gateway process, and a real
`MCPServer` upstream. With a Gateway page size of one it retrieves two template pages, hides both
upstream templates behind protected references, expands path and optional query values, and reads the
expected upstream resource. It rejects missing and extra parameters, cross-list and cross-identity
cursors, unadvertised direct URIs, restricted-Agent access, unsafe descriptors, malformed stdio
pages, and repeated stdio cursors.

Completion suggestions for the current SDK are covered separately by `specs/mcp-completion-v1.md`.
This does not claim support for subscriptions or task-based long-running resource reads. Those
capabilities remain separate and must be advertised only after their own authorization, durability,
and multi-replica tests pass.

References:

- [Official MCP Python SDK resource documentation](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/servers/resources.md)
- [Official bounded URI-template implementation](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/shared/uri_template.py)
