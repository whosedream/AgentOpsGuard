# MCP completion boundary v1

Date: 2026-09-04

## Outcome

The standard Gateway supports MCP `completion/complete` for prompt and resource-template arguments
on the current MCP Python SDK. It uses the official SDK request, reference, result, and client types;
AgentOps Guard adds authorization and content controls around that implementation rather than
maintaining a separate completion protocol.

## Security contract

- A client can request completion only with `mcp:read` and a project-bound protected prompt name or
  protected resource template returned by the Gateway. The Gateway resolves it against the current
  visible descriptor on every request. Removed, changed, quarantined, cross-project, restricted-Agent,
  raw upstream, and forged references fail before the completion handler is called.
- The requested argument and every context key must be declared by that prompt or resource template.
  There are at most 32 context arguments; names are at most 128 characters and values at most 512.
- Recognizable credential material and quarantinable instruction content in an argument or context
  value is rejected before it reaches the upstream. Errors contain a fixed message, not the value.
- An upstream may return at most 100 string suggestions of at most 512 characters each. Every value
  is treated as untrusted prompt or resource content and scanned. Credential-bearing and quarantined
  values are omitted, other redactions are preserved, and duplicates are removed. The Gateway
  reports the safe returned count instead of trusting the upstream count.
- Completion is advisory. A suggestion grants no tool permission, approval, or trusted provenance and
  cannot change deterministic action and target authorization.
- Stdio servers that explicitly report method-not-found and Streamable HTTP servers that do not
  advertise completion contribute an empty completion set. Other malformed results fail closed.

Prompt retrieval now applies the same current-advertisement, declared-argument, size, credential, and
instruction checks before calling the upstream. This closes the older compatibility route's ability
to name an unadvertised prompt directly.

## Verification

The real-process contract starts a real MCP v2 upstream, a real Gateway, and the official current MCP
client. It completes both a protected prompt and a protected resource template, passes declared
context, removes an instruction-injection suggestion, rejects an undeclared argument, and confirms
scope and Agent restrictions remain active. Separate transport and compatibility-route tests cover
the official Streamable HTTP client path, standard stdio request shape, optional method-not-found,
credential rejection before upstream, exact protected-reference mapping, unsafe-result filtering,
deduplication, and unadvertised prompt rejection.

## Boundary

This is current-SDK protocol and security-path evidence. It does not claim completion support for the
frozen MCP 1.x clients, production throughput, subscriptions, or durable task workflows. Those remain
separate release gates.

References:

- [Official MCP Python SDK server implementation](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/server/mcpserver/server.py)
- [Official MCP Python SDK client implementation](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/client.py)
