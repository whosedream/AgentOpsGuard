# AgentOps Guard Dashboard Control Center Spec

This file is the product spec source for the TDD + SDD GUI implementation. Every acceptance scenario has a stable ID and must be referenced by tests.

## Global Assumptions

- API authentication uses `X-AgentOps-Api-Key` with the default development key `dev-agentops-key`.
- The Dashboard talks to the backend API at `NEXT_PUBLIC_AGENTOPS_API_URL` and to the Gateway at `NEXT_PUBLIC_AGENTOPS_GATEWAY_URL`.
- Empty, loading, and error states must be visible without crashing the page.
- The UI is an operations console, not a replacement for SDK code instrumentation.

## Setup

- `SPEC-SETUP-001`: Setup page shows API status, database status, and object counts from `/v1/system/status`.
- `SPEC-SETUP-002`: Setup page shows Gateway status by calling `/mcp/tools/list`.
- `SPEC-SETUP-003`: If either API or Gateway fails, the page shows an actionable error message.

## Overview

- `SPEC-OVERVIEW-001`: Overview shows run count, success rate, cost, high-risk count, API health, recent risks, and quick links.
- `SPEC-OVERVIEW-002`: Overview handles zero runs without layout breakage.

## Runs and Replay

- `SPEC-RUN-001`: Runs page supports URL-driven filters for status, risk label, and agent text; refresh preserves filters and the API receives matching query parameters.
- `SPEC-RUN-002`: Run detail shows a DAG view and event inspector; selecting an event shows metadata, risk, input/output refs, and allows loading redacted content for each ref.
- `SPEC-RUN-003`: Runs page paginates with `page_mode=envelope`, shows loading/empty/error states, and exposes a Next page action when `next_cursor` is present.
- `SPEC-RUN-004`: Run detail handles loading/error/empty event states and keeps replay creation visible beside the inspector.
- `SPEC-REPLAY-001`: Run detail can create a replay for the selected run and show the replay result.
- `SPEC-REPLAY-002`: Replay Studio can list runs, create a replay, list replay history, and show failure suggestions.

## Risks

- `SPEC-RISK-001`: Risks page supports URL-driven severity filtering, displays evidence spans, and paginates through envelope responses.
- `SPEC-RISK-002`: Each risk event links back to its related run when a run is present.

## Scanner Playground

- `SPEC-SCAN-001`: User can paste untrusted content, submit it to `/v1/scanner/scan`, and see risk labels, score, severity, evidence, and sanitized output.
- `SPEC-SCAN-002`: Scanner Playground shows validation or API errors without losing the input text.

## Policy Playground

- `SPEC-POLICY-001`: User can submit actor/tool/command/risk labels to `/v1/policies/evaluate` and see action, reason code, severity, matched policy, and remediation.
- `SPEC-POLICY-002`: Dangerous shell command `rm -rf /` returns `deny` and `dangerous_command`.

## Eval Studio

- `SPEC-EVAL-001`: User can create an eval suite from JSON cases.
- `SPEC-EVAL-002`: User can run an eval suite from the UI and see pass/fail counts and case failures.
- `SPEC-EVAL-003`: Eval Studio lists historical eval runs filtered by suite.

## MCP Manager

- `SPEC-MCP-001`: User can create, edit, and delete MCP server registry entries.
- `SPEC-MCP-002`: User can refresh tools from Gateway and see active/quarantined risk state.
- `SPEC-MCP-003`: User can test a tool call and see policy decision, risk, and output.
- `SPEC-MCP-004`: User can quarantine or restore an MCP server, see server health/status, keep cached tools visible after refresh failure, and inspect tool risk labels plus upstream/job errors.

## Acceptance Gate

- Backend: `uv run ruff check .` and `uv run pytest --cov=agentops_guard --cov-fail-under=80` pass.
- Frontend: `npm run test`, `npm run test:e2e`, and `npm run build` pass from `dashboard`.
- Manual smoke: Docker stack starts, Dashboard can complete Scanner, Policy, Replay, Eval, and MCP flows.
