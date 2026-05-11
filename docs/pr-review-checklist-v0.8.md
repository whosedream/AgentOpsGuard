# PR Review Checklist: v0.8 Engineering Hardening

## Reviewer Focus

- Runtime guards:
  - Production rejects default dev key and wildcard CORS.
  - Startup schema behavior no longer mutates production databases.
- Project isolation:
  - Project-scoped keys cannot cross-read or cross-mutate resources.
  - Governance, MCP, runs, risks, replay, eval, jobs, and audit paths all enforce project ownership.
- Reliability:
  - SDK batching and retry keep telemetry non-blocking by default.
  - Gateway stdio and upstream error handling return stable error payloads.
  - Metrics are Prometheus-backed and keep low-cardinality labels.
- Governance:
  - Policy pack revisioning does not mutate active rules in place.
  - Scanner provider/plugin flow preserves built-in scanning if plugin loading fails.
  - Dashboard capability gating disables governance and MCP actions without the required scopes.
- Delivery:
  - Compose health ordering is explicit and smoke has been run.
  - Helm chart lints and templates successfully.

## Validation Confirmed

- `uv run pytest -q`
- `uv run ruff check src tests scripts`
- `node .\node_modules\vitest\vitest.mjs run`
- `node .\node_modules\next\dist\bin\next build`
- `node .\node_modules\@playwright\test\cli.js test`
- `docker compose build`
- `docker compose up -d`
- `uv run python scripts/compose_smoke.py`
- `docker compose down`
- `powershell -ExecutionPolicy Bypass -File scripts\helm_template_check.ps1`
- `uv run python scripts/helm_template_check.py`
