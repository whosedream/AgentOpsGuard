# PR Draft: v0.8 Engineering Hardening

## Title

`feat: implement v0.8 engineering hardening across runtime sdk gateway dashboard and helm`

## Summary

This PR hardens AgentOps Guard across runtime safety, governance workflows, SDK reliability, deployment packaging, and validation tooling.

### Runtime Hardening

- Added explicit environment guards for production configuration, operator bootstrap, and local SQLite schema bootstrap.
- Enforced project-scoped authorization across runs, risks, jobs, replays, evals, MCP registry, audit, and governance routes.
- Switched production startup behavior to validate Alembic head instead of mutating schema at runtime.

### Reliability

- Added SDK event batching, retry, background flushing, and explicit `flush()` / `close()` behavior.
- Added Gateway stdio limits for timeout, response size, stderr capture, and standardized upstream error payloads.
- Switched `/metrics` to Prometheus client-backed metrics.

### Governance

- Added `/v1/auth/context` and Dashboard capability gating for governance and MCP actions.
- Added policy pack family tracking and revision creation without in-place rule mutation.
- Added provider-based scanner execution and plugin loading through `AGENTOPS_SCANNER_PLUGINS`.

### Delivery

- Added Compose smoke automation and validated the stack with health-check-based startup ordering.
- Added Helm chart assets, Helm lint/template helpers, and release/deployment documentation updates.
- Added SDD + TDD phase specs and regression coverage for P0, P1, and P2 milestones.

## Validation

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

## Notes

- Remote push and PR creation are intentionally not included because no `origin` remote is configured locally.
- Helm validation supports three execution paths:
  - system `helm`
  - `%TEMP%\helm-v3.18.4\windows-amd64\helm.exe`
  - `AGENTOPS_HELM_IMAGE`
