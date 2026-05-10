# Changelog

## v0.8

### Engineering Hardening

- Added explicit runtime environment guards for production configuration, operator bootstrap, and local SQLite schema bootstrap.
- Tightened project-scoped access control across run, risk, replay, eval, MCP, audit, and governance routes.
- Reworked startup schema handling so production paths validate Alembic head instead of mutating schema at runtime.

### Gateway and SDK Reliability

- Added stdio gateway limits for timeout, response size, stderr capture, and standardized upstream error payloads.
- Added SDK event batching, retry, background flushing, and explicit `flush()` / `close()` behavior with non-blocking telemetry defaults.
- Added provider-based scanner execution with plugin loading support through `AGENTOPS_SCANNER_PLUGINS`.

### Governance and Dashboard

- Added `/v1/auth/context` and Dashboard capability gating for governance and MCP controls.
- Added policy pack revision creation without in-place rule mutation and introduced policy pack family tracking.
- Added SDD + TDD phase specs and contract tests for P0, P1, and P2 engineering milestones.

### Operations and Delivery

- Switched `/metrics` to Prometheus client-backed metrics.
- Added Compose smoke automation and real compose health-check-based startup validation.
- Added Helm chart assets, static validation, and real `helm lint` / `helm template` validation through `scripts/helm_template_check.ps1`.
- Added deployment and release guidance for Compose, Helm, smoke, and Helm-image override behavior.

## v0.7

### Governance Control Plane

- Added project configuration, approvals, policy packs, scanner rules, and run suppressions.
- Added Dashboard governance entry points for project status, policy/scanner controls, and approval workflows.
- Preserved v1 API compatibility with additive control-plane endpoints.

### Operations Hardening

- Added JSON request logs with request id, method, path, status, duration, and optional project id.
- Extended `/readyz` with Alembic migration status and strict mismatch failures outside local SQLite bootstrap.
- Expanded `/metrics` with governance, MCP, and job status gauges using low-cardinality labels.
- Updated release checks for migration gate, metrics smoke, structured logs, and API contract review.

### Dashboard Productization

- Added URL-driven Runs and Risks filters with envelope pagination.
- Added Run Detail DAG/event inspector with content reference loading.
- Added MCP Manager server status display, quarantine/restore actions, cached tool risk labels, refresh job output, and retryable errors.
- Hardened Dashboard BFF proxy query-string forwarding for filtered, paginated, and project-scoped requests.
- Added Playwright control-center E2E coverage to CI for setup, scanner, policy, replay, eval, MCP, and risks flows.

### MCP Gateway and Registry

- Documented MCP server status contract: `active`, `quarantined`, `disabled`, and `error`.
- Refresh failures now preserve cached tools and mark the affected server `error`.
- Successful refresh no longer overrides manual `quarantined` or `disabled` server states.

### Documentation

- Added SDK quickstart and common error guidance.
- Added MCP Gateway registration, refresh, policy guard, and troubleshooting guide.
