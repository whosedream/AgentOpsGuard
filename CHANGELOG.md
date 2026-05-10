# Changelog

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
