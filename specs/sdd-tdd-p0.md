# SDD + TDD: P0 Engineering Boundary Hardening

## Intent

P0 closes the current runtime boundary gaps without introducing a new tenancy or identity model.
The system remains single-team and project-scoped, but production startup, request authorization,
resource ownership, and MCP gateway execution limits must become explicit and testable.

## Constraints

- Production startup must not mutate schema.
- Local SQLite bootstrap may remain available for developer ergonomics, but only behind an explicit opt-in.
- Existing `/v1` contracts should remain broadly compatible unless a stricter failure is required for safety.
- Dashboard continues to use a server-side BFF and API key scopes; no browser-side secret handling is added.

## Behavior

### Schema lifecycle

- `alembic upgrade head` is the only supported production schema driver.
- API, Gateway, and Worker startup must fail in production when schema is missing or behind Alembic head.
- Local SQLite may skip Alembic only when both of the following are true:
  - `AGENTOPS_ENV=dev`
  - `AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP=true`

### Production configuration guards

- `AGENTOPS_ENV` accepts `dev`, `test`, or `prod`.
- `prod` rejects:
  - default `dev-agentops-key`
  - wildcard CORS origins
  - schema bootstrap opt-in
- Production governance/bootstrap operations require an explicit operator key.

### Project isolation

- Database API keys are bound to a single `project_id`.
- Scope grants operation class permission only; it does not grant cross-project access.
- Any resource read/write by id must validate resource ownership before returning or mutating.
- Cross-project access should not leak resource existence. Use `404` for resource-by-id access.

### Gateway limits

- Gateway transport limits are configuration-driven:
  - startup timeout
  - call timeout
  - max response bytes
  - max stderr bytes
  - per-server concurrency
- Upstream failures and limit breaches return a stable JSON shape:
  - `isError`
  - `policyDecision`
  - `risk`
  - `upstreamError`

## Acceptance IDs

- `SPEC-P0-001`: prod startup rejects implicit schema bootstrap.
- `SPEC-P0-002`: prod config rejects default dev key and wildcard CORS.
- `SPEC-P0-003`: project-scoped keys cannot read or mutate another project's resources.
- `SPEC-P0-004`: gateway stdio/http failures and limit breaches return standardized error payloads.
