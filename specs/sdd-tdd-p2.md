# SDD + TDD: P2 Versioning, Extensibility, and Delivery

## Intent

P2 productizes the governance plane around immutable policy revisions, pluggable scanners,
scope-driven Dashboard capability gating, and a deployable Helm package for application components.

## Behavior

### Policy revisioning

- `PolicyPack` remains the public object, but rule changes create a new revision instead of mutating the active one in place.
- Existing list/create behavior stays compatible.
- A new version creation path must support rollback by reactivating an older revision.

### Scanner providers

- Built-in regex rules and database custom rules execute through a common provider interface.
- Additional providers may be loaded from `AGENTOPS_SCANNER_PLUGINS`.
- Provider failures must be isolated and must not break the full scan pipeline.

### Dashboard capability gating

- Dashboard reads `/v1/auth/context`.
- Governance and MCP controls render disabled or hidden when scopes are insufficient.
- The browser does not receive secrets; gating is capability-based only.

### Helm

- A Helm chart must exist for API, Gateway, Worker, Dashboard, and migration job.
- Postgres and Redis are external dependencies configured via values.

## Acceptance IDs

- `SPEC-P2-001`: policy pack revisions can be created without mutating the existing revision.
- `SPEC-P2-002`: scanner plugin loading tolerates provider failure and still returns built-in findings.
- `SPEC-P2-003`: Dashboard capability helpers map auth context to governance and MCP permissions.
- `SPEC-P2-004`: Helm chart assets exist with values for local-like, staging, and prod.
