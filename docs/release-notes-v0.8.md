# Release Notes: v0.8

## Highlights

- Hardened production runtime configuration and schema startup behavior.
- Enforced project-scoped authorization across core API and governance surfaces.
- Added SDK batching/retry, Gateway execution limits, and Prometheus-backed metrics.
- Introduced policy pack revisioning and provider-based scanner/plugin execution.
- Added Dashboard capability gating for governance and MCP actions.
- Shipped Compose smoke automation and Helm chart validation tooling.

## Operational Impact

- Production environments must provide explicit operator and API key configuration.
- Local SQLite bootstrap remains available only behind an explicit opt-in.
- Compose startup now depends on health-checked Redis/Postgres and migration completion.
- Helm validation can run via local Helm, downloaded Helm, or a configured Helm container image.

## Validation Summary

- Python full test suite passed.
- Dashboard unit tests, production build, and Playwright E2E passed.
- Compose build/up/smoke/down passed.
- Helm lint and template validation passed.
