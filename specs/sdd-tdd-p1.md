# SDD + TDD: P1 Reliability, Metrics, and Smoke

## Intent

P1 improves runtime reliability and operability without changing the project-scoped identity model.
The main additions are a non-blocking SDK exporter, complete audit coverage, Prometheus-native metrics,
and an executable compose smoke runner.

## Behavior

### SDK exporter

- Trace and event export may be buffered and retried in the background.
- Default mode is non-blocking telemetry:
  - queue overflows do not break application code
  - transient export failures are retried
  - `flush()` and `close()` force draining
- Policy and scanner calls remain synchronous.

### Metrics

- `/metrics` must be produced by a Prometheus client registry rather than ad hoc in-memory counters.
- Request counters and latency histograms remain keyed by method/path/status only.
- Governance, job, scanner, and MCP status metrics remain low-cardinality.

### Compose smoke

- A smoke script must verify:
  - `/readyz`
  - `/metrics`
  - gateway tools list or call
  - at least one replay/eval or MCP refresh job path
  - dashboard setup page reachability

## Acceptance IDs

- `SPEC-P1-001`: SDK exporter retries and flushes buffered events without breaking the caller by default.
- `SPEC-P1-002`: `/metrics` exposes Prometheus text with request, policy, scanner, MCP, and job families.
- `SPEC-P1-003`: compose smoke script fails fast on unhealthy API, Gateway, or Dashboard setup reachability.
