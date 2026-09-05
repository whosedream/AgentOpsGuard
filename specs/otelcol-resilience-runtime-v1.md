# OpenTelemetry Collector Resilient Runtime Verification v1

## Scope

This local subsystem check uses the official OpenTelemetry Collector Contrib `0.160.0` Linux/amd64
runtime to verify that AgentOps traces cross a real OTLP receiver/exporter pipeline, do not contain
request content, and survive both a downstream outage and a Collector restart through a persistent
sending queue.

It does not claim a production observability backend, signed container image, Kubernetes volume,
high availability, production retention, alert delivery, or load capacity.

## Runtime provenance

- Upstream: <https://github.com/open-telemetry/opentelemetry-collector-releases>
- Release: `v0.160.0`
- Asset: `otelcol-contrib_0.160.0_linux_amd64.tar.gz`
- Archive SHA-256: `7bb60c584c241c86261c2b8697cd3725dd8c56691f5ad5d98454eaa005b47b0c`
- Extracted binary SHA-256: `8524ac54f6e1d4d00d9ba5eea91daadec2ebc31e4da80db9c17eba2e859ecdd4`

The official release publishes a per-asset checksum and a Sigstore bundle. The archive signature is
now verified by pinned Cosign `3.1.2` using the exact OpenTelemetry release-workflow identity and
GitHub Actions issuer, with a pinned trusted-root snapshot. The installer retains read-only release
material for repeat verification. See `specs/signed-runtime-provenance-v1.md`. This is signed archive
evidence, not signed container-image evidence.

The 380 MiB extracted runtime is installed outside Git at
`~/.local/share/agentops-guard/otelcol-contrib/0.160.0/otelcol-contrib`, mode `0500`, with:

```text
uv run python scripts/install_otelcol_current_runtime.py \
  --archive <downloaded-tar.gz> \
  --checksum-file <downloaded-tar.gz.sha256> \
  --sigstore-bundle <downloaded-tar.gz.sigstore.json>
```

The installer accepts only an archive containing the expected regular `README.md` and
`otelcol-contrib` files, caps the executable at 512 MiB, verifies the reviewed archive and binary
digests, exact signing identity and issuer, installs atomically, and requires the installed program
to report exactly version `0.160.0`.

## Real failure flow

`scripts/verify_otelcol_resilient_host_runtime.py`:

1. verifies the installed binary's SHA-256 and version;
2. starts the real Collector with OTLP/gRPC and health listeners bound only to loopback;
3. configures `memory_limiter`, `batch`, OTLP export retry, and a `file_storage`-backed sending queue;
4. leaves the downstream OTLP endpoint unavailable and sends one instrumented AgentOps request;
5. confirms the persistent queue has written data, then terminates the Collector;
6. starts a local OTLP backend and restarts the Collector against the same queue directory;
7. confirms the queued trace reaches the backend after restart;
8. inspects the in-memory protobuf only long enough to assert that the random private request marker
   is absent while the fixed route template and component label are present;
9. shuts down both processes and deletes the temporary config, queue and received trace.

The aggregate report records no trace payload, request marker, environment values or credentials.

## Observed result

- official `0.160.0` archive checksum and installed binary digest/version: pass;
- official archive Sigstore signature with exact workflow identity and issuer: pass;
- installed binary matches the binary inside the signed archive: pass;
- one-byte archive mutation rejected: pass;
- real OTLP ingest while downstream was unavailable: pass;
- disk-backed queue data observed: pass;
- Collector termination and restart recovered the queued trace: pass;
- random request path/query/header/body marker absent: pass;
- fixed route template and component label present: pass;
- Collector and backend listeners loopback-only; process non-root: pass.

## Remaining production gate

The production Collector gate stays open until a signature-verified, digest-pinned official image is
run in the target Kubernetes environment with an approved persistent volume and exports to the real
Prometheus/Tempo/Loki or equivalent backend. The same environment must demonstrate backend outage,
queue pressure, Collector restart, search-based sensitive-field checks, alert delivery, retention and
the target load window without telemetry gaps.
