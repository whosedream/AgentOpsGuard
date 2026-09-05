# AgentOps Guard

AgentOps Guard is a self-hosted Agent tracing, evaluation, and security gateway for MCP + Python agents. It implements a runnable v1 scaffold for trace collection, policy decisions, prompt-injection scanning, replay/evaluation, MCP gatewaying, and a dashboard.

## Features

- Trace Collector for model calls, tool calls, MCP calls, handoffs, state changes, policy decisions, scanner results, approvals, errors, and run completion.
- Policy Engine with deterministic rule-first decisions: `allow`, `deny`, `redact`, `require_approval`, `quarantine`, `sandbox`, and `rate_limit`.
- Prompt Injection Scanner for instruction override, credential exfiltration, tool hijacking, hidden HTML, markdown traps, and base64 obfuscation.
- Replay & Evaluation service for exact/mock/policy replay summaries and YAML-based regression cases.
- Standard MCP Streamable HTTP Gateway that scans tool metadata/results and enforces the same
  pre/post policy and approval checks as the compatibility API. Fixed resources, resource templates,
  prompts, and completion suggestions are exposed only after current-advertisement and content checks.
- Next.js Dashboard for overview, runs, risks, eval suites, and MCP registry.
- v0.7 Governance Control Plane for project configuration, approval queues, policy packs, custom scanner rules, and run suppressions.

## Enterprise safety controls

- Every MCP route is authenticated. Project API keys and signed Agent workload tokens are bound to
  one project, and an Agent-bound credential cannot impersonate another Agent through request data.
- Tool calls require the separate `mcp:invoke` scope. Read-only MCP credentials cannot invoke tools.
- Each decision records immutable tool and policy snapshots. Human approval is bound to the
  authenticated caller, run, tool revision, normalized argument digest, policy snapshot, and expiry.
- An approved execution is claimed atomically. Reuse, changed arguments, changed identity, changed
  tool metadata, or changed policy cannot execute under the old approval. An uncertain upstream
  outcome is not retried automatically. The committed execution lease is always longer than the
  configured upstream timeout, and stale processes cannot overwrite a state changed elsewhere.
- Stdio upstream reads have a wall-clock timeout even when the child writes no bytes, and all
  managed child processes close when the Gateway stops. If an approved side effect occurs but its
  response is lost, the execution becomes `outcome_unknown` and the same approval cannot run again.
  An administrator can close the incident only with an external evidence SHA-256; only a confirmed
  `not executed` result reopens the original, still-version-bound request for one fresh claim.
- Background jobs and their PostgreSQL outbox event commit together. Redis is delivery
  infrastructure, not the source of truth. Workers claim a job atomically, renew a bounded lease,
  stop committing after lease loss, and move the job to `dead` after three unsuccessful attempts.
- A fixed PostgreSQL 16 verifier uses built-in physical streaming replication, `pg_basebackup`, a
  replication slot, synchronous `remote_apply`, and `pg_promote()`. After the old primary is stopped,
  the promoted standby retains one unique execution request, queued work, and a valid audit chain and
  accepts a new audited write.
- A second fixed verifier reuses Patroni `4.1.4` on a three-member Kubernetes `1.34.0` cluster. It
  forces the primary Pod to fail, observes automatic election, keeps the in-cluster database Service
  address unchanged, verifies the old Pod identity is gone and rejoins as a replica, and proves the
  committed AgentOps state remains writable with a valid audit chain. The fixed licensed-image run
  recovered Service queries in `3.821s` and the full one-primary/two-replica topology in `13.106s`.
  A second fault, adapted from the public Jepsen PostgreSQL HA test model and injected with
  Toxiproxy `2.12.0`, kept the database path open while disconnecting only the primary from the
  Kubernetes DCS. Patroni stopped the isolated primary's writes; the maximum observed writable
  primary count remained one, Service queries recovered in `23.912s`, and the healed topology
  recovered in `28.914s`. This is single-machine self-demotion evidence, not persistent-volume,
  hardware-watchdog/node fencing, arbitrary host partition, TLS, cross-zone, or production-scale
  evidence.
- Multi-replica Gateways use Redis-backed expiring capacity leases, so one upstream's concurrency
  limit applies across processes. Coordination failure returns `503` before an upstream call;
  single-process development can keep the local semaphore backend.
- Managed provider secrets cross the Agent boundary only as `credential_ref`. Recognizable secret
  material is removed before policy-service calls, audit records, traces, approval context, project
  metadata, errors, and API responses; raw-content storage never overrides this secret suppression.
- Production semantic scanning uses a separate, offline model service. The Gateway sends only
  locally normalized, redacted text capped at 1,024 characters; model weights are not mounted into
  the Gateway, API, Worker, or Dashboard. A high shadow score cannot allow or deny content directly;
  it can only make a later state-changing action wait for human approval.
- Gateway-generated provenance marks MCP tool descriptions, results, resources, and prompts as
  untrusted after scanning and stores the marker with the redacted content reference. Upstream
  `io.agentops/*` metadata is removed before the Gateway writes its own marker; unknown or derived
  sources never become trusted by default.
- Audit records form a per-project hash chain with an integrity verification endpoint. This detects
  database-only history edits; it is not a substitute for exporting signed evidence to independent
  write-once storage.
- The S3 Object Lock exporter is also exercised against a real local compatibility runtime: a
  `COMPLIANCE`-locked version survives administrator deletion and retention-shortening attempts, and
  duplicate conditional writes create no second version. Because the community MinIO binary is no
  longer maintained and the service is local, this does not replace target enterprise-storage tests.

The trust boundaries, release targets, dependency failures, implemented evidence, and remaining
gaps are recorded in `specs/threat-model-v1.md`, `specs/production-slo-v1.md`,
`specs/failure-mode-matrix-v1.md`, and `specs/enterprise-implementation-status-v1.md`.
The provenance wire contract and its client-side limitation are documented in
`specs/content-provenance-v1.md`.
Protected completion references, input bounds, and output filtering are documented in
`specs/mcp-completion-v1.md`.
The aggregate-only holdout registry and one-way first-run lifecycle are documented in
`specs/unknown-attack-eval-v1.md`. A holdout loses its unseen status before any content is exposed;
failed or interrupted runs remain consumed, and duplicate corpus digests cannot be relabelled.

## Quickstart

```powershell
uv sync --extra dev
docker run --rm -p 6379:6379 redis:7
uv run agentops-guard api --reload
```

In another shell:

```powershell
uv run python examples/demo_agent.py
uv run agentops-guard run-eval examples/evals/redteam-smoke.yaml
```

Open the API docs at `http://localhost:8000/docs`. The default API key is `dev-agentops-key` and can be changed with `AGENTOPS_API_KEY`.

## Dashboard

```powershell
cd dashboard
npm install
npm run dev
```

Open `http://localhost:3000`.

For reproducible installs in CI and release verification, use `npm ci` instead of `npm install`. The Dashboard dependencies are pinned in `dashboard/package.json` and locked by `dashboard/package-lock.json`; do not use `latest` ranges for release-bound dependencies.

The Dashboard backend proxy uses `AGENTOPS_SERVER_API_KEY` or `AGENTOPS_API_KEY` on the server side. Do not expose backend API keys with `NEXT_PUBLIC_` variables.

The Governance page (`/governance`) exposes the v0.7 control plane: project retention/raw-content settings, pending approvals, policy packs, custom scan rules, run status mix, and suppression workflows.

## Governance API

Core v0.7 control-plane endpoints:

- `GET /v1/control-plane/status?project_id=default`: project config plus approval, policy, scan-rule, suppression, and run-status counts.
- `POST /v1/projects`, `PATCH /v1/projects/{project_id}`: create or update project-level retention, raw-content storage, policy fail mode, status, and metadata.
- `GET /v1/approvals`, `POST /v1/approvals/{approval_id}/review`: inspect and resolve human approval requests generated by policy decisions.
- `POST /v1/policy-packs`, `PATCH /v1/policy-packs/{pack_id}`: manage deterministic project policy packs with simple `when` conditions.
- `POST /v1/scanner/rules`, `PATCH /v1/scanner/rules/{rule_id}`: manage project-specific scanner regex rules.
- `POST /v1/runs/{run_id}/suppressions`, `PATCH /v1/suppressions/{suppression_id}`: suppress or resolve known-benign runs while preserving audit history.

## Redis/RQ Worker

Replay, Eval, and MCP refresh requests first commit a job and an outbox event to PostgreSQL. The API
can accept them while Redis is unavailable; the outbox dispatcher delivers pending events after
Redis recovers.

```powershell
$env:AGENTOPS_REDIS_URL="redis://localhost:6379/0"
uv run agentops-guard outbox-dispatcher --dispatcher-id local-1
uv run agentops-guard worker --queue default --with-scheduler
```

## MCP Gateway

Load example registry configuration:

```powershell
uv run agentops-guard load-mcp-config mcp-gateway.yaml
uv run agentops-guard gateway --config mcp-gateway.yaml --port 8001
```

Gateway endpoints:

- `POST/GET /mcp`: standard MCP Streamable HTTP endpoint for official MCP clients.
- `GET /mcp/tools/list`
- `POST /mcp/tools/call`
- `GET /mcp/resources/list`
- `POST /mcp/resources/read`
- `GET /mcp/prompts/list`
- `POST /mcp/prompts/get`

The standard endpoint and all six compatibility endpoints require authentication. Send credentials
only in the `Authorization: Bearer` header for standard MCP. Listing resources requires `mcp:read`;
invoking a tool requires `mcp:invoke`. The authenticated credential fixes the project and Agent;
request data cannot switch either identity. In production, prefer short-lived signed workload
tokens. Do not put tokens in query parameters or request bodies.

See `docs/mcp-gateway.md` for server registration, stdio/streamable HTTP configuration, refresh
jobs, quarantine/restore, policy guard, and troubleshooting. Tested downstream client anchors and
unsupported capability boundaries are recorded in `specs/mcp-compatibility-matrix-v1.md`.

## SDK

See `docs/sdk.md` for the Python SDK quickstart, trace/span usage, scanner/policy calls, and common error handling.

## Environment

- `AGENTOPS_ENV`: `dev`, `test`, or `prod`. Production rejects the default development API key and wildcard CORS.
- `AGENTOPS_API_KEY`: API key for SDK and dashboard requests.
- `AGENTOPS_OPERATOR_API_KEY`: Operator-only bootstrap key for cross-project governance and initial provisioning.
- `AGENTOPS_OIDC_ISSUER`, `AGENTOPS_OIDC_AUDIENCE`, `AGENTOPS_OIDC_JWKS_URL`: Optional enterprise
  OIDC verification settings. All three are required together; production JWKS URLs must use HTTPS.
  Human users must be provisioned in AgentOps, and Agent workload tokens must carry signed
  `project_id`, `agent_id`, `sub`, and `scope` claims. The repository-external Keycloak fixture can
  be installed with `scripts/install_keycloak_oidc_runtime.py` and exercised with
  `scripts/verify_keycloak_oidc.py`; it proves live discovery, token verification, workload binding,
  signing-key rotation, and client disable behavior without writing tokens or secrets to its report.
  Installation requires both detached signatures and the exact reviewed Keycloak Bot and Adoptium
  public-key fingerprints; `scripts/verify_keycloak_oidc_release_signature.py` also proves a
  one-byte change to either archive is rejected.
  It is a local development-mode integration, not a production IdP, TLS, federation, HA, or immediate
  JWT revocation claim.
- `AGENTOPS_OIDC_MAX_TOKEN_BYTES`, `AGENTOPS_OIDC_MAX_TOKEN_LIFETIME_SECONDS`: Bound bearer-token
  parsing to 16 KiB and accepted signed-token lifetime to 15 minutes by default. Workload project,
  Agent, subject and scope claims also have schema-sized count and length limits; oversized or
  ambiguous claims fail before authorization.
- `AGENTOPS_SERVER_API_KEY`: Server-only Dashboard proxy API key.
- `AGENTOPS_DATABASE_URL`: SQLAlchemy database URL. Defaults to local SQLite `agentops_guard.sqlite3`.
- `AGENTOPS_REDIS_URL`: Redis URL for RQ jobs. Defaults to `redis://localhost:6379/0`.
- `AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP`: Only enable for local SQLite development bootstrap.
- `AGENTOPS_COMPONENT`: Declares the process role so production validates only the configuration
  that role actually needs. Helm fixes this value for API, Gateway, Worker, outbox dispatcher,
  semantic scanner, audit-anchor exporter, and migration jobs.
- `AGENTOPS_STORE_RAW_CONTENT`: Set to `true` only when full replay requires raw prompt/tool content.
- `AGENTOPS_POLICY_FAIL_MODE`: Default `closed_for_high_risk`.
- `AGENTOPS_OPA_URL`: Optional OPA base URL. When configured, API and Gateway readiness require
  OPA health. Compose configures the bundled OPA service automatically.
- `AGENTOPS_OPA_TIMEOUT_SECONDS`: OPA request timeout. Default `2` seconds.
- `AGENTOPS_OPA_EXPECTED_POLICY_REVISION`: Exact approved revision returned by the signed policy.
  Production OPA configuration requires it; a healthy OPA serving another validly signed revision
  is treated as unavailable.
- `AGENTOPS_GATEWAY_MAX_CONCURRENCY_PER_SERVER`: Maximum simultaneous calls to one MCP server.
- `AGENTOPS_GATEWAY_CAPACITY_WAIT_SECONDS`: How long a call waits for that server's capacity before
  receiving `429`.
- `AGENTOPS_GATEWAY_CONCURRENCY_BACKEND`: `local` for one Gateway process or `redis` for shared
  multi-replica capacity. `AGENTOPS_GATEWAY_CONCURRENCY_LEASE_SECONDS` bounds crash recovery time.
- `AGENTOPS_MCP_PUBLIC_URL`: Credential-free public HTTPS URL of the standard MCP endpoint; the path
  must be `/mcp`.
- `AGENTOPS_MCP_ALLOWED_HOSTS`, `AGENTOPS_MCP_ALLOWED_ORIGINS`: Comma-separated allowlists used by
  the standard endpoint's host and browser-origin checks. Production rejects an exact wildcard.
- `AGENTOPS_MCP_PAGE_SIZE`: Server-selected page size for standard MCP tool, fixed-resource,
  resource-template and prompt lists. The default is 100 and the accepted range is 1 to 1,000;
  cursors are opaque and bound to the authenticated identity and current visible-item set.
- `AGENTOPS_SCANNER_PLUGINS`: Comma-separated `module:factory` scanner provider plugins.
- `AGENTOPS_SEMANTIC_SERVICE_URL`: Credential-free base URL for the isolated semantic scorer.
  Production rejects in-process semantic scanning. `AGENTOPS_SEMANTIC_SERVICE_TIMEOUT_SECONDS`
  controls its request timeout; model paths and hashes belong only to the scorer process.
- `AGENTOPS_CREDENTIAL_ENCRYPTION_KEY`: Fernet master key for outbound service credentials. Load it from a dedicated secret store only into the API process; never print it or put it in a command argument.
- `AGENTOPS_CREDENTIAL_STORE`: `fernet` for local development or `openbao` for external secret
  storage. The Agent-facing API remains `credential_ref` in both modes.
- `AGENTOPS_OPENBAO_URL`, `AGENTOPS_OPENBAO_AUTH_METHOD`, `AGENTOPS_OPENBAO_KV_MOUNT`: OpenBao
  KV v2 connection settings. Production requires `proxy`; the application connects only to a
  loopback OpenBao Proxy and never receives an OpenBao token or SecretID. The official Proxy owns
  response-wrapped AppRole authentication, renewal, reauthentication, and token injection.
- `AGENTOPS_OPENBAO_TOKEN`: Legacy local-development authentication only. Production configuration
  rejects this mode.
- `AGENTOPS_AUDIT_CHECKPOINT_BACKEND`: `disabled` by default or `openbao` for signed audit
  checkpoints. `AGENTOPS_OPENBAO_TRANSIT_MOUNT` and `AGENTOPS_AUDIT_CHECKPOINT_KEY_NAME` identify
  a non-exportable Ed25519 Transit key; the private key never enters AgentOps Guard.
- `AGENTOPS_AUDIT_ANCHOR_BACKEND`: `disabled` by default or `s3_object_lock` in the dedicated
  exporter. The exporter uses Boto3's normal workload-identity credential chain and accepts no
  static AWS access-key setting. It writes only public signed checkpoint envelopes with SHA-256
  verification and S3 Object Lock `COMPLIANCE` retention.
- `AGENTOPS_OTEL_ENABLED`, `AGENTOPS_OTEL_EXPORTER_OTLP_ENDPOINT`: Enable OTLP traces to an
  OpenTelemetry Collector. Traces contain route templates, timings, status, policy action and risk
  bucket; request/response bodies, headers, tool parameters and credential values are excluded.
  The endpoint must be a credential-free HTTP base URL without a query string or fragment.

## DeepSeek credential boundary

DeepSeek keys use a model-blind path: an administrator submits the key to
`POST /v1/credentials/deepseek`, receives only an opaque `credential_ref`, and grants that
reference to explicit authenticated actor IDs. Agents call
`POST /v1/deepseek/chat/completions` with the reference; they cannot provide a URL, headers, or
raw key. The trusted API process checks the project, actor, provider, fixed target, status, and
version under a per-credential database lock, then the trusted transport decrypts and injects the
key only into the final `Authorization` header for
`https://api.deepseek.com/chat/completions`. Redirects are not followed.

The built-in Fernet adapter protects against a database-only disclosure. The optional OpenBao
adapter stores only an opaque KV path and version proof in SQL; the provider secret remains in
OpenBao. Its production path delegates AppRole authentication and token renewal to the official
OpenBao Proxy. The application sends credential operations to a loopback listener without any
OpenBao token; only the Proxy mounts RoleID and response-wrapped SecretID files. The trusted
deployment component must replace the one-use wrapping token before reauthentication or a Pod
restart. A fixed local verifier also runs three real OpenBao `2.6.1` processes with TLS and
Integrated Storage, terminates the elected leader, reconnects the official Proxy to the new leader,
rotates every node's leaf certificate in standby-first order through OpenBao's supported SIGHUP
reload path without restarting those processes, and restores a Raft snapshot while checking that
the same `credential_ref` and non-exportable Transit key still work throughout. This is local
subsystem evidence with an ephemeral test CA, not proof of enterprise PKI automation, CA trust
rotation, KMS/HSM auto-unseal, cross-zone placement, or transparent load-balancer failover. Neither
mode is protection against compromise of the API process, host, or encryption-key store. Production
Helm installs must put the key in a separate Kubernetes Secret and set
`credentialEncryption.existingSecret`; that Secret is mounted only into the API deployment.

The local `bao` runtime is installed by `scripts/install_openbao_current_runtime.py` from the
official release archive only after both the signed checksum manifest and the archive's own
Sigstore bundle match the exact OpenBao release-workflow identity and issuer. The fixed release
verifier repeats those checks offline, compares the installed binary with the signed archive, and
requires one-byte mutations of the archive and manifest to fail. This proves the host binary's
provenance, not the signature or contents of a production container image; see
`specs/openbao-signed-runtime-provenance-v1.md`.

## Docker Compose

The Compose credential-key setting is for local development only. Do not load production
provider credentials into this stack. Production's concurrent revoke/rotate guarantee requires
PostgreSQL row locks; SQLite is limited to single-process development and tests.

```powershell
docker compose up --build
uv run python scripts/compose_smoke.py
```

The compose stack starts API, Gateway, outbox dispatcher, Worker, Redis, Postgres, and Dashboard.
Production-style deployments should run `agentops-guard-migrate` before API, Gateway, and Worker
startup. It applies Alembic and then idempotently installs the reviewed default scanner rule pack;
any database copy that differs from the pinned pack fails the deployment. The Compose and Helm
stacks include this one-shot migration path.

The semantic model is an explicit offline profile. Set the reviewed model hash and start with
`docker compose --profile semantic up`; the Gateway never mounts the model directory.

For read-only Windows/WSL proxy and Docker connectivity checks, see
`docs/wsl-network-diagnostics.md`. The diagnostic scripts never change daemon or proxy state.

## Helm

```powershell
uv run python scripts/validate_helm_assets.py
powershell -File scripts/helm_template_check.ps1
```

Set `AGENTOPS_HELM_IMAGE` if your environment cannot pull the default Helm image used by the validation helper.

Before installation, provision the Secret named by `runtimeSecret.existingSecret`; the chart only
references individual keys and never renders database, Redis, API, or Dashboard credentials into the
Helm release. Provider decryption keys remain in an API-only Secret. RoleID and response-wrapped
SecretID files are mounted only into official OpenBao Proxy sidecars, never into the application
containers or environment variables. The exporter Proxy uses a separate AppRole whose policy can
only read the Transit public key; it cannot sign checkpoints or read managed provider credentials.

Production values also refuse mutable image tags. Set `image.digest` for the Python services and
`dashboardImage.digest` for the separate Dashboard image; when embedded OPA is enabled, set
`opa.image.digest` independently. All three use reviewed `sha256:<64 lowercase hex characters>`
release digests. Development values may still use tags. This digest gate stops tag drift, but it
does not prove who built an image. Production values therefore also render Sigstore's standard
`ClusterImagePolicy` in enforcing mode. Rendering fails until operators provide repository-scoped
image globs, an HTTPS OIDC issuer, one exact non-wildcard signing identity, and a reviewed managed
`TrustRoot`. The controller is installed separately from the official chart and the target namespace
must explicitly opt in; see `deploy/admission/README.md`. A real local cluster has proved unsigned
and infrastructure-failure rejection plus controller recovery, but correctly signed admission and
the full wrong-signer/mutation/lookalike matrix still require a reachable private registry.

Production also enables a namespace-wide default-deny `NetworkPolicy`. Only the ingress-controller
to Gateway/Dashboard paths and the exact internal API, OPA, and semantic-scanner calls are opened by
the chart. Database, Redis, OIDC, MCP-upstream, OpenBao, object-storage, and telemetry destinations
must be declared per workload with exact ports; global CIDRs, empty selectors, and port ranges are
rejected. Apply restricted Pod Security labels and run real packet probes as described in
`specs/kubernetes-isolation-v1.md`. The local Kubernetes `1.34.0` kindnet run passed 23/23 path probes,
11/11 policy deletion/restoration checks, and restricted Pod Security rejection; this does not replace
rerunning the same matrix on the production CNI and destinations. Each application workload also uses
a dedicated zero-RBAC ServiceAccount and disables automatic Kubernetes API token mounts. The audit
exporter keeps its separately supplied workload identity but likewise receives no general API token
automatically.

Deterministic Python and Dashboard CycloneDX SBOM generation is part of the release checks. A real
online Google OSV scan of both current lockfiles and a production-only npm audit now report zero
known vulnerabilities; the aggregate OSV evidence is bound to both lockfile digests and rechecked
offline by the fixed release verifier. The hosted workflow now also defines a default-branch-only
release chain for both production images: checksum-pinned Buildx runs a digest-pinned BuildKit,
BuildKit attaches SLSA provenance, a digest-pinned Trivy
binary produces a CycloneDX image SBOM and gates the exact digest, and Cosign attaches signed copies
of the provenance and SBOM before signing and re-verifying that digest with the exact GitHub workflow
identity. Pull requests and non-default branches cannot publish or sign, and no mutable
`latest` tag is produced. Build and scan jobs have no OIDC signing permission; a separate signing job
runs only after both matrix builds pass, does not check out or execute project code, and accepts only a
checksum-pinned Cosign binary plus digest-checked workflow artifacts. The workflow definition is
locally validated, but a successful hosted run,
private-registry image digests, and live signed-image admission remain separate release gates; see
`specs/dependency-vulnerability-audit-v1.md` and `docs/deployment.md`.

Production embedded OPA also refuses loose ConfigMap policies. Set `opa.bundle.enabled=true` and
point `opa.bundle.existingSecret` at a pre-created Secret containing only `bundle.tar.gz` and the
verification key `public.pem`. OPA verifies the key ID, scope, signature, file list, and file hashes
before it becomes ready. Set `opa.bundle.expectedPolicyRevision` to the exact revision approved for
that release. API, Gateway, and Worker reject an otherwise valid response from a different revision,
which prevents an older correctly signed bundle from being silently reused. The publishing private
key must remain in the external signing system and must never be mounted into the runtime cluster.

The repository also includes a digest-pinned OPA `1.20.1` host-runtime installer and a real remote
Bundle Service/Status API verifier covering two replicas, signed hot updates, tamper rejection,
last-good retention, publisher outage, restart from persisted last-good policy, and recovery. See
`specs/opa-remote-bundle-runtime-v1.md`; the loopback fixture is not evidence of enterprise TLS,
workload identity, key custody or a signature-verified production image.

A separate digest-pinned OpenTelemetry Collector Contrib `0.160.0` host-runtime check exercises a
real OTLP ingest/export path plus `file_storage` queue recovery across downstream outage and Collector
restart. It verifies that the generated private request marker is absent from the recovered protobuf.
Pinned Cosign `3.1.2` is first verified without executing it by the TUF artifact public key, then
verifies its upstream transparency proofs and the Collector archive against exact identities and
issuers, and finally proves a one-byte mutation is rejected.
See `specs/otelcol-resilience-runtime-v1.md` and `specs/signed-runtime-provenance-v1.md`; signed archive
evidence does not replace container-image verification, production persistent-volume testing, or
validation against the enterprise observability backend.

## Operations

- `GET /healthz`: process liveness.
- `GET /readyz`: database readiness plus Redis delivery status. Redis degradation is reported but
  does not make the API unready because committed jobs remain in PostgreSQL.
- `GET /v1/audit-logs/integrity?project_id=...`: verifies the stored per-project audit hash chain.
- `POST /v1/audit-logs/checkpoints?project_id=...`: asks OpenBao Transit to sign the current audit
  head. `GET /v1/audit-logs/checkpoints` returns the public evidence, and
  `GET /v1/audit-logs/checkpoints/{id}/integrity` verifies its signature and anchored chain prefix.
- `agentops-guard audit-anchor-exporter`: independently verifies every public checkpoint against
  OpenBao and its database chain, then copies it to versioned S3 Object Lock storage. Repeated runs
  verify the existing immutable object version instead of creating a replacement.
- `GET /v1/jobs/reconciliation?project_id=...`: reports stale jobs, expired leases, undelivered
  outbox records, failed jobs, and executions whose upstream outcome is unknown.
- `POST /v1/jobs/{job_id}/retry`: administrators can create a new, audited retry for an eligible
  failed internal job; the failed record is preserved rather than reset in place.
- `POST /v1/executions/{execution_id}/resolve`: administrators reconcile an `outcome_unknown`
  execution as confirmed succeeded, failed, or not executed. The API accepts only an irreversible
  evidence SHA-256, never evidence text, URLs, credentials, or tool arguments.
- `GET /metrics`: Prometheus text metrics, including API request counters and latency totals.
- All API responses include `X-Request-Id`; pass one in the request to correlate logs.

## Development

```powershell
uv run pytest
uv run ruff check .
```

Before opening a release PR, also run the Dashboard and deployment gates:

```powershell
cd dashboard
npm ci
npm run test
npm run test:e2e
npm run build
cd ..
docker compose config --quiet
```

The repository uses `uv` for Python environment management.

## Public benchmarks

The repository includes reproducible aggregate-only runners for the fixed NVIDIA Nemotron corpus and
Microsoft LLMail-Inject Phase 2 challenge data. The LLMail runner verifies fixed source-file hashes,
runs deterministic rules and the pinned local semantic model separately, and never writes raw prompts
or per-row model scores to its report. See `specs/public-benchmark-v1.md` and
`specs/llmail-benchmark-v1.md` for commands, results, and evidence boundaries.

The first frozen AgentDojo-derived unseen static run is documented in
`specs/agentdojo-static-blind-v1.md`: union detection was 107/140 (76.43%) and union false positives
were 9/97 (9.28%). The result is intentionally retained as evidence that the current shadow model is
not ready to block traffic; it is not a full AgentDojo or end-to-end score.

A larger first-run external holdout is documented in `specs/bipia-static-holdout-v1.md`. It reuses
the pinned official Microsoft BIPIA Email, Table, and Code test data without copying it into this
repository. Across 13,750 context/attack combinations, rules detected 491, the shadow model 4,786,
and their union 5,264 (38.28%); union false positives were 13/200 (6.50%). The aggregate-only result
confirms that the model is active but not suitable for enforcement. It is a static scanner test, not
the BIPIA response benchmark and not an Agent/tool blocking rate.

A separate first-run holdout now reuses the pinned official UIUC InjecAgent `base` tool responses.
Without tuning on those cases, rules detected 20/1,054 attacks, the shadow model 571, and their union
577 (54.74%). The union flagged 1/17 matched clean response templates. Data-stealing cases reached
81.62% union detection while direct-harm cases reached only 26.08%, showing why semantic detection
helps but cannot replace intent-to-action authorization. The immutable report contains aggregate
counts only. See `specs/injecagent-static-holdout-v1.md`; this is static scanning, not the official
InjecAgent prompted-agent ASR or an Agent/tool blocking result.

An Apache-2.0 ProtectAI DeBERTa candidate was then tested under the same drop-in conditions and
rejected: union detection fell to 3,564/13,750 (25.92%), union false positives rose to 40/200
(20.00%), and CPU p95 increased from 361.17 ms to 490.56 ms. This post-holdout comparison is retained
as negative selection evidence and is not a second blind result.

A benchmark-only long-text probe then adapted Meta llama-cookbook's 512-token chunking and maximum
risk aggregation while keeping the current Wolf Defender model. On a known 200-attack/200-benign
BIPIA slice, union attack hits improved from 126 to 159, but union false positives increased from 13
to 28 and model p95 rose from 320.84 ms to 2328.22 ms. Raising the threshold collapsed semantic
recall. The design is therefore rejected for production and retained only as aggregate negative
architecture evidence; it is neither blind nor a Prompt Guard 2 model result.

The first real-model dynamic micro-suite is documented in
`specs/agentdojo-template-dynamic-gateway-v1.md`. Qwen3-4B attempted the unauthorized mutation in
7/7 previously unscored official-template adaptations; the deterministic intent/approval boundary
blocked all seven and the controlled upstream observed zero effects. Rules quarantined 0/7 while the
shadow scanner flagged 7/7, with 0/2 flags on benign controls. These nine samples show the layers
working separately; they are not a full AgentDojo result or a statistically sufficient unknown-attack
score, and the semantic model remains shadow-only.

That finding now has a deployment-ready managed rule-pack regression. The reviewed, versioned rule
is installed idempotently by the Compose and Helm migration entrypoint and cannot be edited or deleted
through the ordinary scanner-rule API. Configurable patterns run on pinned Google RE2 with bounded
compilation memory, so an administrator cannot introduce catastrophic regex backtracking. It catches
7/7 of the known template regressions with 0/302 flags across AgentDojo legitimate tasks, LLMail normal
emails, and the dynamic benign controls. An unfixed-seed v7 run produced only 5/7 reads and is retained
as variability evidence. After fixing temperature 0, maximum output 512, and seed 0, unchanged v8 and
v9 runs are identical except for creation time; both quarantine 7/7 attack results before another model
action, allow 2/2 benign reads, and produce zero upstream effects. The current v10 report reruns the
same real path after expanding the semantic input boundary to 1,024 characters and preserves the same
7/7 attack quarantines, 2/2 benign reads, and zero upstream effects. It follows protected resource
templates, completion controls, and consistent restricted-Agent discovery/read controls, and binds 23
provenance, protocol,
authentication, concurrency, transport, approval, tool revision, scanner and evaluation
implementation inputs instead of only the Gateway entry file. See
`specs/managed-scanner-rule-pack-v1.md`. These are post-finding regressions, not new blind scores.

The broader dynamic regression reuses the official 24-sample AgentThreatBench task from pinned
`inspect-evals 0.16.0`. The same Qwen3-4B runs the official baseline and then runs through a real
Gateway and standard MCP client; the effect scorer counts only tool calls that actually executed.
In the current public-corpus regression, 5/5 autonomy-hijack samples had their state-changing calls
paused before upstream execution, attack samples executed zero high-risk actions, and the benign
autonomy task still completed without approval. Full effect security was 17/19 (89.47%), because one
memory-poison response and one email-task response still echoed attack content without causing an
external effect. Overall benign utility remained the model baseline of 1/5. The six immutable reports
retain the disconnected v1, the v3
zero-utility over-quarantine, later action-classification fixes, and the current result instead of
keeping only the best number. See `specs/agent-threat-bench-dynamic-gateway-v1.md`. This public corpus
has already been used for repairs, has only five benign samples, and is neither a blind benchmark nor
a production deployment test.

Future unknown-attack evaluations must use the holdout registry before Inspect AI reads any case.
The registry now classifies the consumed AgentDojo, BIPIA and InjecAgent static first runs, the
consumed AgentDojo dynamic micro-suite and the known Nemotron set. It still has no independent
multilingual end-to-end corpus. The external unknown-attack Agent gate remains open until such a set
is run through a real Agent, Gateway and controlled tools.

The authenticated low-risk Gateway component benchmark is documented in
`specs/gateway-security-path-benchmark-v1.md`. Its local SQLite/TestClient result is a regression
baseline only, not a production throughput or availability claim.

The isolated Inspect AI evaluation in `evals/inspect/` drives a deliberately compromised deterministic
Agent through a real Gateway process and real MCP v2 upstream. It verifies that read-only work still
completes while an induced unauthorized write has no upstream effect. Inspect receives only an opaque
`credential_ref`; a fixed-target trusted process owns and injects the temporary test identity. See
`specs/online-eval-v1.md` for the command and evidence boundary; this smoke test is not a real-model
generalization benchmark.

For a real local-model smoke test, `scripts/run_llama_cpp_agent_eval.py` requires reviewed SHA-256
values for the runtime source/lock or llama.cpp executable and the GGUF model, starts the model on
loopback itself, and writes only aggregate evidence. The pinned Qwen3-4B Q4_K_M run completed both
read-only tasks against the real Gateway and MCP upstream with zero unauthorized upstream effects.
This is two-sample execution evidence, not an unknown-attack or model-quality benchmark. A separately
started compatible endpoint remains insufficient provenance.
