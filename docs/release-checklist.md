# Release Checklist

- Run `uv run python scripts/run_release_verification.py` and retain the generated
  `artifacts/verification/*.json` report with the release evidence. The verifier runs the fixed
  local checks without forwarding application credentials or recording command output, request
  content, model content, environment values, or secrets. A passing local report does not clear
  the report's explicit external gates.
- Run `uv run ruff check .`.
- The fixed verifier runs `uv run pytest --cov=agentops_guard --cov-fail-under=80 -q`;
  confirm the report's `python_tests` check passed.
- Confirm `inspect_eval_dependency_lock`, `inspect_eval_environment`, and
  `inspect_agent_gateway_smoke` passed. The isolated Inspect AI environment must be created from its
  own lock file, then run offline against a real Gateway process and real MCP v2 upstream. Both reads
  must complete, the deliberately induced write attempt must create no upstream side effect, and the
  temporary evaluation identity must be held only by the fixed-target trusted injector, never the
  Inspect or Agent process, and must not appear in Inspect logs. This is deterministic security-path
  evidence, not a real-model or unknown-attack quality result.
- Confirm `local_model_runtime_dependency_lock`, `local_model_runtime_environment`, and
  `real_local_model_agent_evidence` passed. The evidence verifier must match the immutable Qwen3-4B
  Q4_K_M v2 report, official GGUF SHA-256, `llama-cpp-python 0.3.35` source/lock/runtime fingerprints,
  and all evaluation implementation fingerprints. The launcher itself must start the verified model
  and loopback-only adapter; a separately started endpoint is not model provenance. The fixed result
  is 2 completed read-only tasks and 0 unauthorized upstream effects. It is not a generalization score.
- Confirm `agentdojo_static_evidence` passed. It must preserve the immutable first-run report and
  verify the current post-first-run regression separately, including the selected corpus digest,
  AgentDojo `0.1.35` / benchmark `v1.2.2`, current local semantic-model digest, current
  implementation digests and aggregate counts without writing or logging raw cases.
- Confirm `bipia_static_holdout_evidence` passed. It must verify the immutable first-run aggregate
  report, official Microsoft BIPIA commit and source-file hashes, selected corpus digest, current
  evaluated implementation and model digests, and the 13,750 attack / 200 normal aggregate counts.
  Prepare the repository-external pinned source with `uv run python scripts/prepare_bipia_eval.py`
  before the offline verifier. This is static scanner evidence, not BIPIA response attack success or
  Agent/tool end-to-end blocking evidence. The same verifier also preserves the post-holdout
  ProtectAI candidate rejection report; it is negative model-selection evidence, not a current-model
  or blind claim. It also preserves the benchmark-only full-token windowing and in-sample threshold
  reports. Those reports reject maximum-risk chunking for the current model because of false-positive
  and latency costs; they do not change production behavior, select a threshold, evaluate Prompt
  Guard 2, or establish a blind result.
- Confirm `injecagent_static_holdout_evidence` passed. It must preserve the immutable first-run
  report, verify UIUC InjecAgent commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`, the two official
  `base` case blobs, selected corpus, frozen system/model/threshold and aggregate 1,054 attack plus
  17 matched-clean results. The fixed result is 577 union detections and one matched-clean flag.
  This is static external-content evidence, not official InjecAgent prompted-agent ASR or end-to-end
  tool blocking.
- Confirm `holdout_manifest_contract` passed. The registry must contain aggregate metadata only,
  reject duplicate corpus digests across evaluation roles, bind sealed sets to a frozen system
  digest, and consume unseen status before content access. Failed, interrupted, or report-less runs
  remain regression data; this workflow does not itself count as a new unknown-attack result.
- Confirm `agentdojo_dynamic_gateway_evidence` passed. It must preserve the immutable first-run and
  historical post-fix real-Qwen reports and verify the current provenance-enabled report, both model artifacts,
  both runtime
  locks, the adapted AgentDojo corpus digest, and all current Gateway/evaluation implementation
  digests, including provenance, protocol, authentication, concurrency, transport, execution envelope,
  and tool revision modules. The first run proves the model attempted 7/7 unauthorized mutations and deterministic
  authorization stopped all seven. The current regression proves the managed rule quarantines 7/7
  attack results before another model action, allows 2/2 benign reads, and produces 0 upstream
  effects. This is a small reused micro-suite, not a blind, full AgentDojo, or statistically
  sufficient unknown-attack result.
- Confirm the standard MCP and Gateway tests cover content provenance: upstream `io.agentops/*`
  metadata cannot forge trust or control fields; tool results, resources and prompts are marked
  untrusted by the Gateway; derived unknown trust stays untrusted; quarantine hides `contentRef`;
  and a normal response's marker is retained on its redacted server-side content record.
- Confirm the official MCP client retrieves every page of tool, fixed-resource, resource-template and prompt lists; expands protected
  templates through the real Gateway and upstream; rejects missing, extra, credential-bearing and unadvertised resource references; and that
  malformed, stale, cross-list and cross-identity cursors fail with `-32602` without leaking an
  upstream identifier.
- Confirm the current official MCP client completes both protected prompts and resource templates;
  only current advertised references and declared bounded arguments reach upstream, while credential
  inputs and unsafe, duplicate, malformed or oversized suggestions fail closed or are omitted.
- Confirm `scanner_rule_pack_evidence` passed. It must preserve the historical reports, verify the
  current reviewed pack and v3 report, reproduce the 7/7 known-attack and 0/302 public-normal
  regression, and prove configurable rules use pinned `google-re2` with bounded compilation memory.
  It also confirms Compose and Helm use `agentops-guard-migrate` so the pack is installed after
  Alembic. This is post-finding regression evidence, not a blind score. Unsafe regex syntax, a
  changed database copy, or ordinary API update/delete of the managed rule must fail.
- Confirm `keycloak_oidc_release_provenance` and `keycloak_oidc_runtime` passed. Install the fixed
  Keycloak `26.7.3` and Eclipse Temurin JRE
  `21.0.12.1+1` archives outside the repository with
  `scripts/install_keycloak_oidc_runtime.py`; the installer must match archive, signature, and
  public-key SHA-256 values, require the exact reviewed signer fingerprints, verify both detached
  signatures, reject unsafe archive members, and refuse to overwrite an existing runtime. The
  offline provenance check must also reject a one-byte change to each archive. The live check must
  issue a 60-second workload token, bind its signed project, Agent, audience and scopes, reject wrong
  issuer/audience, a modified signature and a genuinely expired one-second token, then rotate the
  signing key and disable the client. It
  intentionally records that the already-issued offline JWT remains accepted until expiry. The
  report must contain no token, claim body, generated password, or client secret. This local
  development-mode Keycloak check does not clear the enterprise OIDC gate.
- Run `uv run python scripts/verify_opa_runtime.py`; confirm the pinned official image passes the
  checked-in Rego tests, accepts a correctly signed policy bundle, rejects a modified bundle,
  receives only the verification public key, serves real policy decisions, cannot lower
  deterministic authorization, and sends risky requests to approval when OPA stops.
- Run `uv run python scripts/verify_opa_remote_bundle.py`; confirm two real OPA processes fetch a
  signed v1 bundle over the Bundle Service API, hot-update to signed v2, report both revisions with
  distinct instance identities, retain v2 when a tampered replacement or publisher outage occurs,
  and recover one restarted replica from its persisted last-good bundle before reconnecting. The verifier also
  requires the reviewed OPA `1.20.1` Linux/amd64 binary SHA-256. Install it outside the repository
  with `scripts/install_opa_current_runtime.py`; do not commit the 61.6 MB binary. The local HTTP
  fixture has no TLS, workload authentication or enterprise key custody, so this
  check does not clear the production OPA gate.
- For production signed bundles, set `opa.bundle.expectedPolicyRevision` to the exact revision approved
  by the release and confirm API, Gateway, and Worker fail conservatively when OPA returns another
  revision. OPA signature timestamps are informational and are not an expiry check.
- Run `AGENTOPS_DATABASE_URL=sqlite:///./release-migration.sqlite3 uv run alembic upgrade head`.
- Run `uv run python scripts/verify_postgres_audit_append_only.py`; confirm normal inserts work while
  PostgreSQL rejects updates, deletes, and truncation of audit records and signed checkpoints;
  also confirm two concurrent outcome reconciliations have one winner and confirmed non-execution
  reopens only the original bounded request. The same verifier must prove a claim survives an
  execution-process exit, expires to `outcome_unknown`, rejects a replacement claim, and cannot be
  overwritten by a stale process result.
- The fixed verifier also runs `scripts/verify_postgres_backup_restore.py`,
  `scripts/verify_postgres_streaming_failover.py`,
  `scripts/verify_patroni_kubernetes_failover_artifact.py`, and
  `scripts/verify_operational_resilience.py`.
  Confirm the report proves a current empty-database restore, legacy audit-chain migration, one
  controlled synchronous-streaming replication failover with preserved application state and a
  valid post-promotion audit write, and the fixed three-member Patroni/Kubernetes evidence. The latter
  must prove automatic election, replacement of the failed Pod identity, one primary after recovery,
  an unchanged in-cluster Service address, preserved application state and a valid post-failover
  write. It must also bind the DCS-only partition evidence: the database path remains reachable at
  injection, the isolated primary loses DCS access and stops writes, no sample observes more than one
  writable primary, the stable Service moves to the replacement, and healing restores one primary
  plus two replicas. Also confirm Worker crash recovery, Redis outage recovery, duplicate RQ delivery suppression,
  expiring cross-process capacity leases, and two real Gateway processes sharing one upstream limit.
  Disposable live checks must remove their resources. Local Patroni self-demotion does not clear
  durable storage, hardware watchdog/node fencing, arbitrary host partitions, TLS, cross-zone, or
  production-scale gates.
- Run `uv run python scripts/verify_openbao_proxy.py`; confirm the application receives no OpenBao
  token, each identity-delivery policy can mint only its assigned wrapped identity and cannot read
  credentials or sign, wrapped identity rotation permits reauthentication, the exporter cannot
  read credentials or sign, and deleting the API AppRole causes access to fail.
- Confirm `openbao_release_provenance` passed before accepting any OpenBao runtime result. It must
  verify the exact official workflow identity and issuer for both the checksum manifest and archive,
  bind the installed binary to that signed archive, and reject one-byte mutations of both inputs.
  This is host-archive provenance and does not prove a production container image.
- Run `uv run python scripts/verify_openbao_raft_ha.py`; confirm three real TLS-enabled Raft voters
  form a cluster; every node reloads a distinct replacement leaf certificate through SIGHUP without
  a process restart; the same `credential_ref` and Transit key remain available during rotation and
  after one elected leader is terminated; and an official snapshot restore removes only the
  post-snapshot marker. Keep enterprise PKI automation, CA trust rotation, mutual TLS, auto-unseal,
  cross-zone placement, and transparent load-balancer failover as separate release evidence.
- Confirm the fixed verifier's `openbao_audit_checkpoint` check passed, including immutable signing
  key use, public-key verification, substituted-key detection, and sealed-prefix tamper detection.
- After loading a signer-verified official Collector image by immutable digest, run
  `uv run python scripts/verify_otel_collector.py --image '<official-repository>@sha256:<digest>'`.
  This local file-export check does not replace validation against the enterprise telemetry backend.
- Run `uv run python scripts/verify_otelcol_resilient_host_runtime.py`; confirm the pinned official
  `0.160.0` binary accepts a real OTLP trace while its downstream is unavailable, writes the
  `file_storage` queue, survives Collector termination, and delivers the queued trace after restart.
  The recovered protobuf must contain the fixed route template and component but not the generated
  private request marker. Install the binary outside Git with
  `scripts/install_otelcol_current_runtime.py`.
- Run `uv run python scripts/verify_otelcol_release_signature.py`; confirm pinned Cosign verifies its
  own release and the Collector archive with exact identities and issuers, the installed binary
  matches the signed archive, and a one-byte archive mutation is rejected. This proves an upstream
  release archive, not a production container image, private-registry policy or hosted CI run.
- Run `uv run python scripts/validate_helm_assets.py`.
- Run `powershell -File scripts/helm_template_check.ps1`.
- Run `uv run python scripts/helm_template_check.py`.
  - The script prefers a local `helm` binary, then `%TEMP%\helm-v3.18.4\windows-amd64\helm.exe`, then `AGENTOPS_HELM_IMAGE`.
  - Production rendering must contain a namespace-wide ingress/egress default-deny policy, separate
    ingress-controller paths for Gateway and Dashboard, fixed internal paths, restricted DNS, and
    per-workload external egress. Disabled isolation, missing required destinations, empty selectors,
    all-address CIDRs, port ranges, and invalid protocols must fail rendering.
  - Every Deployment and migration Job must name a dedicated ServiceAccount and set
    `automountServiceAccountToken: false`. The application chart must render no Role, ClusterRole,
    RoleBinding, or ClusterRoleBinding.
- On the target Kubernetes minor, label the application namespace to enforce/audit/warn the
  `restricted` Pod Security profile and opt into Sigstore verification. Confirm the selected CNI
  supports NetworkPolicy, then run the positive and negative packet probes in
  `specs/kubernetes-isolation-v1.md`. Merely listing accepted NetworkPolicy objects is insufficient.
- Run `cd dashboard && npm ci && npm run test && npm run test:e2e && npm run build`.
- Run `docker compose config --quiet`.
- Start `docker compose up --build -d` and smoke `/readyz`, `/mcp/tools/list`, a replay job, and Dashboard `/setup`.
- Confirm `docker compose ps` shows API, Gateway, Worker, Redis, Postgres, Dashboard, and the migration job completed successfully.
- Review API contract changes in `specs/api-contracts.md`.
- Confirm no backend API key is exposed through `NEXT_PUBLIC_` variables.
- Smoke `/readyz` and confirm `migration.status` is `ok` in migrated environments or `skipped` only for local SQLite development.
- Smoke `/metrics` and confirm governance/job metrics are present without high-cardinality labels.
- Capture one API request log line and confirm it is parseable JSON with `request_id`, `method`, `path`, `status`, and `duration_ms`.
- Review `specs/api-contracts.md` for operations, metrics, and v0.7 governance API changes.
- Review `docs/sdk.md` and run the SDK quickstart smoke against a local API.
- Review `docs/mcp-gateway.md` and smoke server register, refresh, quarantine/restore, and tool call flows.
- Confirm `CHANGELOG.md` captures the current authorization, credential, policy, audit, failure-recovery,
  deployment, telemetry, and verification changes, including every unresolved external release gate.
- Confirm Dashboard BFF proxy preserves query strings for Runs/Risks filters, pagination, and project-scoped requests.
- Confirm `dashboard/package.json` uses pinned dependency versions, not `latest`, and `dashboard/package-lock.json` is updated.
- Run `cd dashboard && npm audit --omit=dev`; document any Next.js transitive advisory that cannot be remediated without a framework downgrade or an upstream patched release.
- Run `python scripts/run_osv_lockfile_audit.py --scanner <reviewed-osv-scanner>` and retain only the
  aggregate evidence; confirm `scripts/verify_osv_lockfile_audit_artifact.py` accepts the current
  `uv.lock` and Dashboard lock digest with zero production and development findings.
- Confirm the `Supply chain` workflow passed without ignored failures. Retain its CycloneDX dependency
  SBOMs and, for both images, the exact digest, BuildKit SLSA provenance, CycloneDX image SBOM, Trivy
  report, and Cosign signature/attestation verification identity. A skipped release-image job is not
  a successful production release.
- Build the Python and Dashboard production images from their separate Dockerfiles; record both image
  digests and configure `image.digest` plus `dashboardImage.digest` before rendering production Helm.
  When OpenBao is enabled, mirror the reviewed official Proxy image into the private registry and
  configure `openbaoProxy.image.digest`; production Helm rejects a mutable Proxy tag.
- Confirm the root and Dashboard `.dockerignore` files remain default-deny allowlists. They must not
  include `.env`, databases, models, datasets, reports, test caches, `.git`, `.next`, or `node_modules`.
- Verify each release image signature against the approved signer identity with Cosign/Sigstore. A digest
  match alone is not signer verification; do not release while this check is unavailable.
- Install the official Sigstore policy-controller chart using
  `deploy/admission/policy-controller-values.prod.yaml`, label only the reviewed application namespace
  with `policy.sigstore.dev/include=true`, and inspect both admission webhook configurations for
  `failurePolicy: Fail`. Provision a reviewed public-key-only `TrustRoot`, wait for Ready, and pass its
  exact name as `imageVerification.trustRootRef`. Render the application chart with exact
  `imageVerification.imageGlobs`, `keyless.issuer`, and `keyless.subject` values; wildcard signer
  identities are forbidden. Run `uv run python scripts/verify_sigstore_admission_artifact.py` to bind
  the fixed local negative/fail-closed evidence to the current production configuration.
- In a real pre-production cluster, prove a correctly signed digest is admitted and that an unsigned
  image, a different signer, a post-signing mutation, and a lookalike repository are denied. Stop both
  webhook replicas and prove new application workloads fail closed. Retain only image/policy digests,
  public signer identity, decisions, and timestamps; this cannot be replaced by local Helm rendering.
- When `auditAnchorExporter.enabled=true`, verify the target bucket has versioning and Object Lock
  enabled, the exporter uses workload identity plus separate read-only database/OpenBao identities,
  and a real `COMPLIANCE`-locked checkpoint version cannot be deleted or shortened before expiry.
- Run `uv run python scripts/verify_minio_object_lock.py`; confirm the signed, digest-pinned local
  compatibility runtime rejects administrator deletion and retention shortening and that a duplicate
  conditional write creates no second version. This is not evidence for the target external service.
