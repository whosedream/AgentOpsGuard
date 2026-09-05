# Changelog

## Unreleased

### Deterministic Authorization and MCP Gateway

- Added authenticated MCP identities with separate read and invoke scopes, project isolation, and
  Agent identity binding. Request data can no longer select a different project or impersonate a
  different Agent.
- Bound every approval to immutable tool metadata, normalized argument digest, policy snapshot,
  caller identity, run, and expiry. Approved executions are claimed atomically and cannot be reused
  after arguments, identity, tool metadata, or policy change.
- Added explicit `outcome_unknown` handling for side effects whose response is lost. These calls are
  never retried automatically; an administrator must reconcile them with an external evidence
  SHA-256, and only confirmed non-execution can reopen the original bounded request.
- Moved the standard Streamable HTTP MCP path to the official MCP Python SDK while preserving the
  same scan, policy, approval, audit, and concurrency checks as the compatibility API.
- Added standard cursor pagination for tool, fixed-resource, resource-template, and prompt lists. Cursors are bounded,
  canonical, stateless, HMAC-authenticated, and tied to the authenticated project, actor, Agent,
  list type, and stable visible-item snapshot; modified, malformed, stale, cross-list, and
  cross-identity reuse fails with the MCP invalid-params error.
- Added standard MCP resource-template discovery and reads by reusing the official SDK's bounded RFC
  6570 implementation. Standard clients receive project-bound protected templates instead of raw
  upstream addresses; missing, extra, non-canonical, oversized, credential-bearing, quarantined, and
  unadvertised resource references fail before an upstream read. Restricted-server Agent allowlists
  now also cover all discovery, resource reads, and prompt retrieval.
- Added standard MCP completion for protected prompts and resource templates using the official SDK
  request and result types. The Gateway rechecks current advertisement and declared argument names,
  rejects bounded unsafe or credential-bearing inputs before upstream, and omits unsafe, duplicate,
  credential-bearing, malformed, or oversized suggestions before returning a capped result. Prompt
  retrieval now also rejects unadvertised prompts and undeclared or unsafe arguments before upstream.

### Credential, Policy, and Model Boundaries

- Restricted Agents and models to opaque `credential_ref` values. Only the trusted API process can
  resolve a reference and inject authentication into a fixed approved target; recognizable secret
  material is removed before policy, model, approval, trace, audit, and error boundaries.
- Added production OpenBao Proxy integration using response-wrapped AppRole identities. Applications
  connect only to a loopback Proxy and do not receive OpenBao tokens; API and audit-export identities
  have separate least-privilege policies.
- Added a real three-process OpenBao `2.6.1` verifier using TLS and Integrated Storage. It forms three
  Raft voters, atomically rotates distinct per-node leaf certificates through the supported SIGHUP
  reload path without process restarts, terminates the elected leader, reconnects the official Proxy
  to the replacement, proves the same `credential_ref` and non-exportable Transit key remain usable,
  and restores an official snapshot without emitting root tokens, unseal shares, delivery tokens, or
  provider credentials.
- Added a pinned OpenBao host-runtime installer and offline release verifier. Both the official
  checksum manifest and Linux/amd64 archive must verify against the exact OpenBao release-workflow
  identity and GitHub Actions issuer; the installed binary must match the signed archive, and
  one-byte mutations of either signed input are rejected. Production image provenance remains open.
- Added signed OPA bundle loading and fail-safe policy integration. OPA may make a decision stricter
  than the built-in authorization rules but cannot turn a deterministic denial into an allow.
- Added a real OPA Bundle Service/Status API verifier. Two OPA processes load signed v1 over the
  network, hot-update to signed v2 and report separate status, reject changed-after-signing bytes
  while retaining v2, preserve the last successful ETag through publisher outage, and recover one
  restarted process from its persisted last-good bundle before reconnecting. Neither process receives
  the publishing private key. The remote flow runs on the reviewed current OPA `1.20.1`
  Linux/amd64 binary with a fixed SHA-256 and an external atomic installer; authenticated enterprise
  publishing and a signature-verified production image remain explicit external gates.
- Production OPA clients now require the exact policy revision approved by the release and treat a
  different response revision as unavailable. This blocks silent rollback to an older validly signed
  bundle; OPA's informational signature timestamp is not misrepresented as an expiry control.
- Isolated the semantic scanner as an offline service that receives only locally redacted text capped
  at 1,024 characters. Its result cannot approve or lower deterministic authorization; a high-risk
  shadow event can only raise a later state-changing action to human approval.
- Added Gateway-owned content provenance for MCP tool descriptions/results, resources, and prompts.
  Unknown and mixed derived content remains untrusted, upstream `io.agentops/*` metadata is removed
  recursively, redacted content records retain the marker, and quarantine responses hide their
  content reference.
- Added ToolHive permission profiles and runtime verification for no network, no host mounts or
  devices, non-privileged execution, isolated host namespaces, and dropped Linux capabilities.

### Durable Work and Tamper-Evident Audit

- Added a transactional PostgreSQL outbox, stable RQ job identifiers, atomic Worker claims, renewable
  leases, bounded recovery, and a dead-job queue. Redis delivery outages no longer discard committed
  work, and a Worker that loses its lease cannot write a stale result.
- Added a digest-pinned PostgreSQL 16 physical-streaming failover verifier. It bootstraps a hot standby
  with `pg_basebackup`, waits for synchronous `remote_apply`, stops the old primary before promotion,
  and proves the replicated approval, execution, job, and audit-chain state remains unique and
  writable after `pg_promote()`.
- Reused Patroni `4.1.4` instead of implementing database election. A digest-pinned three-member
  Kubernetes `1.34.0` run forces the primary Pod to fail, automatically elects a different primary,
  preserves the in-cluster Service address, replaces the old Pod identity as a replica, and keeps the
  AgentOps approval, job and audit-chain state writable. The fixed licensed-image run recovered
  Service queries in `3.821s` and the full topology in `13.106s`. A second fault reuses Toxiproxy
  `2.12.0` and the public Jepsen PostgreSQL HA partition invariant: the database path stays open while
  only the primary's DCS path is disconnected. The isolated primary stops writes, the maximum
  observed writable-primary count stays at one, Service queries recover in `23.912s`, and healing
  restores the full topology in `28.914s`. Hardware watchdog/node fencing, arbitrary host partitions,
  persistent volumes, TLS, cross-zone placement and production load remain external gates.
- Added Redis-backed expiring capacity leases so multiple Gateway replicas enforce one concurrency
  limit per upstream. Coordination failure returns before the upstream tool is called.
- Added per-project audit hash chains, PostgreSQL append-only triggers, and OpenBao Transit-signed
  checkpoints with online and offline verification material.
- Added an independent S3 Object Lock exporter with version, digest, conditional-create, retention,
  and read-after-write checks. This path is implemented and request-level tested but has not yet been
  run against an enterprise Object Lock bucket.

### Deployment, Supply Chain, and Telemetry

- Hardened Helm workloads with digest-only production images, non-root users, read-only root filesystems,
  runtime seccomp, no privilege escalation, dropped capabilities, scoped Secrets, and network policies.
- Added separate Python and Dashboard production images plus default-deny build-context allowlists.
  Compose now mounts only required Dashboard source paths and binds every published service port to
  the host loopback interface.
- Added deterministic CycloneDX SBOM generation for Python and Dashboard dependencies and a supply-chain
  workflow that does not ignore audit, scan, or signature failures.
- Added a default-branch-only production image release job using pinned Docker Buildx, Aqua Trivy,
  and Sigstore Cosign actions. Both application images receive BuildKit SLSA provenance and a
  digest-pinned Trivy CycloneDX SBOM; Cosign signs both attestations and the exact image digest only
  after every dependency and image gate passes. The job publishes commit-addressed tags only and
  re-verifies the exact GitHub workflow identity. Build and scan jobs have no OIDC signing permission;
  an isolated signer job does not check out project code and executes only a checksum-pinned Cosign
  binary transferred through digest-checked workflow artifacts. A hosted successful run and real
  registry artifacts remain external evidence gates.
- Pinned the downloaded Buildx executable and BuildKit daemon image independently of the setup
  action, disabled binary caching and BuildKit insecure entitlements, and verifies Buildx before the
  registry login step. This closes the gap where an immutable action could still fetch a mutable
  builder while package credentials were present.
- Reused Google's pinned OSV workflow and added a local aggregate-only lockfile audit. Updated the
  affected Python, Next.js, ECharts, PostCSS, Browserslist, Nano ID, Sharp, JSDOM, Undici and Vite
  dependency paths; the real online OSV rescan of both current lockfiles and the production-only npm
  audit now report zero known vulnerabilities. The evidence records only scanner/lock digests and
  counts, expires on any lock change, and does not turn the unrun hosted workflow or image scan into a
  completed gate. The immutable BIPIA first-run report remains unchanged; a pinned compatibility
  manifest allows only the two reviewed Python security patches and rejects every other lock digest.
- Restricted tracing to fixed low-cardinality attributes and route templates. Request bodies, dynamic
  paths, query strings, headers, tool arguments, model content, credentials, and ambient OpenTelemetry
  resource variables are not exported.
- Added a reviewed OpenTelemetry Collector Contrib `0.160.0` host-runtime installer and real
  persistent-queue recovery check. With the downstream unavailable, a trace is durably queued; after
  Collector termination and restart it reaches a local OTLP backend without the generated private
  request marker. Added a digest-pinned Cosign `3.1.2` installer and offline release verifier that
  checks exact signer identities and issuers for Cosign and the Collector archive, binds the installed
  Collector to the signed archive, and rejects a one-byte mutation. Signed production images, the
  production container/PV and enterprise backend remain external gates.
- Added a real local S3 Object Lock verifier using a checksum- and Minisign-pinned compatibility
  runtime. It exercises the production sink, exact-version read-back, idempotent conditional writes,
  and administrator rejection for deletion and retention shortening without exposing generated
  credentials. The unmaintained community runtime is explicitly not a production recommendation.
- Added a fixed release verifier that records source and dependency digests, check status, duration, and
  unresolved external gates without recording command output, application credentials, or request/model
  content. It now recreates disposable PostgreSQL and Redis services to rerun backup/restore, Worker and
  RQ crash recovery, Redis outage recovery, distributed capacity, two-Gateway contention, and OpenBao
  audit-checkpoint tamper checks against the current source state.
- Added an isolated Inspect AI `0.3.262` evaluation project. Its fixed compromised-Agent smoke test
  drives a real Gateway process and real MCP v2 upstream: both read-only tasks complete, the induced
  unauthorized write creates no upstream effect, and Inspect receives only an opaque `credential_ref`.
  A fixed-target trusted process injects the temporary identity, which is absent from Inspect logs. This
  is deterministic gateway-path evidence, not real-model or unknown-attack quality evidence.
- Added a digest-pinned llama.cpp evaluation launcher and Inspect's pinned OpenAI-compatible client.
  The launcher itself starts the verified GGUF model on loopback and writes aggregate-only evidence;
  merely connecting to a claimed local endpoint can no longer be reported as real-model execution.
- Added an isolated, source-digest-pinned `llama-cpp-python 0.3.35` runtime and minimal loopback Qwen
  tool-call adapter. The verified Qwen3-4B Q4_K_M run completed 2/2 read-only tasks through the real
  Gateway and MCP v2 upstream with zero unauthorized upstream effects. The immutable v2 evidence pins
  the model, runtime, lock and implementation digests and is explicitly not a model-quality benchmark.
- Added AgentDojo `0.1.35` as an isolated evaluation dependency and froze the first `v1.2.2` unseen-set
  static run. Across 140 published template/goal attacks, rules detected 38, the shadow model 105,
  and their union 107 (76.43%); the model produced 9/97 false positives on legitimate tasks while
  rules produced none. The immutable aggregate-only evidence keeps the model in shadow mode.
- Added a content-addressed, repository-external loader for the official Microsoft BIPIA Email,
  Table, and Code test data. The first pre-tuning static holdout evaluated 13,750 context/attack
  combinations and 200 normal contexts: rules, shadow model, and union detected 491, 4,786, and
  5,264 attacks respectively; union false positives were 13/200. The immutable aggregate-only
  report proves the model is active but still not fit for enforcement. This is not a BIPIA response
  attack-success score or an Agent/tool end-to-end result.
- Reused the pinned official UIUC InjecAgent `base` tool responses as a new one-time static holdout.
  Across 1,054 attacks, rules detected 20, the shadow model 571, and their union 577 (54.74%);
  one of 17 matched clean response templates was flagged. Data-stealing union detection was 81.62%
  while direct-harm detection was 26.08%. The aggregate-only immutable report and one-way holdout
  record prove the model was active without promoting it to enforcement. This is not the official
  prompted-agent ASR or an end-to-end Gateway blocking score.
- Source-pinned and evaluated the Apache-2.0 ProtectAI DeBERTa prompt-injection model as a drop-in
  candidate after the holdout was known. It was rejected because union detection dropped to 25.92%,
  false positives rose to 20.00%, and CPU p95 rose to 490.56 ms. The immutable negative report
  prevents this known-bad candidate from being silently promoted or repeatedly reconsidered.
- Adapted Meta llama-cookbook's 512-token maximum-risk chunking into a benchmark-only probe while
  keeping the current Wolf Defender model. On a known 200-attack/200-benign BIPIA slice, union hits
  improved from 126 to 159, but false positives rose from 13 to 28 and model p95 reached 2328.22 ms.
  A separate aggregate threshold probe found no useful recall/false-positive operating region, so
  the design is explicitly rejected for production and both immutable reports are release-verified.
- Added a real-Qwen, real-Gateway, real-MCP adapted AgentDojo-template micro-suite. All seven
  previously unscored template attacks induced a real mutation attempt; deterministic intent
  authorization created seven approval gates and the controlled upstream observed zero effects.
  Rules quarantined 0/7, the shadow model flagged 7/7, and both benign controls completed without
  flags. The immutable aggregate-only report is explicitly not a full AgentDojo or statistically
  sufficient unknown-attack score.
- Added a reviewed, versioned managed scanner rule pack for the exposed AgentDojo
  `important_instructions` blind spot. The dedicated migration entrypoint applies Alembic and then
  installs the pack idempotently for Compose and Helm; database drift and ordinary API mutation or
  deletion fail closed. Post-finding regression detects 7/7 known attacks with 0/302 flags across
  public normal controls and is kept separate from blind results.
- Routed administrator-configurable scanner patterns through pinned `google-re2 1.1.20251105`, with
  a 4,096-character pattern limit and 8 MiB compilation-memory bound. Unsupported backtracking-only
  constructs fail at create, update, or migration time; a 100,000-character adversarial input is
  covered by regression tests.
- Preserved the original AgentDojo static and dynamic reports as historical evidence and added
  separate current-code regressions. Static results remain 107/140 union attack detections and
  9/97 union false positives. In the real-Qwen Gateway rerun, the deployed managed rule quarantined
  7/7 attack results before another model action, 2/2 benign reads completed, and upstream effects
  remained zero. These reused sets are explicitly not blind or full AgentDojo results.
- Re-ran the real-Qwen AgentDojo-derived micro-suite after adding Gateway provenance. The separate v3
  evidence retains 7/7 known-attack quarantines, 2/2 benign completions and zero unauthorized upstream
  effects while binding the report to the provenance-enabled Gateway implementation.
- Corrected the dynamic evidence boundary after finding that v3 locked only the Gateway entry file.
  The v4 rerun preserves the same 7/7, 2/2 and zero-effect results while expanding the immutable
  implementation map from 16 to 23 security-path files, including provenance and standard MCP adapters.
- Re-ran the same real-Qwen regression after adding signed, identity- and snapshot-bound pagination to
  standard MCP list operations. The separate v5 report keeps 7/7 known-attack quarantines, 2/2 benign
  completions and zero unauthorized upstream effects while binding the changed protocol implementation.
- Re-ran the real-Qwen regression again after protected resource templates and consistent restricted-Agent
  discovery/read controls changed the Gateway path. The v6 report retains 7/7 known-attack quarantines,
  2/2 benign completions, zero unauthorized upstream effects and the 23-file implementation lock.
- Preserved a v7 run that exposed unfixed generation variance at 5/7 attack reads instead of hiding
  it. Added temperature-zero, 512-token, seed-zero generation evidence, then ran unchanged v8 and v9
  repetitions. They are identical except for creation time and both retain 7/7 known-attack
  quarantines, 2/2 benign reads, zero unauthorized effects, and the 23-file implementation lock.
- Expanded the semantic classifier's continuous tool-result view from 512 to 1,024 characters after
  AgentThreatBench exposed missed medium-length instructions. Re-ran the managed-rule static corpus
  as v3 and the real-Qwen AgentDojo-derived path as v10; results remain 7/7 known attacks, 0/302
  normal rule hits, 2/2 benign dynamic reads, and zero unauthorized upstream effects. Older BIPIA and
  InjecAgent first-run reports are now explicitly historical evidence for their frozen implementation.
- Added an aggregate-only holdout registry with one-way first-run consumption, frozen-system matching,
  duplicate-corpus rejection, file locking and atomic updates. A claimed, failed, interrupted or
  report-less run remains regression data and cannot be presented as a second blind result.

### Verification and Remaining Gates

- Added a pinned `inspect-evals 0.16.0` AgentThreatBench dynamic regression across 19 attack and 5
  benign samples using the real local Qwen3-4B, real Gateway and standard MCP client. The current v6
  run paused state-changing calls for 5/5 autonomy-hijack attacks before upstream execution, executed
  zero high-risk actions in attack samples, retained benign autonomy utility without approval, and
  reached 17/19 effect security. One memory-poison response and one email response still echoed attack
  content, so the result is not reported as complete detection.
- Preserved all six AgentThreatBench reports: v1's disconnected zero-call false safety, v3's zero-
  utility over-quarantine, v4's action-classification omission, v5's narrow semantic window, and v6's
  bounded 1,024-character correction. The aggregate-only verifier locks the public corpus, model,
  runtime, privacy flags, historical failures, current metrics and security-path source hashes.

- Verified 649 Python tests at 82% statement coverage, 14 Dashboard tests and a production Dashboard
  build, real PostgreSQL/RQ/Redis crash recovery, real OpenBao Proxy identity rotation and revocation,
  signed OPA bundle acceptance and tamper rejection, official MCP client compatibility, and ToolHive
  runtime isolation.
- The fixed local release verifier now covers 44 checks, 18 benchmark artifacts, 15 Agent-evaluation
  artifacts and 3 supply-chain evidence files. The report retains all 10 external production gates and records that the
  evaluated worktree is dirty; local success is not treated as deployment evidence.
- Retained the fixed LLMail-Inject Phase 2 static-scan result: 92.80% detection across 21,007 labelled
  attacks, 95.73% across 3,165 attacks that induced API calls in the original challenge, and 0/203 false
  positives on the fixed normal set. These are static replay results, not a blind end-to-end blocking rate.
- Recorded the first AgentDojo-derived unseen static result separately: 76.43% union detection on 140
  attacks and 9.28% union false positives on 97 legitimate task prompts. It is not a full AgentDojo
  run or an end-to-end blocking result.
- Recorded the first adapted AgentDojo-template real-model dynamic result separately: 7/7 induced
  mutation attempts were blocked, 0 upstream effects occurred, the shadow scanner flagged 7/7,
  rules quarantined 0/7, and 2/2 benign reads completed without flags. Its sample size is too small
  to change the shadow-only deployment decision.
- Recorded the post-fix dynamic regression separately: the managed rule quarantined 7/7 attack
  results before another model action, 2/2 benign reads completed, and upstream effects remained 0.
  Because the rule was authored from this attack structure, this is regression rather than new
  generalization evidence.
- Production release still requires a real enterprise OIDC tenant, an external Object Lock bucket,
  signed private-registry images and full signature admission, the production Kubernetes CNI, an
  OpenTelemetry backend, production-scale failover/load tests, and a real Agent red-team exercise.
- Reused Sigstore policy-controller's standard `v1beta1` `ClusterImagePolicy` instead of building an
  admission webhook. Production Helm now requires enforce mode, repository-scoped image patterns,
  an exact non-wildcard OIDC signing identity, Fulcio, Rekor, and an administrator-managed
  `TrustRoot`. It rejects disabled verification, warning mode, empty/wildcard identities, and global
  image globs during rendering. The official `0.10.7` chart is configured with a digest-pinned
  `0.15.1` controller, two webhook replicas, fail-closed admission, and deny on no matching policy.
  A real kind run proved namespace opt-in, explicit unsigned rejection under the official `0.13.1`
  controller, all-replica outage rejection, managed TrustRoot readiness, 2/2 recovery in 20.442
  seconds, and registry-outage rejection under `0.15.1`. Correctly signed admission and the remaining
  signer/mutation/lookalike cases still require a reachable private registry and production rerun.
- Added production namespace default-deny isolation with native Kubernetes NetworkPolicy. Gateway and
  Dashboard now have separate ingress-controller paths, internal callers receive only exact service
  ports, and environment-specific egress must be declared per workload. Helm rejects disabled
  production isolation, missing destinations, empty selectors, all-address CIDRs, port ranges,
  invalid protocols, and unknown workload keys. A real Kubernetes `1.34.0` kindnet run applied the
  11 rendered policies and passed 23/23 normal/unauthorized probes, 11/11 policy deletion/restoration
  checks, and restricted Pod Security rejection. The production CNI and real external destinations
  remain unverified.
- Added separate zero-RBAC ServiceAccounts for every application workload and disabled automatic
  Kubernetes API token mounting on both accounts and Pods. The audit exporter retains its explicit
  platform workload identity without receiving a generic API token. Helm validation rejects missing
  workload identities and any Role, ClusterRole, or binding emitted by the application chart.
- Added a repository-external installer for pinned Keycloak `26.7.3` and Temurin JRE
  `21.0.12.1+1`, with archive/signature/public-key digest checks, exact signer fingerprints,
  detached-signature verification, bounded safe extraction, atomic installation, and overwrite
  refusal. A real loopback Keycloak check now covers workload issuance and binding, wrong
  issuer/audience, signature tampering, real token expiry, signing-key rotation, and client disable. It also records the
  honest limit that a previously issued 60-second offline JWT remains valid until expiry; generated
  secrets, tokens, claims, and service logs are excluded from reports.
- Added an offline identity-runtime provenance check that reverifies both detached signatures and
  proves that changing one byte in either Keycloak or Temurin archive is rejected. The result is not
  presented as signed-container or reproducible-build provenance.
- Bounded OIDC bearer tokens to 16 KiB and 15-minute signed lifetimes by default, and bounded
  workload subject, project, Agent, and scope claims before database or authorization use. Oversized
  tokens are rejected before JWKS retrieval; empty, duplicate, excessive, oversized, quoted,
  backslash-containing, or control-character scopes are rejected deterministically.

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
