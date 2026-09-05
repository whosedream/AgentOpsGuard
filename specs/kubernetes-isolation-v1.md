# Kubernetes isolation contract v1

## Purpose

Production starts with no Pod-to-Pod or Pod-to-external connectivity. Each required path is then
opened for one workload, one destination, and explicit ports. The chart uses the Kubernetes
`networking.k8s.io/v1` API instead of a custom network agent.

This contract is useful only on a cluster whose CNI actually enforces `NetworkPolicy`. An API server
accepting these objects is not proof that packets are blocked.

## Fixed internal paths

| Caller | Destination | Port | Reason |
| --- | --- | ---: | --- |
| reviewed ingress controller | Gateway | 8001/TCP | MCP endpoint |
| reviewed ingress controller | Dashboard | 3000/TCP | operator UI |
| Dashboard | API | 8000/TCP | server-side UI proxy |
| Gateway | API | 8000/TCP | control-plane decisions |
| Gateway | semantic scanner | configured scanner port | isolated shadow scan |
| API, Gateway, Worker | OPA | 8181/TCP | optional policy decision |
| application clients | selected cluster DNS Pods | 53/TCP+UDP | service discovery |

Semantic scanner and embedded OPA Pods are deliberately absent from the DNS policy and have no
external-egress policy. Their existing policies keep egress empty.

## Environment-owned external paths

Production operators must provide a non-empty `networkPolicy.externalEgress` list for API, Gateway,
Worker, outbox dispatcher, and migration. The audit-anchor exporter needs its own list when enabled.
Each rule uses standard `NetworkPolicyEgressRule` syntax, must name at least one destination and
individual numeric TCP/UDP ports, and may use a non-empty Pod selector, namespace selector, or IP
block. `0.0.0.0/0`, `::/0`, empty selectors, port ranges, and unknown workload keys are rejected.

These lists cover database, Redis, OIDC/JWKS, approved MCP upstreams, OpenBao, object storage, and
telemetry as applicable. Prefer namespace plus Pod selectors for in-cluster services. Standard
NetworkPolicy has no portable DNS-name egress rule; for outside services use controlled stable CIDRs
or a separately reviewed egress proxy/CNI extension and test the actual packet path.

## Namespace admission

Before deploying, label the application namespace for both Sigstore and Kubernetes Pod Security
Admission. Pin Pod Security versions to the target cluster minor rather than silently following
`latest`:

```bash
kubectl label namespace agentops-guard --overwrite \
  policy.sigstore.dev/include=true \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=<target-kubernetes-minor> \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/audit-version=<target-kubernetes-minor> \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/warn-version=<target-kubernetes-minor>
```

Do not copy the placeholder literally. First run the command with server-side dry-run against the
target cluster and review every existing Pod warning.

## Live acceptance

The external gate closes only after packet probes show:

1. the two reviewed ingress paths work and other ingress fails;
2. every fixed internal path above works and an unlisted cross-service path fails;
3. each external allowlist succeeds only from its assigned workload and port;
4. semantic scanner cannot reach DNS, API, database, OpenBao, object storage, or the internet;
5. OPA cannot make outbound connections;
6. a Pod violating the restricted Pod Security profile is rejected;
7. deleting each allow policy breaks only its intended path and restoration recovers it.

Record resource digests, selectors, destination ranges, CNI identity/version and aggregate probe
results. Do not record connection strings, authorization headers, tokens, request bodies, or model
content.

## Current live evidence

On 2026-09-05 the official kind `v0.30.0` and kubectl `v1.34.0` Linux AMD64 binaries matched their
upstream SHA-256 files. The release-published kind `v1.34.0` node index
`sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a` was copied through the
working Windows network path with checksum-verified `crane v0.21.9`; its Linux AMD64 child manifest
was independently matched before import. The first cluster attempt exposed a stale proxy from the
Docker client configuration inside the node. Re-running kind with a temporary empty `DOCKER_CONFIG`
removed proxy injection only for that test process and left the user's global Docker configuration
unchanged.

The resulting Kubernetes `v1.34.0` cluster ran kindnet
`v20250512-df8de77b`, whose DaemonSet was ready before probing. The runtime verifier applied the 11
`NetworkPolicy` objects rendered from the project Helm chart, not substitute test policies. It then
used a digest-recorded Redis `7.4.6` probe image with the same application labels and ports. All
`23/23` baseline probes passed: reviewed ingress and internal paths worked, unlisted paths failed,
API-only external egress worked, and the semantic scanner plus OPA had no DNS or external access.
All `11/11` policy-removal tests also passed: removing each allow or default-deny policy changed the
intended path, an unrelated control path stayed healthy, and restoration recovered the path. A
privileged Pod was rejected by `restricted:v1.34` Pod Security Admission.

The content-free evidence is
`artifacts/verification/kubernetes-isolation-live-v1.json`, SHA-256
`066e7b25b38e7da370cd4a541f223c43169db5543dd6dbdca41aaa4187f79cd4`. The fixed verifier re-renders
the current chart and requires the resource digests, all probe totals, CNI identity, Pod Security
rejection, and the artifact digest to match. This closes the local Kubernetes data-path and built-in
Pod Security proof. It does not prove Sigstore image admission, a private registry, production CNI,
cloud workload identity, or environment-owned database/OpenBao/telemetry routes.

## Kubernetes API identity

API, Gateway, Worker, outbox dispatcher, Dashboard, semantic scanner, OPA, and migration use separate
ServiceAccounts with no RBAC grants. Both each account and each Pod disable automatic service-account
token mounting. The audit exporter uses the administrator-selected cloud workload identity but also
disables the generic Kubernetes API token; a cloud-specific projected identity is an explicit
platform integration, not permission for the application to query the cluster API.
