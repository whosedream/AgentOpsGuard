# OPA Current Runtime and Remote Bundle Verification v1

## Scope

This evidence checks two previously separate gaps with the real Open Policy Agent runtime:

1. the checked-in Rego policies run on OPA `1.20.1` for Linux/amd64;
2. two OPA processes fetch signed policy bundles over the Bundle Service API, report activation
   independently through the Status API, and retain the last good revision when the publisher serves
   a tampered bundle or is unavailable;
3. one process restarts while the publisher is unavailable and serves the persisted last-good policy
   before both processes recover normal polling.

It is a local subsystem run. It is not a production control-plane, Kubernetes, TLS, workload
identity, private-registry, high-availability, or enterprise key-custody result.

## Runtime provenance

- Upstream: <https://github.com/open-policy-agent/opa>
- Release: `v1.20.1`
- Asset: `opa_linux_amd64_static`
- SHA-256: `0b3f152e61be276b70396cfbca49e39fc9d0c5089e0a8574e8f6a30f41a9187f`
- Build timestamp reported by the binary: `2026-08-28T07:25:34Z`

The binary and its `.sha256` file are downloaded from the same immutable GitHub release. The
repository pins the reviewed digest in both the installer and verifier. This detects accidental or
later byte changes, but it is not a GitHub artifact-attestation or an organization-approved image
signature. Production must mirror and verify an approved digest/signature independently.

The 61.6 MB runtime is deliberately not committed to Git. It is installed outside the repository at
`~/.local/share/agentops-guard/opa/1.20.1/opa`, mode `0500`, using:

```text
uv run python scripts/install_opa_current_runtime.py \
  --binary <downloaded-opa_linux_amd64_static> \
  --checksum-file <downloaded-opa_linux_amd64_static.sha256>
```

The installer checks the reviewed digest, checksum-file digest and asset name, copies atomically,
sets the executable read-only, then asks the installed binary to report exactly `1.20.1`.

## Real runtime flow

`scripts/verify_opa_remote_bundle.py` performs the following with loopback-only listeners:

1. creates a temporary RSA publishing key and a separate public verification key;
2. uses OPA `1.20.1` to build signed v1 and v2 bundles from the production Rego files;
3. starts a temporary Bundle Service and Status API receiver;
4. starts two real OPA processes with separate runtime directories containing only JSON config and
   the public key;
5. verifies signed v1 activation and separate status identities, then a signed v2 hot update on both;
6. serves a v2 archive changed after signing and waits for the Status API error;
7. verifies decisions still come from v2 and subsequent fetches carry v2's last successful ETag;
8. returns `503` from the publisher and verifies v2 remains active on both processes;
9. restarts one process during the outage, verifies it loads persisted v2, restores the publisher,
   and checks conditional fetch plus healthy bundle/plugin status on both processes;
10. removes all temporary runtime material and processes.

The emitted aggregate result does not contain bundle bytes, policy/status bodies, the private key,
requests, environment values, or model content.

## Observed result

- signed v1 activated on two processes: pass;
- signed v2 hot update activated on two processes: pass;
- distinct v1 and v2 status callbacks from both processes observed: pass;
- changed-after-signing replacement rejected while both kept v2: pass;
- retries used the last successful v2 ETag: pass;
- publisher outage retained v2 on both processes: pass;
- one process restarted during outage and loaded persisted v2: pass;
- publisher recovery and conditional fetch on both processes: pass;
- runtime directory and config contained no private key: pass;
- pinned binary digest/version and non-root execution: pass.

The existing `scripts/verify_opa_runtime.py` remains a separate check on the digest-pinned official
OPA `1.8.0` container. It covers non-root image configuration, read-only root, dropped Linux
capabilities, no-new-privileges, read-only policy mount, loopback exposure, local signed-bundle
verification, real policy decisions, deterministic-policy precedence, and failure-mode behavior.
Those container-hardening results must not be attributed to the host `1.20.1` process.

## Remaining production gate

OPA's official bundle documentation states that the signature `iat` and `iss` claims are informational
and unused during verification. AgentOps Guard therefore does not claim native signed-bundle expiry.
Production clients pin `AGENTOPS_OPA_EXPECTED_POLICY_REVISION` and fail conservatively if a healthy OPA
serves another validly signed revision; the release control plane remains responsible for selecting
and approving that exact revision.

The combined production OPA gate stays open until the same behavior is shown with an approved,
signature-verified `1.20.1` image in the target environment and a remote publisher that uses TLS,
workload identity, enterprise signing-key custody, production replicas and real alert delivery. A
loopback HTTP fixture proves OPA semantics, not production operations.
