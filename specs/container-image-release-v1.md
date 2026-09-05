# Container image release v1

Date: 2026-09-04

## Outcome

The repository defines a fail-closed release path for the Python application image and the Dashboard
image. It is designed so that a pull request, a non-default branch, a failed dependency audit, a
failed image scan, a changed artifact, or a mismatched signing identity cannot produce an image that
passes the production Sigstore admission policy.

This document describes implemented workflow behavior. It is not evidence that the GitHub-hosted
workflow, GHCR, or a Kubernetes admission controller has run successfully.

## Reused components

| Component | Pinned input | Purpose |
| --- | --- | --- |
| Docker login action | commit `b45d80f862d83dbcd57f89517bcf500b2ab88fb2` | trusted final-hop injection of the repository package token |
| Docker setup-buildx action | commit `d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5` | create the isolated BuildKit builder |
| Docker build-push action | commit `f9f3042f7e2789586610d6e8b85c8f03e5195baf` | build and push the two image indexes |
| Buildx | `v0.36.1`, Linux AMD64 SHA-256 `48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778` | client used by the build action |
| BuildKit | `moby/buildkit:v0.32.2@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8` | digest-pinned builder daemon with insecure entitlements disabled |
| Aqua setup-trivy action | immutable safe commit `3fb12ec12f41e471780db15c232d5dd185dcb514` | install the reviewed scanner without a repository token |
| Trivy | `v0.70.0`, Linux AMD64 executable SHA-256 `379d59f24a4a828c55de5f0b91b6805cc35d13580180b658820e648611256166` | create the image CycloneDX SBOM and gate fixable HIGH/CRITICAL findings |
| Sigstore Cosign installer | commit `6f9f17788090df1f26f669e9d70d6ae9567deba6` | download Cosign with the installer's built-in checksum check |
| Cosign | `v3.0.6`, Linux AMD64 SHA-256 `c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74` | keyless attestation, signing, and exact-identity verification |
| GitHub artifact transfer | upload commit `ea165f8d65b6e75b540449e92b4886f43607fa02`, download commit `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | pass only checked evidence and the checked signer binary; download digest mismatch is fatal |

The separate executable and daemon digests matter. Pinning an action commit alone does not prevent
that action from downloading a different tool later. This is especially important after the
[2026 Trivy supply-chain incident](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23).

## Flow and authority boundary

1. OSV, Python, and Dashboard dependency jobs run first. The image build matrix cannot start unless
   all three succeed.
2. The build matrix installs and verifies Buildx, Trivy, and Cosign before registry login. Tool
   installers therefore do not run while the package credential is present.
3. The application and Dashboard are built separately from default-deny contexts. Only a
   `sha-<commit>` tag is pushed; no `latest` tag is created.
4. BuildKit emits maximum-mode SLSA provenance. The workflow rejects provenance whose recorded VCS
   revision is not the triggering commit.
5. The checksum-pinned Trivy binary creates a CycloneDX image SBOM and scans the exact pushed digest.
   Fixable HIGH or CRITICAL findings fail the matrix. A failed scan can leave an unsigned commit tag,
   but production admission cannot accept it.
6. The build matrix has no `id-token: write` permission. After both matrix entries succeed, it sends
   the repository, revision, digest, provenance, SBOM, and checksum-pinned Cosign binary through a
   digest-checked GitHub artifact.
7. The signer matrix has the only OIDC signing permission. It does not check out or execute project
   code. It rechecks the repository name, commit, digest format, artifact transport digest, and Cosign
   executable digest before registry login.
8. Cosign keylessly signs the SLSA predicate, CycloneDX predicate, and exact image digest. It then
   verifies all three against the exact repository workflow path and default-branch ref.

The actual `GITHUB_TOKEN` value is passed only to the pinned Docker login action. Shell commands,
reports, artifact names, URLs, and model-visible data contain no credential value. Cosign obtains a
short-lived GitHub OIDC identity inside the trusted signing process; there is no stored signing key.

## Fail-closed cases

| Failure | Result |
| --- | --- |
| Pull request or non-default branch | image build and signing jobs are skipped |
| Any dependency audit fails | no image build starts |
| Buildx, Trivy, or Cosign checksum changes | failure occurs before the affected tool can use registry credentials |
| BuildKit daemon image changes under its tag | pinned digest still selects the reviewed image |
| Provenance records another revision | scan and signing are skipped |
| Image has a fixable HIGH/CRITICAL finding | report is retained; no signature is produced |
| One of the two images fails | signer job does not start for either image |
| Transferred release input changes | download digest or subject validation fails |
| Cosign issuer, workflow path, repository, branch, or image digest differs | verification fails and the workflow remains red |
| Signature exists but cluster policy-controller is unavailable | production webhook is configured to fail closed; live proof is still required |

## Evidence required to clear the external gate

- Protect the default branch and require CI plus Supply chain checks before merge.
- Run the workflow on that default branch and retain the successful run URL and immutable run ID.
- Record both image digests and the public signing identity; never retain registry credentials.
- Download the scan, provenance, SBOM, and Cosign verification artifacts and verify their GitHub
  artifact digests.
- Configure Helm with those image digests, repository globs, issuer, and exact
  `.github/workflows/supply-chain.yml@refs/heads/<default-branch>` subject.
- In a real pre-production cluster, admit the correct signed digests and reject an unsigned image, a
  different signer, changed bytes, a lookalike repository, and a webhook outage.

GitHub's native artifact attestation action is not a baseline dependency because private/internal
repository support requires GitHub Enterprise Cloud. Organizations that have that plan may add it as
an additional record; the portable BuildKit plus Cosign proof remains required.

## Current evidence boundary

- Local workflow structure, immutable-action, permission separation, digest, order, negative Helm,
  and documentation checks pass.
- The official Trivy `0.70.0` release archive checksum and extracted executable checksum were compared
  locally before fixing the executable digest in the workflow.
- Local application and Dashboard builds reached their locked dependency-download steps, then were
  stopped after the existing WSL network path made no progress.
- No GitHub-hosted run, GHCR image scan, keyless image signature, signed attestation, or live
  Kubernetes admission result exists yet. Those claims remain external release gates.

Primary references: [Docker provenance](https://docs.docker.com/build/metadata/attestations/slsa-provenance/),
[Trivy SBOM attestation](https://github.com/aquasecurity/trivy/blob/main/docs/guide/supply-chain/attestation/sbom.md),
[Cosign attest](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md), and
[Sigstore policy-controller](https://docs.sigstore.dev/policy-controller/overview/).
