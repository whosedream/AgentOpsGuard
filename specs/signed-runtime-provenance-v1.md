# Signed Runtime Provenance Verification v1

## Scope

This local supply-chain check proves that the installed Linux/amd64 Cosign `3.1.2` runtime and the
OpenTelemetry Collector Contrib `0.160.0` release archive match reviewed upstream release assets and
valid Sigstore identities. It runs entirely from pinned material after installation and therefore
does not depend on live Sigstore or GitHub availability during a release check.

It does not prove that an AgentOps container image was signed, admitted by Kubernetes, built by the
checked-in workflow, or stored in an approved private registry.

## Trust bootstrap

- Cosign release: <https://github.com/sigstore/cosign/releases/tag/v3.1.2>
- Linux binary SHA-256:
  `f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf`
- Linux Sigstore bundle SHA-256:
  `fdaa1c168d67041cd0d8f5782f8136ac5d148827b6911ba8bb577cbc7e13de2c`
- Artifact-key bundle SHA-256:
  `5a16755e5fd4c048527f26bf0fb4c8c9731fca3cf35156b945aa222d220ca7ef`
- TUF-published artifact public-key SHA-256:
  `59ebf97a9850aecec4bc39c1f5c1dc46e6490a6b5fd2a6cacdcac0c3a6fc4cbf`
- Exact certificate identity: `keyless@projectsigstore.iam.gserviceaccount.com`
- Exact OIDC issuer: `https://accounts.google.com`

The WSL network could not reach Sigstore TUF. A Windows/amd64 Cosign `3.1.2` binary whose SHA-256
matched the digest displayed by the official GitHub release page refreshed the public Sigstore
trusted root. The TUF target metadata bound `artifact.pub` to its expected length and SHA-256; the
matching public key and artifact-key bundle were downloaded. Before executing the Linux binary,
the installer parses the bundle with duplicate-key rejection, confirms its embedded SHA-256, and
uses the independent P-256 public key to verify the ECDSA signature. The now-verified Linux binary
then validates the artifact-key bundle's transparency proof and separately verifies its identity
bundle using the exact official identity and issuer. The reviewed trusted-root snapshot is pinned by
SHA-256 `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`; root rotation is a
deliberate dependency update, not an unreviewed network fetch during release.

`scripts/install_cosign_current_runtime.py` validates all five source digests, the independent
artifact-key signature, exact version/platform, certificate identity, issuer and transparency-log
proof before atomically installing the executable outside Git with mode `0500` and verification
material with mode `0400`.

## Collector release proof

- Release: <https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.160.0>
- Archive SHA-256:
  `7bb60c584c241c86261c2b8697cd3725dd8c56691f5ad5d98454eaa005b47b0c`
- Sigstore bundle SHA-256:
  `337558f73b8bc9d6814ea66203e6e863822e40ac719f3af60ecb0be11de48f8a`
- Extracted binary SHA-256:
  `8524ac54f6e1d4d00d9ba5eea91daadec2ebc31e4da80db9c17eba2e859ecdd4`
- Exact certificate identity:
  `https://github.com/open-telemetry/opentelemetry-collector-releases/.github/workflows/base-release.yaml@refs/tags/v0.160.0`
- Exact OIDC issuer: `https://token.actions.githubusercontent.com`

`scripts/install_otelcol_current_runtime.py` now requires the checksum, Sigstore bundle, pinned
Cosign and pinned trusted root. It verifies the signature before extraction and retains read-only
release material beside the installed runtime so later release checks can repeat the proof.

`scripts/verify_otelcol_release_signature.py` verifies both releases offline, compares the binary
inside the signed archive with the installed Collector, flips one byte in a temporary archive and
requires Cosign to reject it. The verifier suppresses tool output and reports only fixed versions,
boolean checks and limitations; it does not store artifact, certificate or environment contents.

## Observed result

- Cosign digest, independent artifact-key signature, version, platform, identity, issuer and both
  transparency proofs: pass;
- Collector archive digest, identity, issuer and signature: pass;
- installed Collector matches the signed archive: pass;
- transparency-log proofs validated from pinned trusted material: pass;
- one-byte Collector archive mutation rejected: pass.

## Remaining production gate

The signed-private-registry and successful-supply-chain-workflow gates remain open. They require an
AgentOps image built by the actual hosted workflow, SBOM/provenance attached to its immutable digest,
signature verification against the approved workload identity, storage in the target private
registry, and positive/negative admission tests in a real Kubernetes cluster.
