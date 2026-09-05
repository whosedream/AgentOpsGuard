# Production image admission

AgentOps Guard reuses Sigstore policy-controller instead of implementing an image-signature
webhook. The application chart renders a standard `policy.sigstore.dev/v1beta1`
`ClusterImagePolicy` and production values fail unless the approved repository scope, OIDC issuer,
and exact signing identity are provided.

The tested configuration target is the official policy-controller Helm chart `0.10.7`, with the
controller overridden to the official `v0.15.1` image index digest and the cleanup image pinned by
digest in `policy-controller-values.prod.yaml`. The production values disable the controller's
built-in network TUF refresh: an administrator must create a reviewed, public-key-only Sigstore
`TrustRoot` and wait for it to become Ready before enabling the application policy. Before
installing, mirror the chart and both pinned images into the approved registry if the cluster cannot
reach their public registries, and review the upstream release and security advisories.

```bash
helm upgrade --install policy-controller \
  oci://ghcr.io/sigstore/helm-charts/policy-controller \
  --version 0.10.7 \
  --namespace cosign-system \
  --create-namespace \
  --atomic \
  --values deploy/admission/policy-controller-values.prod.yaml
```

The controller is opt-in by namespace. Label the application namespace before deploying the first
workload and verify that both the mutating and validating webhooks use `failurePolicy: Fail`:

```bash
kubectl label namespace agentops-guard policy.sigstore.dev/include=true --overwrite
kubectl get mutatingwebhookconfiguration,validatingwebhookconfiguration -o yaml
```

Supply the public signing identity through an environment-specific values file. The identity is not
a credential, but it must be exact: wildcard and regular-expression identities are rejected by the
chart. Keep registry credentials in `imagePullSecrets`; do not place them in these fields.

```yaml
imageVerification:
  trustRootRef: agentops-public-sigstore
  imageGlobs:
    - registry.example/security/agentops-guard@sha256:*
    - registry.example/security/agentops-guard-dashboard@sha256:*
  keyless:
    issuer: https://token.actions.githubusercontent.com
    subject: https://github.com/example/agentops-guard/.github/workflows/supply-chain.yml@refs/heads/main
```

The repository workflow publishes only from the repository's default branch. Its release job builds
the Python and Dashboard images separately, pushes only a commit-addressed tag, attaches BuildKit
SLSA provenance, and uses a separately digest-pinned Trivy binary to generate a CycloneDX image SBOM
and scan the exact digest. Cosign signs both attestations and the digest with a short-lived GitHub
OIDC identity, then verifies them against this exact workflow path and branch. Set the production
subject to that path and the real default branch; do not copy the example owner. A failed scan can
leave an unsigned commit-addressed image in the registry, but it cannot pass
the signature admission policy and no mutable `latest` tag is published.

The build/scan matrix has no OIDC signing permission. Only a following signer matrix receives that
permission after every image succeeds; it does not check out or execute project code, revalidates the
repository, revision and digest, and executes a checksum-pinned Cosign binary transferred through an
artifact whose transport digest is enforced. The registry token is injected only into the pinned
Docker login action and is never placed in a command argument or retained as evidence.

The local kind test has already proved the namespace opt-in, both webhooks using `failurePolicy:
Fail`, `no-match-policy: deny`, an unsigned matching digest being rejected by the official `0.13.1`
controller as having no signature, and the API rejecting new opted-in Pods while all controller
replicas were stopped. The upgraded `0.15.1` controller consumed an administrator-managed Ready
`TrustRoot`, recovered to 2/2 replicas in 20.442 seconds with no restart, and also failed closed when
the public registry was unreachable. The fixed content-free evidence is checked by
`scripts/verify_sigstore_admission_artifact.py`.

This is partial evidence, not production acceptance. A reachable private registry and release
images are still required to admit a correctly signed digest and prove that an unsigned image, a
different signer, a post-signing mutation, and a lookalike repository are rejected under the final
`0.15.1` configuration. Repeat the all-replicas-stopped test in pre-production. Save only the image
digest, public signer identity, policy version, decision, and timestamps; never save registry
credentials.
