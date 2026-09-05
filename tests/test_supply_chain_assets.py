import json
from pathlib import Path
import re
from runpy import run_path


normalize_sbom = run_path("scripts/generate_python_sbom.py")["normalize_sbom"]


def _object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def test_supply_chain_workflow_fails_closed_and_emits_a_standard_sbom():
    workflow = Path(".github/workflows/supply-chain.yml").read_text(encoding="utf-8")

    assert "uv sync --locked --no-dev --extra semantic --no-install-project" in workflow
    assert "pip-audit==2.10.1" in workflow
    assert "pip-audit --strict" in workflow
    assert "sysconfig.get_path" in workflow
    assert ".venv/lib/python3.12/site-packages" not in workflow
    assert "scripts/generate_python_sbom.py" in workflow
    assert "scripts/generate_dashboard_sbom.py" in workflow
    assert "cyclonedx-bom" not in workflow
    assert "npm audit --omit=dev --audit-level=high" in workflow
    assert (
        "google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@"
        "0c58c542420dfd23fcac08dd9c8ca3cca9c36f1a"
    ) in workflow
    assert "--lockfile=./uv.lock" in workflow
    assert "--lockfile=./dashboard/package-lock.json" in workflow
    assert "upload-sarif: false" in workflow
    assert "fail-on-vuln: true" in workflow
    assert "continue-on-error" not in workflow


def test_release_images_are_digest_scanned_attested_and_keylessly_signed():
    workflow = Path(".github/workflows/supply-chain.yml").read_text(encoding="utf-8")

    assert "github.event_name != 'pull_request'" in workflow
    assert (
        "github.ref == format('refs/heads/{0}', "
        "github.event.repository.default_branch)"
    ) in workflow
    assert "id-token: write" in workflow
    assert "packages: write" in workflow
    assert "ubuntu-24.04" in workflow
    assert "needs: [osv-lockfiles, dependency-evidence, dashboard-dependencies]" in workflow
    assert "needs: [build-scan-images]" in workflow
    assert "image_suffix: -dashboard" in workflow
    assert 'image_repository="ghcr.io/${REPOSITORY,,}${IMAGE_SUFFIX}"' in workflow
    assert 'echo "tag=$image_repository:sha-$GITHUB_SHA"' in workflow
    assert ":latest" not in workflow

    expected_actions = {
        "docker/login-action@b45d80f862d83dbcd57f89517bcf500b2ab88fb2",
        "docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5",
        "docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf",
        "aquasecurity/setup-trivy@3fb12ec12f41e471780db15c232d5dd185dcb514",
        "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    }
    assert all(action in workflow for action in expected_actions)
    assert "password: ${{ secrets.GITHUB_TOKEN }}" in workflow
    assert workflow.count("${{ secrets.") == 2
    assert 'github-token: ""' in workflow
    assert 'token: ""' in workflow
    build_job, sign_job = workflow.split("\n  sign-images:\n", 1)
    assert "id-token: write" not in build_job
    assert "id-token: write" in sign_job
    assert workflow.count("id-token: write") == 1
    assert "actions/checkout@" not in sign_job
    assert "digest-mismatch: error" in sign_job

    assert "BUILDX_GIT_CHECK_DIRTY" in workflow
    assert "BUILDX_GIT_LABELS: full" in workflow
    assert "version: v0.36.1" in workflow
    assert "48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778" in workflow
    assert (
        "moby/buildkit:v0.32.2@sha256:"
        "28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
    ) in workflow
    assert "buildkitd-flags: --oci-worker-gc=true" in workflow
    assert "cache-binary: false" in workflow
    assert "allow-insecure-entitlement" not in workflow
    assert "push: true" in workflow
    assert "provenance: mode=max" in workflow
    assert "build-args:" not in workflow
    assert workflow.count("docker buildx imagetools inspect") == 1
    assert "vcs.revision == $revision" in workflow
    assert "379d59f24a4a828c55de5f0b91b6805cc35d13580180b658820e648611256166" in workflow
    assert 'test "$(trivy --version' in workflow
    assert "trivy image --timeout 10m --format cyclonedx" in workflow
    assert '.bomFormat == "CycloneDX"' in workflow

    assert workflow.count("IMAGE_DIGEST: ${{ steps.build.outputs.digest }}") == 3
    assert workflow.count("IMAGE_DIGEST: ${{ steps.subject.outputs.digest }}") == 2
    assert 'image="$IMAGE_REPOSITORY@$IMAGE_DIGEST"' in workflow
    assert "--scanners vuln --severity HIGH,CRITICAL" in workflow
    assert "--ignore-unfixed --exit-code 1 --format json" in workflow
    assert "version: v0.70.0" in workflow

    assert '"$input_dir/cosign" attest --yes --type slsaprovenance02' in workflow
    assert '"$input_dir/cosign" attest --yes --type cyclonedx' in workflow
    assert '"$input_dir/cosign" sign --yes "$image"' in workflow
    assert "c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74" in workflow
    assert "--certificate-identity \"$CERTIFICATE_IDENTITY\"" in workflow
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in workflow
    assert workflow.count('"$input_dir/cosign" verify-attestation') == 2
    assert "supply-chain.yml@${{ github.ref }}" in workflow
    assert workflow.index("Build and push the commit-addressed image") < workflow.index(
        "Generate the image SBOM and scan the exact digest"
    ) < workflow.index("Sign the exact attestations and image digest")
    assert workflow.index("Verify the pinned Buildx executable") < workflow.index(
        "Log in to the repository package registry"
    )
    assert workflow.index("Verify the pinned Trivy executable") < workflow.index(
        "Log in to the repository package registry"
    )
    assert workflow.index("Verify the pinned Cosign executable") < workflow.index(
        "Log in to the repository package registry"
    )

    ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in ci
    assert "uv sync --locked --extra dev" in ci
    assert "uv sync --locked --no-dev --extra semantic" in dockerfile
    assert "uv sync --locked --no-dev --extra semantic --no-install-project" in dockerfile
    assert "uv sync --locked --no-dev --extra semantic --offline" in dockerfile
    assert dockerfile.index("--no-install-project") < dockerfile.index("COPY src ./src")
    assert dockerfile.index("COPY src ./src") < dockerfile.index("--offline")


def test_production_chart_has_separate_application_and_dashboard_images():
    values = Path("deploy/helm/agentops-guard/values.yaml").read_text(encoding="utf-8")
    dashboard = Path(
        "deploy/helm/agentops-guard/templates/deployment-dashboard.yaml"
    ).read_text(encoding="utf-8")

    assert "dashboardImage:" in values
    assert 'include "agentops-guard.dashboardImage"' in dashboard
    assert 'command: ["npm", "run", "start"]' not in dashboard


def test_default_opa_runtime_tracks_reviewed_current_release():
    values = Path("deploy/helm/agentops-guard/values.yaml").read_text(encoding="utf-8")
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")

    assert "tag: 1.20.1-debug" in values
    assert "openpolicyagent/opa:1.20.1-debug" in compose


def test_docker_build_contexts_are_strict_allowlists():
    root = Path(".dockerignore").read_text(encoding="utf-8").splitlines()
    dashboard = Path("dashboard/.dockerignore").read_text(encoding="utf-8").splitlines()

    assert root[0] == "*"
    assert dashboard[0] == "*"
    assert set(root[1:]) == {
        "!README.md",
        "!alembic.ini",
        "!pyproject.toml",
        "!uv.lock",
        "!src",
        "!src/**",
        "!policies",
        "!policies/**",
        "!alembic",
        "!alembic/**",
    }
    assert set(dashboard[1:]) == {
        "!package.json",
        "!package-lock.json",
        "!app",
        "!app/**",
        "!components",
        "!components/**",
        "!lib",
        "!lib/**",
        "!next-env.d.ts",
        "!next.config.js",
        "!postcss.config.js",
        "!tailwind.config.ts",
        "!tsconfig.json",
    }


def test_dependabot_tracks_every_release_dependency_surface():
    config = Path(".github/dependabot.yml").read_text(encoding="utf-8")

    assert "package-ecosystem: uv" in config
    assert "package-ecosystem: npm" in config
    assert config.count("package-ecosystem: docker") == 2
    assert "package-ecosystem: github-actions" in config
    assert "directory: /dashboard" in config


def test_github_actions_are_immutable_and_checkout_does_not_keep_credentials():
    workflows = [
        Path(".github/workflows/ci.yml").read_text(encoding="utf-8"),
        Path(".github/workflows/supply-chain.yml").read_text(encoding="utf-8"),
    ]
    actions = [
        line.strip().split(" #", 1)[0].removeprefix("- ").removeprefix("uses: ")
        for workflow in workflows
        for line in workflow.splitlines()
        if line.strip().startswith(("- uses:", "uses:"))
    ]

    assert actions
    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) for action in actions)
    assert sum(workflow.count("persist-credentials: false") for workflow in workflows) == 5
    assert all('version: "0.12.1"' in workflow for workflow in workflows)
    assert all('python-version: "3.12"' in workflow for workflow in workflows)
    assert all("node-version: 22.23.2" in workflow for workflow in workflows)


def test_sbom_normalization_removes_time_variance_and_binds_the_lockfile():
    original = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "urn:uuid:random",
        "metadata": {"timestamp": "2026-09-04T00:00:00Z"},
        "components": [{"bom-ref": "b"}, {"bom-ref": "a"}],
        "dependencies": [{"ref": "b", "dependsOn": ["z", "a"]}, {"ref": "a"}],
    }

    first = normalize_sbom(original, lock_digest="a" * 64)
    second = normalize_sbom(
        {**original, "serialNumber": "urn:uuid:other"}, lock_digest="a" * 64
    )

    assert first == second
    assert "timestamp" not in first["metadata"]
    assert first["serialNumber"].startswith("urn:uuid:")
    assert first["metadata"]["properties"] == [
        {"name": "agentops:uv_lock_sha256", "value": "a" * 64}
    ]
    assert [item["bom-ref"] for item in first["components"]] == ["a", "b"]
    assert first["dependencies"][1]["dependsOn"] == ["a", "z"]


def test_dashboard_manifest_has_one_identity_and_no_duplicate_dependencies():
    package = json.loads(
        Path("dashboard/package.json").read_text(encoding="utf-8"),
        object_pairs_hook=_object_without_duplicates,
    )
    lock = json.loads(Path("dashboard/package-lock.json").read_text(encoding="utf-8"))

    assert package["name"] == "agentops-guard-dashboard"
    assert package["version"] == "0.1.0"
    assert package["private"] is True
    assert package["dependencies"]["lucide-react"] == "^1.14.0"
    assert lock["name"] == package["name"]
    assert lock["version"] == package["version"]
    assert lock["packages"][""]["name"] == package["name"]
    assert lock["packages"][""]["version"] == package["version"]
