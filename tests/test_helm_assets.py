from pathlib import Path
import shutil
import subprocess

from runpy import run_path

import pytest
import yaml


def test_SPEC_P2_004_helm_chart_assets_exist():
    base = Path("deploy/helm/agentops-guard")
    expected = [
        base / "Chart.yaml",
        base / "values.yaml",
        base / "values.local-like.yaml",
        base / "values.staging.yaml",
        base / "values.prod.yaml",
        base / "templates" / "_helpers.tpl",
        base / "templates" / "configmap.yaml",
        base / "templates" / "configmap-openbao-proxy.yaml",
        base / "templates" / "service-api.yaml",
        base / "templates" / "service-gateway.yaml",
        base / "templates" / "service-dashboard.yaml",
        base / "templates" / "service-semantic-scanner.yaml",
        base / "templates" / "serviceaccounts.yaml",
        base / "templates" / "ingress.yaml",
        base / "templates" / "deployment-api.yaml",
        base / "templates" / "deployment-gateway.yaml",
        base / "templates" / "deployment-worker.yaml",
        base / "templates" / "deployment-outbox-dispatcher.yaml",
        base / "templates" / "deployment-audit-anchor-exporter.yaml",
        base / "templates" / "deployment-dashboard.yaml",
        base / "templates" / "deployment-semantic-scanner.yaml",
        base / "templates" / "networkpolicy-semantic-scanner.yaml",
        base / "templates" / "job-migration.yaml",
        base / "templates" / "configmap-opa.yaml",
        base / "templates" / "deployment-opa.yaml",
        base / "templates" / "service-opa.yaml",
        base / "templates" / "networkpolicy-opa.yaml",
        base / "templates" / "networkpolicy-default-deny.yaml",
        base / "templates" / "clusterimagepolicy.yaml",
        base / "files" / "dangerous_command.rego",
        base / "files" / "decision.rego",
        Path("deploy/openbao/agentops-audit-signing-policy.hcl"),
        Path("deploy/openbao/agentops-audit-export-policy.hcl"),
        Path("deploy/openbao/agentops-api-policy.hcl"),
        Path("deploy/openbao/agentops-api-identity-delivery-policy.hcl"),
        Path("deploy/openbao/agentops-audit-export-identity-delivery-policy.hcl"),
        Path("deploy/admission/policy-controller-values.prod.yaml"),
        Path("deploy/admission/README.md"),
    ]
    missing = [str(path) for path in expected if not path.exists()]
    assert not missing, f"missing helm assets: {missing}"


def test_validate_helm_assets_script_exists():
    assert Path("scripts/validate_helm_assets.py").exists()


def test_helm_template_check_script_exists():
    assert Path("scripts/helm_template_check.ps1").exists()


def test_cross_platform_helm_template_check_script_exists():
    assert Path("scripts/helm_template_check.py").exists()


def test_credential_encryption_key_is_mounted_only_into_the_api_deployment():
    templates = Path("deploy/helm/agentops-guard/templates")
    marker = "AGENTOPS_CREDENTIAL_ENCRYPTION_KEY"

    assert marker in (templates / "deployment-api.yaml").read_text(encoding="utf-8")
    for name in (
        "deployment-gateway.yaml",
        "deployment-worker.yaml",
        "deployment-outbox-dispatcher.yaml",
        "deployment-audit-anchor-exporter.yaml",
        "deployment-dashboard.yaml",
        "deployment-semantic-scanner.yaml",
        "job-migration.yaml",
    ):
        assert marker not in (templates / name).read_text(encoding="utf-8")


def test_invocation_key_is_separate_and_only_gateway_worker_receive_it():
    templates = Path("deploy/helm/agentops-guard/templates")
    marker = "AGENTOPS_INVOCATION_ENCRYPTION_KEY"
    for path in templates.glob("*.yaml"):
        if path.name in {"deployment-gateway.yaml", "deployment-worker.yaml"}:
            assert marker in path.read_text()
        else:
            assert marker not in path.read_text()
    policy = (templates / "networkpolicy-semantic-scanner.yaml").read_text()
    assert "app: agentops-guard-worker" in policy
    assert "-worker-scanner-egress" in (templates / "networkpolicy-default-deny.yaml").read_text()


@pytest.mark.parametrize("mode", ["shadow", "disabled"])
@pytest.mark.parametrize("proxy", [False, True])
def test_rendered_worker_and_gateway_use_same_semantic_configuration(mode, proxy):
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("Helm is required for the rendered deployment test")
    command = [helm, "template", "agentops-guard", "deploy/helm/agentops-guard",
        "-f", "deploy/helm/agentops-guard/values.local-like.yaml",
        "--set", "runtimeSecret.existingSecret=test-runtime",
        "--set-string", "semanticScanner.modelSha256=" + "a" * 64,
        "--set", "semanticScanner.existingClaim=test-model-volume",
        "--set", f"semanticScanner.mode={mode}",
        "--set", "semanticScanner.threshold=0.94",
        "--set", f"gatewayProxy.enabled={str(proxy).lower()}"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    documents = {doc["metadata"]["name"]: doc for doc in yaml.safe_load_all(result.stdout)
                 if doc and doc["kind"] == "Deployment"}
    environments = []
    for name in ("agentops-guard-worker", "agentops-guard-gateway"):
        env = documents[name]["spec"]["template"]["spec"]["containers"][0]["env"]
        environments.append({item["name"]: item["value"] for item in env if item["name"].startswith("AGENTOPS_SEMANTIC_")})
    assert environments[0] == environments[1]
    assert environments[0]["AGENTOPS_SEMANTIC_SCANNER_MODE"] == mode
    assert environments[0]["AGENTOPS_SEMANTIC_SCANNER_THRESHOLD"] == "0.94"
    if mode == "disabled":
        assert "AGENTOPS_SEMANTIC_SERVICE_URL" not in environments[0]
    else:
        target = "gateway-proxy" if proxy else "semantic-scanner"
        assert target in environments[0]["AGENTOPS_SEMANTIC_SERVICE_URL"]


def test_openbao_authentication_is_limited_to_api_and_read_only_exporter():
    templates = Path("deploy/helm/agentops-guard/templates")
    token_marker = "AGENTOPS_OPENBAO_TOKEN"
    secret_file_marker = "AGENTOPS_OPENBAO_APPROLE_SECRET_ID_FILE"

    api = (templates / "deployment-api.yaml").read_text(encoding="utf-8")
    assert token_marker in api
    assert secret_file_marker in api
    exporter = (templates / "deployment-audit-anchor-exporter.yaml").read_text(encoding="utf-8")
    assert token_marker not in exporter
    assert secret_file_marker not in exporter
    assert "value: proxy" in exporter
    assert "name: openbao-proxy" in exporter
    assert "path: wrapped-secret-id" in exporter
    assert ".Values.auditAnchorExporter.openbaoExistingSecret" in exporter
    for name in (
        "deployment-gateway.yaml",
        "deployment-worker.yaml",
        "deployment-outbox-dispatcher.yaml",
        "deployment-dashboard.yaml",
        "deployment-semantic-scanner.yaml",
        "job-migration.yaml",
    ):
        content = (templates / name).read_text(encoding="utf-8")
        assert token_marker not in content
        assert secret_file_marker not in content


def test_chart_references_precreated_runtime_secret_with_least_privilege():
    templates = Path("deploy/helm/agentops-guard/templates")
    assert not (templates / "secret.yaml").exists()
    expected = {
        "deployment-api.yaml": {
            "AGENTOPS_DATABASE_URL",
            "AGENTOPS_REDIS_URL",
            "AGENTOPS_API_KEY",
            "AGENTOPS_OPERATOR_API_KEY",
        },
        "deployment-gateway.yaml": {
            "AGENTOPS_DATABASE_URL",
            "AGENTOPS_REDIS_URL",
            "AGENTOPS_API_KEY",
        },
        "deployment-worker.yaml": {"AGENTOPS_DATABASE_URL", "AGENTOPS_REDIS_URL"},
        "deployment-outbox-dispatcher.yaml": {
            "AGENTOPS_DATABASE_URL",
            "AGENTOPS_REDIS_URL",
        },
        "deployment-audit-anchor-exporter.yaml": {"AGENTOPS_DATABASE_URL"},
        "deployment-dashboard.yaml": {"AGENTOPS_SERVER_API_KEY"},
        "job-migration.yaml": {"AGENTOPS_DATABASE_URL"},
    }
    all_runtime_variables = {
        "AGENTOPS_DATABASE_URL",
        "AGENTOPS_REDIS_URL",
        "AGENTOPS_API_KEY",
        "AGENTOPS_OPERATOR_API_KEY",
        "AGENTOPS_SERVER_API_KEY",
    }
    for name, allowed in expected.items():
        content = (templates / name).read_text(encoding="utf-8")
        assert "secretKeyRef:" in content
        for variable in all_runtime_variables:
            assert (variable in content) is (variable in allowed)


def test_audit_anchor_exporter_uses_workload_identity_and_separate_read_only_secrets():
    content = Path(
        "deploy/helm/agentops-guard/templates/deployment-audit-anchor-exporter.yaml"
    ).read_text(encoding="utf-8")
    policy = Path("deploy/openbao/agentops-audit-export-policy.hcl").read_text(encoding="utf-8")

    assert "auditAnchorExporter.serviceAccountName is required" in content
    assert "auditAnchorExporter.databaseExistingSecret is required" in content
    assert "auditAnchorExporter.openbaoExistingSecret is required" in content
    assert "openbao-proxy-identity" in content
    assert "wrapped-secret-id" in content
    assert "AWS_ACCESS_KEY_ID" not in content
    assert "AWS_SECRET_ACCESS_KEY" not in content
    assert 'capabilities = ["read"]' in policy
    assert "sign/" not in policy


def test_each_python_workload_declares_its_component_role():
    templates = Path("deploy/helm/agentops-guard/templates")
    expected = {
        "deployment-api.yaml": "api",
        "deployment-gateway.yaml": "gateway",
        "deployment-worker.yaml": "worker",
        "deployment-outbox-dispatcher.yaml": "outbox_dispatcher",
        "deployment-semantic-scanner.yaml": "semantic_scanner",
        "deployment-audit-anchor-exporter.yaml": "audit_anchor_exporter",
        "job-migration.yaml": "migration",
    }
    for filename, component in expected.items():
        content = (templates / filename).read_text(encoding="utf-8")
        assert "AGENTOPS_COMPONENT" in content
        assert f"value: {component}" in content


def test_render_validator_rejects_credential_key_on_a_non_api_workload():
    validate = run_path("scripts/helm_template_check.py")["_validate_credential_mount"]
    rendered = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentops-guard-api
spec:
  template:
    spec:
      containers:
        - name: api
          env:
            - name: AGENTOPS_CREDENTIAL_ENCRYPTION_KEY
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentops-guard-worker
spec:
  template:
    spec:
      containers:
        - name: worker
          env:
            - name: AGENTOPS_CREDENTIAL_ENCRYPTION_KEY
"""

    with pytest.raises(SystemExit, match="agentops-guard-worker"):
        validate(rendered)


def test_semantic_scanner_weights_are_mounted_only_into_isolated_service():
    templates = Path("deploy/helm/agentops-guard/templates")
    gateway = (templates / "deployment-gateway.yaml").read_text(encoding="utf-8")
    semantic = (templates / "deployment-semantic-scanner.yaml").read_text(encoding="utf-8")
    model_markers = {
        "AGENTOPS_SEMANTIC_MODEL_PATH",
        "AGENTOPS_SEMANTIC_MODEL_SHA256",
        "HF_HUB_OFFLINE",
        "TRANSFORMERS_OFFLINE",
    }

    assert "AGENTOPS_SEMANTIC_SCANNER_MODE" in gateway
    assert "AGENTOPS_SEMANTIC_SERVICE_URL" in gateway
    for marker in model_markers:
        assert marker not in gateway
        assert marker in semantic
        for name in ("deployment-api.yaml", "deployment-worker.yaml", "deployment-dashboard.yaml"):
            assert marker not in (templates / name).read_text(encoding="utf-8")


def test_semantic_scanner_helm_defaults_to_disabled_and_isolates_model_service():
    values = Path("deploy/helm/agentops-guard/values.yaml").read_text(encoding="utf-8")
    semantic = Path(
        "deploy/helm/agentops-guard/templates/deployment-semantic-scanner.yaml"
    ).read_text(encoding="utf-8")
    network_policy = Path(
        "deploy/helm/agentops-guard/templates/networkpolicy-semantic-scanner.yaml"
    ).read_text(encoding="utf-8")

    assert "semanticScanner:" in values
    assert "mode: disabled" in values
    assert "mountPath: {{ .Values.semanticScanner.modelPath | quote }}" in semantic
    assert "readOnly: true" in semantic
    assert "persistentVolumeClaim:" in semantic
    assert 'include "agentops-guard.containerSecurityContext"' in semantic
    assert 'policyTypes: ["Ingress", "Egress"]' in network_policy
    assert "egress: []" in network_policy


def test_opa_helm_is_optional_and_wires_policy_clients_when_enabled():
    values = Path("deploy/helm/agentops-guard/values.yaml").read_text(encoding="utf-8")
    templates = Path("deploy/helm/agentops-guard/templates")

    assert "opa:" in values
    assert "enabled: false" in values
    opa = (templates / "deployment-opa.yaml").read_text(encoding="utf-8")
    assert ".Values.opa.enabled" in opa
    assert "--disable-telemetry" in opa
    assert "opa.bundle.enabled is required for production embedded OPA" in opa
    assert "- --bundle\n            - /policy/bundle.tar.gz" in opa
    assert "--bundle=/policy/bundle.tar.gz" not in opa
    assert "--verification-key=/policy/public.pem" in opa
    assert "opa.bundle.existingSecret" in opa
    assert "opa.bundle.expectedPolicyRevision is required" in opa
    assert "private" not in opa.casefold()
    assert "not .Values.opa.bundle.enabled" in (templates / "configmap-opa.yaml").read_text(
        encoding="utf-8"
    )
    for name in ("deployment-api.yaml", "deployment-gateway.yaml", "deployment-worker.yaml"):
        workload = (templates / name).read_text(encoding="utf-8")
        assert "AGENTOPS_OPA_URL" in workload
        assert "AGENTOPS_POLICY_FAIL_MODE" in workload
        assert "AGENTOPS_OPA_EXPECTED_POLICY_REVISION" in workload


def test_helm_telemetry_is_optional_and_has_no_content_capture_setting():
    values = Path("deploy/helm/agentops-guard/values.yaml").read_text(encoding="utf-8")
    templates = Path("deploy/helm/agentops-guard/templates")

    assert "telemetry:" in values
    assert "otlpEndpoint:" in values
    for name in ("deployment-api.yaml", "deployment-gateway.yaml", "deployment-worker.yaml"):
        workload = (templates / name).read_text(encoding="utf-8")
        assert "AGENTOPS_OTEL_ENABLED" in workload
        assert "AGENTOPS_OTEL_EXPORTER_OTLP_ENDPOINT" in workload
        assert "CAPTURE" not in workload


def test_helm_routes_standard_mcp_endpoint_to_gateway_with_explicit_guards():
    base = Path("deploy/helm/agentops-guard")
    values = (base / "values.yaml").read_text(encoding="utf-8")
    configmap = (base / "templates" / "configmap.yaml").read_text(encoding="utf-8")
    ingress = (base / "templates" / "ingress.yaml").read_text(encoding="utf-8")

    assert "mcp:" in values
    assert "publicUrl: https://agentops.local/mcp" in values
    assert "pageSize: 100" in values
    assert "AGENTOPS_MCP_PUBLIC_URL" in configmap
    assert "AGENTOPS_MCP_ALLOWED_HOSTS" in configmap
    assert "AGENTOPS_MCP_ALLOWED_ORIGINS" in configmap
    assert "AGENTOPS_MCP_PAGE_SIZE" in configmap
    assert ".Values.mcp.ingressPath" in ingress
    assert 'ternary "gateway-proxy" "gateway"' in ingress


def test_helm_requires_distributed_capacity_for_multiple_gateway_replicas():
    base = Path("deploy/helm/agentops-guard")
    values = (base / "values.yaml").read_text(encoding="utf-8")
    production = (base / "values.prod.yaml").read_text(encoding="utf-8")
    gateway = (base / "templates" / "deployment-gateway.yaml").read_text(encoding="utf-8")

    assert "gatewayConcurrency:" in values
    assert "backend: local" in values
    assert "backend: redis" in production
    assert "multiple Gateway replicas require" in gateway
    assert 'if eq .Values.gatewayConcurrency.backend "redis"' in gateway


def test_production_helm_requires_digest_pinned_images():
    base = Path("deploy/helm/agentops-guard")
    values = (base / "values.yaml").read_text(encoding="utf-8")
    production = (base / "values.prod.yaml").read_text(encoding="utf-8")
    helpers = (base / "templates" / "_helpers.tpl").read_text(encoding="utf-8")

    assert 'digest: ""' in values
    assert "requireImageDigests: false" in values
    assert "requireImageDigests: true" in production
    assert "image.digest is required" in helpers
    assert "dashboardImage.digest is required" in helpers
    assert "opa.image.digest is required" in helpers
    assert "openbaoProxy.image.digest is required" in helpers
    assert "^sha256:[0-9a-f]{64}$" in helpers

    for name in (
        "deployment-api.yaml",
        "deployment-gateway.yaml",
        "deployment-worker.yaml",
        "deployment-outbox-dispatcher.yaml",
        "deployment-audit-anchor-exporter.yaml",
        "deployment-semantic-scanner.yaml",
        "job-migration.yaml",
    ):
        workload = (base / "templates" / name).read_text(encoding="utf-8")
        assert 'include "agentops-guard.image"' in workload
    dashboard = (base / "templates" / "deployment-dashboard.yaml").read_text(encoding="utf-8")
    assert 'include "agentops-guard.dashboardImage"' in dashboard
    opa = (base / "templates" / "deployment-opa.yaml").read_text(encoding="utf-8")
    assert 'include "agentops-guard.opaImage"' in opa
    for name in ("deployment-api.yaml", "deployment-audit-anchor-exporter.yaml"):
        assert 'include "agentops-guard.openbaoProxyImage"' in (
            base / "templates" / name
        ).read_text(encoding="utf-8")


def test_production_helm_requires_exact_keyless_image_signer():
    base = Path("deploy/helm/agentops-guard")
    values = (base / "values.yaml").read_text(encoding="utf-8")
    production = (base / "values.prod.yaml").read_text(encoding="utf-8")
    policy = (base / "templates" / "clusterimagepolicy.yaml").read_text(encoding="utf-8")
    controller_text = Path("deploy/admission/policy-controller-values.prod.yaml").read_text(
        encoding="utf-8"
    )
    controller = yaml.safe_load(controller_text)

    assert "requireImageSignatures: false" in values
    assert "requireImageSignatures: true" in production
    assert "imageVerification:" in values
    assert "enabled: true" in production
    assert "policy.sigstore.dev/v1beta1" in policy
    assert "kind: ClusterImagePolicy" in policy
    assert "approved-keyless-builder" in policy
    assert "trustRootRef" in policy
    assert "imageVerification.trustRootRef is required" in policy
    assert "issuerRegExp" not in policy
    assert "subjectRegExp" not in policy
    assert "must be an exact non-wildcard signing identity" in policy
    assert "repository-scoped image glob" in policy
    assert "end with @sha256:*" in policy
    assert controller["webhook"]["failurePolicy"] == "Fail"
    assert controller["webhook"]["configData"]["no-match-policy"] == "deny"
    assert controller["webhook"]["replicaCount"] == 2
    assert controller["webhook"]["image"] == {
        "repository": "ghcr.io/sigstore/policy-controller/policy-controller",
        "version": "sha256:0492bb264fb1d9bdc8e3f343ef542cc85b7dd7c7fd8d9524b453c2bd31a1d128",
        "pullPolicy": "IfNotPresent",
    }
    assert controller["webhook"]["extraArgs"] == {"disable-tuf": True}
    assert controller["leasescleanup"]["image"]["version"] == (
        "sha256:7200e12e0a13c12291314c31bbd0843baf07947e91091bce8755ee3f8374bea0"
    )


def test_image_signature_policy_validator_rejects_warning_mode():
    validate = run_path("scripts/helm_template_check.py")["_validate_image_signature_policy"]
    rendered = """
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: agentops-guard-signed-images
spec:
  mode: warn
  images: []
  authorities: []
"""

    with pytest.raises(SystemExit, match="must enforce rejection"):
        validate(rendered)


def test_production_network_policy_defaults_to_deny_and_requires_explicit_egress():
    base = Path("deploy/helm/agentops-guard")
    values = (base / "values.yaml").read_text(encoding="utf-8")
    production = (base / "values.prod.yaml").read_text(encoding="utf-8")
    policy = (base / "templates" / "networkpolicy-default-deny.yaml").read_text(encoding="utf-8")
    migration = (base / "templates" / "job-migration.yaml").read_text(encoding="utf-8")

    assert "networkPolicy:" in values
    assert "requireExplicitExternalEgress: false" in values
    assert "requireExplicitExternalEgress: true" in production
    assert "-default-deny" in policy
    assert 'policyTypes: ["Ingress", "Egress"]' in policy
    assert "ingress: []" in policy
    assert "egress: []" in policy
    assert "0.0.0.0/0" in policy
    assert "must not allow an all-address CIDR" in policy
    assert (
        "agentops-guard-semantic-scanner"
        not in policy.split('name: {{ include "agentops-guard.name" . }}-dns-egress', 1)[1].split(
            "---", 1
        )[0]
    )
    assert "app: agentops-guard-migration" in migration


def test_network_isolation_validator_rejects_missing_default_deny():
    validate = run_path("scripts/helm_template_check.py")["_validate_network_isolation"]

    with pytest.raises(SystemExit, match="policies are missing"):
        validate("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: placeholder\n")


def test_helm_private_registry_pull_secrets_cover_every_workload_image():
    templates = Path("deploy/helm/agentops-guard/templates")
    for name in (
        "deployment-api.yaml",
        "deployment-gateway.yaml",
        "deployment-worker.yaml",
        "deployment-outbox-dispatcher.yaml",
        "deployment-audit-anchor-exporter.yaml",
        "deployment-semantic-scanner.yaml",
        "job-migration.yaml",
    ):
        assert ".Values.image.pullSecrets" in (templates / name).read_text(encoding="utf-8")
    assert ".Values.dashboardImage.pullSecrets" in (
        templates / "deployment-dashboard.yaml"
    ).read_text(encoding="utf-8")
    assert ".Values.opa.image.pullSecrets" in (templates / "deployment-opa.yaml").read_text(
        encoding="utf-8"
    )


def test_production_images_have_pinned_base_images_and_non_root_users():
    application = Path("Dockerfile").read_text(encoding="utf-8")
    dashboard = Path("dashboard/Dockerfile").read_text(encoding="utf-8")
    next_config = Path("dashboard/next.config.js").read_text(encoding="utf-8")

    assert "python3.12-bookworm-slim@sha256:" in application
    assert "USER 10001:10001" in application
    assert "node:22-bookworm-slim@sha256:" in dashboard
    assert "USER node" in dashboard
    assert 'CMD ["node", "server.js"]' in dashboard
    assert 'output: "standalone"' in next_config
    values = Path("deploy/helm/agentops-guard/values.yaml").read_text(encoding="utf-8")
    assert "repository: ghcr.io/openbao/openbao" in values
    assert "tag: 2.6.1" in values


def test_openbao_proxy_owns_response_wrapped_approle_authentication():
    template = Path("deploy/helm/agentops-guard/templates/configmap-openbao-proxy.yaml").read_text(
        encoding="utf-8"
    )
    api = Path("deploy/helm/agentops-guard/templates/deployment-api.yaml").read_text(
        encoding="utf-8"
    )

    assert 'use_auto_auth_token = "force"' in template
    assert "secret_id_response_wrapping_path" in template
    assert 'role_id_file_path = "/var/run/secrets/agentops/openbao/role-id"' in template
    assert 'secret_id_file_path = "/var/run/secrets/agentops/openbao/wrapped-secret-id"' in template
    assert "tls_skip_verify = true" not in template
    assert "name: openbao-proxy-identity" in api
    assert "path: role-id" in api
    assert "path: wrapped-secret-id" in api


def test_openbao_identity_delivery_policies_cannot_use_managed_secrets_or_signatures():
    for name in (
        "agentops-api-identity-delivery-policy.hcl",
        "agentops-audit-export-identity-delivery-policy.hcl",
    ):
        policy = Path("deploy/openbao", name).read_text(encoding="utf-8")
        assert "/role-id" in policy
        assert "/secret-id" in policy
        assert 'capabilities = ["read"]' in policy
        assert 'capabilities = ["update"]' in policy
        assert "secret/data" not in policy
        assert "transit/" not in policy


def test_every_helm_workload_uses_restricted_security_contexts():
    templates = Path("deploy/helm/agentops-guard/templates")
    helpers = (templates / "_helpers.tpl").read_text(encoding="utf-8")
    assert "runAsNonRoot: true" in helpers
    assert "fsGroup: 10001" in helpers
    assert "fsGroupChangePolicy: OnRootMismatch" in helpers
    assert "allowPrivilegeEscalation: false" in helpers
    assert "readOnlyRootFilesystem: true" in helpers
    assert 'drop: ["ALL"]' in helpers
    assert "type: RuntimeDefault" in helpers

    for name in (
        "deployment-api.yaml",
        "deployment-gateway.yaml",
        "deployment-worker.yaml",
        "deployment-outbox-dispatcher.yaml",
        "deployment-audit-anchor-exporter.yaml",
        "deployment-dashboard.yaml",
        "deployment-semantic-scanner.yaml",
        "deployment-opa.yaml",
        "job-migration.yaml",
    ):
        workload = (templates / name).read_text(encoding="utf-8")
        assert 'include "agentops-guard.podSecurityContext"' in workload
        assert 'include "agentops-guard.containerSecurityContext"' in workload
        assert "mountPath: /tmp" in workload


def test_every_workload_uses_a_non_automounted_dedicated_service_account():
    base = Path("deploy/helm/agentops-guard")
    templates = base / "templates"
    accounts = (templates / "serviceaccounts.yaml").read_text(encoding="utf-8")
    values = (base / "values.yaml").read_text(encoding="utf-8")

    assert "serviceAccounts:" in values
    assert "automountServiceAccountToken: false" in accounts
    for name, field in {
        "deployment-api.yaml": "serviceAccounts.api",
        "deployment-gateway.yaml": "serviceAccounts.gateway",
        "deployment-worker.yaml": "serviceAccounts.worker",
        "deployment-outbox-dispatcher.yaml": "serviceAccounts.outboxDispatcher",
        "deployment-dashboard.yaml": "serviceAccounts.dashboard",
        "deployment-semantic-scanner.yaml": "serviceAccounts.semanticScanner",
        "deployment-opa.yaml": "serviceAccounts.opa",
        "job-migration.yaml": "serviceAccounts.migration",
    }.items():
        content = (templates / name).read_text(encoding="utf-8")
        assert field in content
        assert "automountServiceAccountToken: false" in content
    exporter = (templates / "deployment-audit-anchor-exporter.yaml").read_text(encoding="utf-8")
    assert "auditAnchorExporter.serviceAccountName" in exporter
    assert "automountServiceAccountToken: false" in exporter
    for kind in (
        "kind: Role",
        "kind: ClusterRole",
        "kind: RoleBinding",
        "kind: ClusterRoleBinding",
    ):
        assert kind not in accounts


def test_service_account_validator_rejects_rbac_grants():
    validate = run_path("scripts/helm_template_check.py")["_validate_service_accounts"]
    rendered = """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: unexpected
"""

    with pytest.raises(SystemExit, match="unexpected Kubernetes API access"):
        validate(rendered)


def test_opa_network_policy_allows_only_policy_clients_and_has_no_egress():
    policy = Path("deploy/helm/agentops-guard/templates/networkpolicy-opa.yaml").read_text(
        encoding="utf-8"
    )

    assert "agentops-guard-api" in policy
    assert "agentops-guard-gateway" in policy
    assert "agentops-guard-worker" in policy
    assert "port: 8181" in policy
    assert "egress: []" in policy


def test_production_image_validator_rejects_a_mutable_tag():
    validate = run_path("scripts/helm_template_check.py")["_validate_production_image_digests"]
    rendered = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentops-guard-api
spec:
  template:
    spec:
      containers:
        - name: api
          image: agentops-guard:latest
"""

    with pytest.raises(SystemExit, match="not digest-pinned"):
        validate(rendered)
