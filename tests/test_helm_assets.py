from pathlib import Path
from runpy import run_path

import pytest


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
        base / "templates" / "secret.yaml",
        base / "templates" / "service-api.yaml",
        base / "templates" / "service-gateway.yaml",
        base / "templates" / "service-dashboard.yaml",
        base / "templates" / "ingress.yaml",
        base / "templates" / "deployment-api.yaml",
        base / "templates" / "deployment-gateway.yaml",
        base / "templates" / "deployment-worker.yaml",
        base / "templates" / "deployment-dashboard.yaml",
        base / "templates" / "job-migration.yaml",
        base / "templates" / "configmap-opa.yaml",
        base / "templates" / "deployment-opa.yaml",
        base / "templates" / "service-opa.yaml",
        base / "files" / "dangerous_command.rego",
        base / "files" / "decision.rego",
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
        "secret.yaml",
        "deployment-gateway.yaml",
        "deployment-worker.yaml",
        "deployment-dashboard.yaml",
        "job-migration.yaml",
    ):
        assert marker not in (templates / name).read_text(encoding="utf-8")


def test_openbao_token_is_mounted_only_into_the_api_deployment():
    templates = Path("deploy/helm/agentops-guard/templates")
    marker = "AGENTOPS_OPENBAO_TOKEN"

    assert marker in (templates / "deployment-api.yaml").read_text(encoding="utf-8")
    for name in (
        "secret.yaml",
        "deployment-gateway.yaml",
        "deployment-worker.yaml",
        "deployment-dashboard.yaml",
        "job-migration.yaml",
    ):
        assert marker not in (templates / name).read_text(encoding="utf-8")


def test_render_validator_rejects_credential_key_on_a_non_api_workload():
    validate = run_path("scripts/helm_template_check.py")[
        "_validate_credential_mount"
    ]
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


def test_semantic_scanner_configuration_is_mounted_only_into_gateway():
    templates = Path("deploy/helm/agentops-guard/templates")
    gateway = (templates / "deployment-gateway.yaml").read_text(encoding="utf-8")
    markers = {
        "AGENTOPS_SEMANTIC_SCANNER_MODE",
        "AGENTOPS_SEMANTIC_MODEL_PATH",
        "AGENTOPS_SEMANTIC_MODEL_SHA256",
        "AGENTOPS_SEMANTIC_SCANNER_THRESHOLD",
        "HF_HUB_OFFLINE",
        "TRANSFORMERS_OFFLINE",
    }

    for marker in markers:
        assert marker in gateway
        for name in (
            "deployment-api.yaml",
            "deployment-worker.yaml",
            "deployment-dashboard.yaml",
            "job-migration.yaml",
        ):
            assert marker not in (templates / name).read_text(encoding="utf-8")


def test_semantic_scanner_helm_defaults_to_disabled_and_mounts_local_model_read_only():
    values = Path("deploy/helm/agentops-guard/values.yaml").read_text(encoding="utf-8")
    gateway = Path(
        "deploy/helm/agentops-guard/templates/deployment-gateway.yaml"
    ).read_text(encoding="utf-8")

    assert "semanticScanner:" in values
    assert "mode: disabled" in values
    assert "mountPath: {{ .Values.semanticScanner.modelPath | quote }}" in gateway
    assert "readOnly: true" in gateway
    assert "hostPath:" in gateway
    assert "startupProbe:" in gateway


def test_opa_helm_is_optional_and_wires_policy_clients_when_enabled():
    values = Path("deploy/helm/agentops-guard/values.yaml").read_text(encoding="utf-8")
    templates = Path("deploy/helm/agentops-guard/templates")

    assert "opa:" in values
    assert "enabled: false" in values
    assert ".Values.opa.enabled" in (templates / "deployment-opa.yaml").read_text(
        encoding="utf-8"
    )
    for name in ("deployment-api.yaml", "deployment-gateway.yaml", "deployment-worker.yaml"):
        workload = (templates / name).read_text(encoding="utf-8")
        assert "AGENTOPS_OPA_URL" in workload
        assert "AGENTOPS_POLICY_FAIL_MODE" in workload


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
