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
