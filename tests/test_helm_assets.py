from pathlib import Path


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
