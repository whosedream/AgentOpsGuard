from __future__ import annotations

from pathlib import Path


REQUIRED_FILES = [
    "Chart.yaml",
    "values.yaml",
    "values.local-like.yaml",
    "values.staging.yaml",
    "values.prod.yaml",
    "templates/_helpers.tpl",
    "templates/configmap.yaml",
    "templates/secret.yaml",
    "templates/service-api.yaml",
    "templates/service-gateway.yaml",
    "templates/service-dashboard.yaml",
    "templates/deployment-api.yaml",
    "templates/deployment-gateway.yaml",
    "templates/deployment-worker.yaml",
    "templates/deployment-dashboard.yaml",
    "templates/job-migration.yaml",
]


def main() -> int:
    base = Path("deploy/helm/agentops-guard")
    missing = [path for path in REQUIRED_FILES if not (base / path).exists()]
    if missing:
        raise SystemExit(f"missing Helm assets: {missing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
