# Deployment

## Compose

- Run `docker compose up --build`.
- Run `uv run python scripts/compose_smoke.py` after the stack is healthy.

## Helm

- Chart path: `deploy/helm/agentops-guard`.
- Static asset validation: `uv run python scripts/validate_helm_assets.py`.
- Real render validation: `powershell -File scripts/helm_template_check.ps1`.
- Cross-platform render validation: `uv run python scripts/helm_template_check.py`.
  - The script prefers a local `helm` binary, then `%TEMP%\helm-v3.18.4\windows-amd64\helm.exe`, then `AGENTOPS_HELM_IMAGE`.
- External dependencies:
  - `AGENTOPS_DATABASE_URL`
  - `AGENTOPS_REDIS_URL`
- Externalized secrets:
  - `AGENTOPS_API_KEY`
  - `AGENTOPS_OPERATOR_API_KEY`
- Example values:
  - `values.local-like.yaml`
  - `values.staging.yaml`
  - `values.prod.yaml`
- Install flow:
  - lint and render the chart in CI through the Helm container helper
  - run migration job before scaling API, Gateway, and Worker
  - route Dashboard through the chart services, not direct public URLs
