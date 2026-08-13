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
  - `AGENTOPS_CREDENTIAL_ENCRYPTION_KEY` in a dedicated Secret exposed only to the API process
- Example values:
  - `values.local-like.yaml`
  - `values.staging.yaml`
  - `values.prod.yaml`
- Install flow:
  - lint and render the chart in CI through the Helm container helper
  - run migration job before scaling API, Gateway, and Worker
  - route Dashboard through the chart services, not direct public URLs

For production, generate the Fernet key inside a managed secret store and sync it into a dedicated
Kubernetes Secret. Do not print the key or pass it as a command argument. For a local development
file that never writes the key to stdout:

```bash
umask 077
uv run python -c "from pathlib import Path; from cryptography.fernet import Fernet; Path('/secure/path/agentops-credential.key').write_bytes(Fernet.generate_key())"
kubectl create secret generic agentops-credential-encryption --from-file=AGENTOPS_CREDENTIAL_ENCRYPTION_KEY=/secure/path/agentops-credential.key
```

Set `credentialEncryption.existingSecret` to a Kubernetes Secret that contains the
`AGENTOPS_CREDENTIAL_ENCRYPTION_KEY` key. Do not add this value to the chart's shared application
Secret: Gateway, Worker, Dashboard, and Migration do not need decryption authority.
Remove the local staging file according to the deployment environment's secret-handling policy.
The Compose path is development-only and must not carry production provider credentials.
