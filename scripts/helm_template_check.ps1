$ErrorActionPreference = "Stop"

$chartPath = "deploy/helm/agentops-guard"
$localHelm = Join-Path $env:TEMP "helm-v3.18.4\windows-amd64\helm.exe"

if (Get-Command helm -ErrorAction SilentlyContinue) {
  $helmCmd = "helm"
} elseif (Test-Path $localHelm) {
  $helmCmd = $localHelm
} elseif ($env:AGENTOPS_HELM_IMAGE) {
  $helmImage = $env:AGENTOPS_HELM_IMAGE
  docker run --rm `
    -v "${PWD}:/workspace" `
    -w /workspace `
    $helmImage `
    lint $chartPath

  docker run --rm `
    -v "${PWD}:/workspace" `
    -w /workspace `
    $helmImage `
    template agentops-guard $chartPath `
    -f "$chartPath/values.yaml" `
    -f "$chartPath/values.staging.yaml" `
    --set credentialEncryption.existingSecret=agentops-credential-test > $null
  exit 0
} else {
  throw "No Helm binary found. Install helm, place helm.exe at $localHelm, or set AGENTOPS_HELM_IMAGE."
}

& $helmCmd lint $chartPath
& $helmCmd template agentops-guard $chartPath `
  -f "$chartPath/values.yaml" `
  -f "$chartPath/values.staging.yaml" `
  --set credentialEncryption.existingSecret=agentops-credential-test > $null
