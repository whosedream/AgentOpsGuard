from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import yaml


CHART_PATH = Path("deploy/helm/agentops-guard")
LOCAL_HELM = Path(os.environ.get("TEMP", "")) / "helm-v3.18.4" / "windows-amd64" / "helm.exe"
CREDENTIAL_RENDER_ARGS = [
    "--set",
    "credentialEncryption.existingSecret=agentops-credential-test",
]


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def _render(command: list[str]) -> str:
    return subprocess.run(
        command, check=True, capture_output=True, text=True
    ).stdout


def _validate_credential_mount(rendered: str) -> None:
    workloads_with_key: set[str] = set()
    for document in yaml.safe_load_all(rendered):
        if not isinstance(document, dict) or document.get("kind") not in {
            "Deployment",
            "Job",
        }:
            continue
        pod_spec = document["spec"]["template"]["spec"]
        if any(
            variable.get("name") == "AGENTOPS_CREDENTIAL_ENCRYPTION_KEY"
            for container in pod_spec.get("containers", [])
            for variable in container.get("env", [])
        ):
            workloads_with_key.add(document["metadata"]["name"])
    if workloads_with_key != {"agentops-guard-api"}:
        raise SystemExit(
            f"credential key mounted into unexpected workloads: {sorted(workloads_with_key)}"
        )


def main() -> int:
    helm = shutil.which("helm")
    if helm:
        _run([helm, "lint", str(CHART_PATH)])
        rendered = _render(
            [
                helm,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                "-f",
                str(CHART_PATH / "values.yaml"),
                "-f",
                str(CHART_PATH / "values.staging.yaml"),
                *CREDENTIAL_RENDER_ARGS,
            ]
        )
        _validate_credential_mount(rendered)
        return 0

    if LOCAL_HELM.exists():
        helm_cmd = str(LOCAL_HELM)
        _run([helm_cmd, "lint", str(CHART_PATH)])
        rendered = _render(
            [
                helm_cmd,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                "-f",
                str(CHART_PATH / "values.yaml"),
                "-f",
                str(CHART_PATH / "values.staging.yaml"),
                *CREDENTIAL_RENDER_ARGS,
            ]
        )
        _validate_credential_mount(rendered)
        return 0

    image = os.environ.get("AGENTOPS_HELM_IMAGE")
    if image:
        mount = f"{Path.cwd()}:/workspace"
        _run(["docker", "run", "--rm", "-v", mount, "-w", "/workspace", image, "lint", str(CHART_PATH)])
        rendered = _render(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                mount,
                "-w",
                "/workspace",
                image,
                "template",
                "agentops-guard",
                str(CHART_PATH),
                "-f",
                str(CHART_PATH / "values.yaml"),
                "-f",
                str(CHART_PATH / "values.staging.yaml"),
                *CREDENTIAL_RENDER_ARGS,
            ]
        )
        _validate_credential_mount(rendered)
        return 0

    raise SystemExit(
        "No Helm execution path found. Install helm, place helm.exe at %TEMP%/helm-v3.18.4/windows-amd64/helm.exe, "
        "or set AGENTOPS_HELM_IMAGE."
    )


if __name__ == "__main__":
    raise SystemExit(main())
