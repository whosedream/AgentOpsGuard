from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


CHART_PATH = Path("deploy/helm/agentops-guard")
LOCAL_HELM = Path(os.environ.get("TEMP", "")) / "helm-v3.18.4" / "windows-amd64" / "helm.exe"


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    helm = shutil.which("helm")
    if helm:
        _run([helm, "lint", str(CHART_PATH)])
        _run([helm, "template", "agentops-guard", str(CHART_PATH), "-f", str(CHART_PATH / "values.yaml"), "-f", str(CHART_PATH / "values.staging.yaml")])
        return 0

    if LOCAL_HELM.exists():
        helm_cmd = str(LOCAL_HELM)
        _run([helm_cmd, "lint", str(CHART_PATH)])
        _run([helm_cmd, "template", "agentops-guard", str(CHART_PATH), "-f", str(CHART_PATH / "values.yaml"), "-f", str(CHART_PATH / "values.staging.yaml")])
        return 0

    image = os.environ.get("AGENTOPS_HELM_IMAGE")
    if image:
        mount = f"{Path.cwd()}:/workspace"
        _run(["docker", "run", "--rm", "-v", mount, "-w", "/workspace", image, "lint", str(CHART_PATH)])
        _run(
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
            ]
        )
        return 0

    raise SystemExit(
        "No Helm execution path found. Install helm, place helm.exe at %TEMP%/helm-v3.18.4/windows-amd64/helm.exe, "
        "or set AGENTOPS_HELM_IMAGE."
    )


if __name__ == "__main__":
    raise SystemExit(main())
