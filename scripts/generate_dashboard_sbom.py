from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile

from generate_python_sbom import normalize_sbom


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard"


def generate_sbom(output: Path) -> None:
    lock_path = DASHBOARD / "package-lock.json"
    lock_digest = sha256(lock_path.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="agentops-dashboard-sbom-") as directory:
        environment = {
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "NPM_CONFIG_CACHE": str(Path(directory) / "npm-cache"),
            "PATH": os.environ["PATH"],
        }
        result = subprocess.run(
            [
                "npm",
                "sbom",
                "--omit=dev",
                "--sbom-format=cyclonedx",
                "--sbom-type=application",
            ],
            cwd=DASHBOARD,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError("npm SBOM export failed")
    document = json.loads(result.stdout)
    normalized = normalize_sbom(
        document,
        lock_digest=lock_digest,
        identity="dashboard",
        lock_property="agentops:package_lock_sha256",
    )
    encoded = json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(encoded, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic Dashboard CycloneDX SBOM"
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    generate_sbom(arguments.output.resolve())
    print("sbom=generated target=dashboard format=cyclonedx-1.5")


if __name__ == "__main__":
    main()
