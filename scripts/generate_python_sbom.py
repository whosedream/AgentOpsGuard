from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any
from uuid import NAMESPACE_URL, uuid5


ROOT = Path(__file__).resolve().parents[1]


def normalize_sbom(
    document: dict[str, Any],
    *,
    lock_digest: str,
    identity: str = "python",
    lock_property: str = "agentops:uv_lock_sha256",
) -> dict[str, Any]:
    normalized = deepcopy(document)
    if normalized.get("bomFormat") != "CycloneDX" or normalized.get("specVersion") != "1.5":
        raise ValueError("uv did not produce a CycloneDX 1.5 document")
    if not isinstance(normalized.get("components"), list) or not normalized["components"]:
        raise ValueError("SBOM has no dependency components")
    if not isinstance(normalized.get("dependencies"), list):
        raise ValueError("SBOM has no dependency graph")

    normalized["serialNumber"] = (
        f"urn:uuid:{uuid5(NAMESPACE_URL, f'agentops-guard-sbom:{identity}:{lock_digest}')}"
    )
    metadata = normalized.setdefault("metadata", {})
    metadata.pop("timestamp", None)
    properties = [
        item
        for item in metadata.get("properties", [])
        if item.get("name") != lock_property
    ]
    properties.append({"name": lock_property, "value": lock_digest})
    metadata["properties"] = sorted(properties, key=lambda item: (item["name"], item["value"]))
    normalized["components"].sort(key=lambda item: item["bom-ref"])
    for item in normalized["dependencies"]:
        if "dependsOn" in item:
            item["dependsOn"] = sorted(item["dependsOn"])
    normalized["dependencies"].sort(key=lambda item: item["ref"])
    return normalized


def generate_sbom(output: Path) -> None:
    lock_path = ROOT / "uv.lock"
    lock_digest = sha256(lock_path.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="agentops-sbom-") as directory:
        raw_path = Path(directory) / "raw.cdx.json"
        environment = {
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PATH": os.environ["PATH"],
            "UV_NO_CONFIG": "1",
        }
        result = subprocess.run(
            [
                "uv",
                "export",
                "--preview-features",
                "sbom-export",
                "--locked",
                "--no-dev",
                "--extra",
                "semantic",
                "--no-emit-project",
                "--format",
                "cyclonedx1.5",
                "--output-file",
                str(raw_path),
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("uv SBOM export failed")
        document = json.loads(raw_path.read_text(encoding="utf-8"))

    normalized = normalize_sbom(document, lock_digest=lock_digest)
    encoded = json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(encoded, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a deterministic Python CycloneDX SBOM")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    generate_sbom(arguments.output.resolve())
    print("sbom=generated format=cyclonedx-1.5")


if __name__ == "__main__":
    main()
