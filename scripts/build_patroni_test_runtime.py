#!/usr/bin/env python3
"""Build the pinned Patroni/Kubernetes verification image from reviewed wheels."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "agentops-patroni-runtime:4.1.4"
POSTGRES_LOCAL_TAG = "agentops-patroni-postgres-base:95206741a5b2"
PYTHON_RUNTIME_LOCAL_TAG = "agentops-patroni-python-base:e5b65587bce7"
POSTGRES_DIGEST = "sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b"
PYTHON_RUNTIME_DIGEST = (
    "sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58"
)
WHEELS = {
    "patroni-4.1.4-py3-none-any.whl": (
        "60c8d11da31e822c461480a0b38265de1b1accf9c87d82c93327a120ce92f264"
    ),
    "urllib3-2.7.0-py3-none-any.whl": (
        "9fb4c81ebbb1ce9531cce37674bbc6f1360472bc18ca9a553ede278ef7276897"
    ),
    "pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64."
    "manylinux_2_28_x86_64.whl": (
        "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc"
    ),
    "py_consul-1.7.1-py2.py3-none-any.whl": (
        "016fe49c65c68426e1c0353de2243865fd58e3c7a940413b6202c2becf3cfb04"
    ),
    "click-8.4.2-py3-none-any.whl": (
        "e6f9f66136c816745b9d65817da91d61d957fb16e02e4dcd0552553c5a197b76"
    ),
    "prettytable-3.18.0-py3-none-any.whl": (
        "b3346e0e6f79180833aebaac088ae926340586cf6d7d991b9eb125b65f72313a"
    ),
    "python_dateutil-2.9.0.post0-py2.py3-none-any.whl": (
        "a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427"
    ),
    "psutil-7.2.2-cp36-abi3-manylinux2010_x86_64.manylinux_2_12_x86_64."
    "manylinux_2_28_x86_64.whl": (
        "076a2d2f923fd4821644f5ba89f059523da90dc9014e85f8e45a5774ca5bc6f9"
    ),
    "ydiff-1.4.2-py3-none-any.whl": (
        "38ec3f4667cc7ec978e34ddf3dd983dc8feba37abd10f94c8fa0a1088bcd6b2c"
    ),
    "psycopg-3.3.3-py3-none-any.whl": (
        "f96525a72bcfade6584ab17e89de415ff360748c766f0106959144dcbb38c698"
    ),
    "psycopg_binary-3.3.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl": (
        "263a24f39f26e19ed7fc982d7859a36f17841b05bebad3eb47bb9cd2dd785351"
    ),
    "typing_extensions-4.16.0-py3-none-any.whl": (
        "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8"
    ),
    "six-1.17.0-py2.py3-none-any.whl": (
        "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"
    ),
    "wcwidth-0.3.5-py3-none-any.whl": (
        "b0a0245130566939a24ab8432e625b38272fbc62ecbe5aecbdcb50b8f02ce993"
    ),
    "requests-2.34.2-py3-none-any.whl": (
        "2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0"
    ),
    "charset_normalizer-3.5.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64."
    "manylinux_2_28_x86_64.whl": (
        "b9af956078716df40d985fb0dfeb2c2120c5ca92ba4ff4b388acfd01cdc14d08"
    ),
    "idna-3.19-py3-none-any.whl": (
        "815e7be7a7806d54abb586dc943addc79e8b2ee16915059658cbeff4b1b43bf4"
    ),
    "certifi-2026.7.22-py3-none-any.whl": (
        "62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775"
    ),
}
TOXIPROXY_BINARY = "toxiproxy-server-linux-amd64"
TOXIPROXY_SHA256 = "556d891134a3c582dc1e1a3f7335fd55142e5965769855a00b944e13e48302fc"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], *, environment: dict[str, str] | None = None) -> bytes:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=300,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Patroni verification runtime build failed")
    return completed.stdout


def _require_image(reference: str, digest: str) -> None:
    output = _run(["docker", "image", "inspect", "--format", "{{.Id}}", reference])
    if output.decode("ascii").strip() != digest:
        raise RuntimeError("Patroni verification runtime base image digest changed")


def _verify_wheels(wheel_dir: Path) -> None:
    if not wheel_dir.is_dir():
        raise RuntimeError("Patroni verification wheel directory is unavailable")
    for name, expected_digest in WHEELS.items():
        wheel = wheel_dir / name
        if not wheel.is_file() or _sha256(wheel) != expected_digest:
            raise RuntimeError(f"Patroni verification wheel failed review: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--toxiproxy-dir", type=Path, required=True)
    arguments = parser.parse_args()
    wheel_dir = arguments.wheel_dir.resolve()
    toxiproxy_dir = arguments.toxiproxy_dir.resolve()

    _run(["docker", "info"])
    _require_image(f"postgres@{POSTGRES_DIGEST}", POSTGRES_DIGEST)
    _require_image(
        f"ghcr.io/astral-sh/uv@{PYTHON_RUNTIME_DIGEST}",
        PYTHON_RUNTIME_DIGEST,
    )
    _run(["docker", "tag", POSTGRES_DIGEST, POSTGRES_LOCAL_TAG])
    _run(["docker", "tag", PYTHON_RUNTIME_DIGEST, PYTHON_RUNTIME_LOCAL_TAG])
    _verify_wheels(wheel_dir)
    toxiproxy_binary = toxiproxy_dir / TOXIPROXY_BINARY
    if not toxiproxy_binary.is_file() or _sha256(toxiproxy_binary) != TOXIPROXY_SHA256:
        raise RuntimeError("Toxiproxy verification binary failed review")
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "DOCKER_BUILDKIT": "1",
        "SOURCE_DATE_EPOCH": "0",
    }
    _run(
        [
            "docker",
            "build",
            "--pull=false",
            "--provenance=false",
            "--build-context",
            f"patroni_wheels={wheel_dir}",
            "--build-context",
            f"fault_injector={toxiproxy_dir}",
            "--build-context",
            f"patroni_config={ROOT / 'evals' / 'patroni-runtime'}",
            "--file",
            "evals/patroni-runtime/Dockerfile",
            "--tag",
            IMAGE,
            ".",
        ],
        environment=environment,
    )
    image_id = _run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE]
    ).decode("ascii").strip()
    patroni_version = _run(["docker", "run", "--rm", "--pull", "never", IMAGE, "patroni", "--version"])
    postgres_version = _run(["docker", "run", "--rm", "--pull", "never", IMAGE, "postgres", "--version"])
    _run(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            IMAGE,
            "test",
            "-f",
            "/usr/share/licenses/patroni/PATRONI-LICENSE.txt",
        ]
    )
    _run(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            IMAGE,
            "test",
            "-f",
            "/usr/share/licenses/toxiproxy/TOXIPROXY-LICENSE.txt",
        ]
    )
    toxiproxy_version = _run(
        ["docker", "run", "--rm", "--pull", "never", IMAGE, "toxiproxy-server", "-version"]
    )
    if patroni_version.decode("utf-8").strip() != "patroni 4.1.4":
        raise RuntimeError("Patroni verification runtime returned an unexpected version")
    if not postgres_version.decode("utf-8").startswith("postgres (PostgreSQL) 16."):
        raise RuntimeError("Patroni verification runtime returned an unexpected PostgreSQL version")
    if toxiproxy_version.decode("utf-8").strip() != "toxiproxy-server version 2.12.0":
        raise RuntimeError("Patroni verification runtime returned an unexpected Toxiproxy version")
    print(
        json.dumps(
            {
                "image": IMAGE,
                "image_id": image_id,
                "patroni_version": "4.1.4",
                "toxiproxy_version": "2.12.0",
                "postgresql_major": 16,
                "wheel_count": len(WHEELS),
                "base_images_digest_pinned": True,
                "wheel_digests_verified": True,
                "patroni_license_included": True,
                "toxiproxy_license_included": True,
                "production_image_provenance_verified": False,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
