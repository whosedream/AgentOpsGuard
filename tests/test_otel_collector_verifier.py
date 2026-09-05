from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_otel_collector.py"
SPEC = importlib.util.spec_from_file_location("verify_otel_collector", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


def test_collector_verifier_requires_official_digest_pinned_image():
    digest = "a" * 64
    assert verifier.validate_image_reference(
        f"otel/opentelemetry-collector-contrib@sha256:{digest}"
    )
    assert verifier.validate_image_reference(
        "ghcr.io/open-telemetry/opentelemetry-collector-releases/"
        f"opentelemetry-collector-contrib@sha256:{digest}"
    )

    for rejected in (
        "otel/opentelemetry-collector-contrib:0.160.0",
        f"mirror.invalid/opentelemetry-collector-contrib@sha256:{digest}",
        "otel/opentelemetry-collector-contrib@sha256:short",
    ):
        with pytest.raises(ValueError, match="official repository"):
            verifier.validate_image_reference(rejected)


def test_collector_verifier_uses_file_export_and_fixed_route_safe_runtime(tmp_path):
    config = tmp_path / "collector.yaml"
    output = tmp_path / "output"
    output.mkdir()
    content = verifier._collector_config("/output/traces.json")
    config.write_text(content, encoding="utf-8")
    command = verifier._container_command(
        image=f"otel/opentelemetry-collector-contrib@sha256:{'b' * 64}",
        name="agentops-otel-test",
        config=config,
        output_dir=output,
        grpc_port=14317,
        health_port=13133,
    )

    assert "debug" not in content
    assert "path: /output/traces.json" in content
    assert "endpoint: 0.0.0.0:4317" in content
    assert "--user=10001:10001" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--memory=384m" in command
    assert "--cpus=1" in command
    assert "127.0.0.1:14317:4317" in command
