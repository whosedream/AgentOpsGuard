from pathlib import Path

import yaml


def test_credential_encryption_key_is_exposed_only_to_the_api_service():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    marker = "AGENTOPS_CREDENTIAL_ENCRYPTION_KEY"

    services_with_key = {
        name
        for name, service in compose["services"].items()
        if marker in (service.get("environment") or {})
    }
    assert services_with_key == {"api"}


def test_openbao_configuration_is_exposed_only_to_the_api_service():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    markers = {
        "AGENTOPS_CREDENTIAL_STORE",
        "AGENTOPS_OPENBAO_URL",
        "AGENTOPS_OPENBAO_TOKEN",
        "AGENTOPS_OPENBAO_KV_MOUNT",
    }

    for marker in markers:
        services_with_marker = {
            name
            for name, service in compose["services"].items()
            if marker in (service.get("environment") or {})
        }
        assert services_with_marker == {"api"}


def test_semantic_scanner_configuration_is_exposed_only_to_gateway():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    semantic_environment = {
        "AGENTOPS_SEMANTIC_SCANNER_MODE",
        "AGENTOPS_SEMANTIC_MODEL_PATH",
        "AGENTOPS_SEMANTIC_MODEL_SHA256",
        "AGENTOPS_SEMANTIC_SCANNER_THRESHOLD",
        "HF_HUB_OFFLINE",
        "TRANSFORMERS_OFFLINE",
    }

    for variable in semantic_environment:
        services_with_variable = {
            name
            for name, service in compose["services"].items()
            if variable in (service.get("environment") or {})
        }
        assert services_with_variable == {"gateway"}


def test_semantic_scanner_compose_defaults_to_disabled_and_mounts_local_model_read_only():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    gateway = compose["services"]["gateway"]
    environment = gateway["environment"]

    assert environment["AGENTOPS_SEMANTIC_SCANNER_MODE"] == "${AGENTOPS_SEMANTIC_SCANNER_MODE:-disabled}"
    assert environment["AGENTOPS_SEMANTIC_MODEL_PATH"] == "/models/semantic-guard"
    assert environment["HF_HUB_OFFLINE"] == "1"
    assert environment["TRANSFORMERS_OFFLINE"] == "1"

    assert any(
        isinstance(volume, str)
        and "${AGENTOPS_SEMANTIC_MODEL_DIR" in volume
        and volume.endswith(":/models/semantic-guard:ro")
        for volume in gateway.get("volumes", [])
    )


def test_compose_runs_opa_with_read_only_policy_and_health_gate():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    opa = compose["services"]["opa"]

    assert opa["image"].startswith("${AGENTOPS_OPA_IMAGE:-openpolicyagent/opa:")
    assert "./policies:/policies:ro" in opa["volumes"]
    assert "/health?bundles=true&plugins=true" in opa["healthcheck"]["test"][-1]
    for name in ("api", "gateway", "worker"):
        service = compose["services"][name]
        assert service["environment"]["AGENTOPS_OPA_URL"] == "http://opa:8181"
        assert service["depends_on"]["opa"]["condition"] == "service_healthy"


def test_compose_routes_traces_through_local_collector_without_content_capture():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    collector = compose["services"]["otel-collector"]
    collector_config = Path("deploy/otel-collector.yaml").read_text(encoding="utf-8")

    assert "otel/opentelemetry-collector-contrib:" in collector["image"]
    assert "./deploy/otel-collector.yaml:/etc/otelcol-contrib/config.yaml:ro" in collector[
        "volumes"
    ]
    assert "content" not in collector_config.casefold()
    for name in ("api", "gateway", "worker"):
        environment = compose["services"][name]["environment"]
        assert environment["AGENTOPS_OTEL_ENABLED"] == "true"
        assert environment["AGENTOPS_OTEL_EXPORTER_OTLP_ENDPOINT"] == (
            "http://otel-collector:4317"
        )
    assert "AGENTOPS_OTEL_ENABLED" not in compose["services"]["dashboard"]["environment"]
