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


def test_dashboard_runtime_cannot_mount_repository_secrets_or_data():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    dashboard = compose["services"]["dashboard"]

    assert dashboard["volumes"] == [
        "./dashboard/package.json:/app/dashboard/package.json:ro",
        "./dashboard/package-lock.json:/app/dashboard/package-lock.json:ro",
        "./dashboard/app:/app/dashboard/app:ro",
        "./dashboard/components:/app/dashboard/components:ro",
        "./dashboard/lib:/app/dashboard/lib:ro",
        "./dashboard/next-env.d.ts:/app/dashboard/next-env.d.ts:ro",
        "./dashboard/next.config.js:/app/dashboard/next.config.js:ro",
        "./dashboard/postcss.config.js:/app/dashboard/postcss.config.js:ro",
        "./dashboard/tailwind.config.ts:/app/dashboard/tailwind.config.ts:ro",
        "./dashboard/tsconfig.json:/app/dashboard/tsconfig.json:ro",
        "dashboard_node_modules:/app/dashboard/node_modules",
        "dashboard_next:/app/dashboard/.next",
    ]
    assert all(
        volume != ".:/app"
        for service in compose["services"].values()
        for volume in service.get("volumes", [])
        if isinstance(volume, str)
    )


def test_compose_publishes_development_ports_only_on_loopback():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    published = [
        port
        for service in compose["services"].values()
        for port in service.get("ports", [])
    ]

    assert published
    assert all(isinstance(port, str) and port.startswith("127.0.0.1:") for port in published)


def test_openbao_configuration_is_exposed_only_to_the_api_service():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    markers = {
        "AGENTOPS_CREDENTIAL_STORE",
        "AGENTOPS_OPENBAO_URL",
        "AGENTOPS_OPENBAO_TOKEN",
        "AGENTOPS_OPENBAO_KV_MOUNT",
        "AGENTOPS_AUDIT_CHECKPOINT_BACKEND",
        "AGENTOPS_OPENBAO_TRANSIT_MOUNT",
        "AGENTOPS_AUDIT_CHECKPOINT_KEY_NAME",
    }

    for marker in markers:
        services_with_marker = {
            name
            for name, service in compose["services"].items()
            if marker in (service.get("environment") or {})
        }
        assert services_with_marker == {"api"}


def test_semantic_model_configuration_is_exposed_only_to_isolated_service():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    semantic_environment = {
        "AGENTOPS_SEMANTIC_MODEL_PATH",
        "AGENTOPS_SEMANTIC_MODEL_SHA256",
        "HF_HUB_OFFLINE",
        "TRANSFORMERS_OFFLINE",
    }

    for variable in semantic_environment:
        services_with_variable = {
            name
            for name, service in compose["services"].items()
            if variable in (service.get("environment") or {})
        }
        assert services_with_variable == {"semantic-scanner"}


def test_semantic_scanner_compose_defaults_to_disabled_and_mounts_only_in_model_service():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    gateway = compose["services"]["gateway"]
    environment = gateway["environment"]
    semantic = compose["services"]["semantic-scanner"]

    assert environment["AGENTOPS_SEMANTIC_SCANNER_MODE"] == "${AGENTOPS_SEMANTIC_SCANNER_MODE:-disabled}"
    assert environment["AGENTOPS_SEMANTIC_SERVICE_URL"] == "http://semantic-scanner:8090"
    assert "AGENTOPS_SEMANTIC_MODEL_PATH" not in environment
    assert semantic["profiles"] == ["semantic"]
    assert semantic["environment"]["AGENTOPS_SEMANTIC_MODEL_PATH"] == "/models/semantic-guard"
    assert semantic["read_only"] is True
    assert semantic["cap_drop"] == ["ALL"]
    assert semantic["expose"] == ["8090"]
    assert "ports" not in semantic

    assert any(
        isinstance(volume, str)
        and "${AGENTOPS_SEMANTIC_MODEL_DIR" in volume
        and volume.endswith(":/models/semantic-guard:ro")
        for volume in semantic.get("volumes", [])
    )


def test_compose_runs_opa_with_read_only_policy_and_health_gate():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    opa = compose["services"]["opa"]

    assert opa["image"].startswith("${AGENTOPS_OPA_IMAGE:-openpolicyagent/opa:")
    assert "--disable-telemetry" in opa["command"]
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

    assert collector["image"] == (
        "${AGENTOPS_OTEL_COLLECTOR_IMAGE:-"
        "otel/opentelemetry-collector-contrib:0.160.0}"
    )
    assert collector["user"] == "10001:10001"
    assert collector["read_only"] is True
    assert collector["init"] is True
    assert collector["pids_limit"] == 128
    assert collector["mem_limit"] == "384m"
    assert float(collector["cpus"]) == 1.0
    assert collector["cap_drop"] == ["ALL"]
    assert collector["security_opt"] == ["no-new-privileges:true"]
    assert set(collector["ports"]) == {
        "127.0.0.1:4317:4317",
        "127.0.0.1:4318:4318",
        "127.0.0.1:13133:13133",
    }
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


def test_compose_exposes_standard_mcp_endpoint_with_explicit_host_guards():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    environment = compose["services"]["gateway"]["environment"]

    assert environment["AGENTOPS_MCP_PUBLIC_URL"].endswith(
        ":-http://localhost:8001/mcp}"
    )
    assert "127.0.0.1:*" in environment["AGENTOPS_MCP_ALLOWED_HOSTS"]
    assert "http://localhost:3000" in environment["AGENTOPS_MCP_ALLOWED_ORIGINS"]


def test_compose_declares_gateway_concurrency_backend_explicitly():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    environment = compose["services"]["gateway"]["environment"]

    assert environment["AGENTOPS_GATEWAY_CONCURRENCY_BACKEND"].endswith(":-local}")
    assert environment["AGENTOPS_GATEWAY_CONCURRENCY_LEASE_SECONDS"].endswith(":-60}")
