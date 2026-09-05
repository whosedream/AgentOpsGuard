import pytest

from agentops_guard.backend.config import Settings
from agentops_guard.backend.services.credentials import CredentialVault


def test_SPEC_P0_002_prod_settings_reject_default_dev_key():
    try:
        Settings(
            env="prod", api_key="dev-agentops-key", cors_allowed_origins=["https://ops.example"]
        )
    except ValueError as exc:
        assert "default development API key" in str(exc)
    else:
        raise AssertionError("prod should reject default dev API key")


def test_SPEC_P0_002_prod_settings_reject_wildcard_cors():
    try:
        Settings(
            env="prod",
            api_key="prod-secret-key",
            operator_api_key="operator-secret",
            cors_allowed_origins=["*"],
        )
    except ValueError as exc:
        assert "wildcard CORS" in str(exc)
    else:
        raise AssertionError("prod should reject wildcard CORS")


def test_invalid_credential_master_key_error_never_contains_the_key():
    invalid_key = "credential-master-key-canary-never-echo"
    settings = Settings(credential_encryption_key=invalid_key)
    assert settings.credential_encryption_key is not None

    try:
        CredentialVault(settings.credential_encryption_key.get_secret_value())
    except ValueError as exc:
        assert invalid_key not in str(exc)
    else:
        raise AssertionError("invalid Fernet key should be rejected")


def test_empty_credential_encryption_key_keeps_optional_vault_disabled():
    settings = Settings(credential_encryption_key="")

    assert settings.credential_encryption_key is None


def test_openbao_audit_signing_requires_a_credential_free_endpoint_and_secret_token():
    with pytest.raises(ValueError, match="requires AGENTOPS_OPENBAO_URL"):
        Settings(_env_file=None, audit_checkpoint_backend="openbao")

    settings = Settings(
        _env_file=None,
        audit_checkpoint_backend="openbao",
        openbao_url="https://openbao.test",
        openbao_token="test-only-token",
        openbao_transit_mount="audit-transit",
        audit_checkpoint_key_name="agentops-audit-v1",
    )

    assert settings.audit_checkpoint_backend == "openbao"
    assert settings.openbao_token is not None
    assert "test-only-token" not in repr(settings.openbao_token)


def test_semantic_scanner_is_disabled_when_model_configuration_is_absent(monkeypatch):
    for variable in (
        "AGENTOPS_SEMANTIC_SCANNER_MODE",
        "AGENTOPS_SEMANTIC_MODEL_PATH",
        "AGENTOPS_SEMANTIC_MODEL_SHA256",
        "AGENTOPS_SEMANTIC_SCANNER_THRESHOLD",
    ):
        monkeypatch.delenv(variable, raising=False)

    settings = Settings(_env_file=None)

    assert settings.semantic_scanner_mode == "disabled"
    assert settings.semantic_model_path is None


def test_semantic_scanner_enforce_mode_is_not_available_before_promotion(tmp_path):
    with pytest.raises(ValueError, match="has not passed the promotion gates"):
        Settings(
            _env_file=None,
            semantic_scanner_mode="enforce",
            semantic_model_path=tmp_path,
            semantic_model_sha256="0" * 64,
        )


def test_shadow_scanner_can_use_credential_free_remote_service_without_local_weights():
    settings = Settings(
        _env_file=None,
        semantic_scanner_mode="shadow",
        semantic_service_url="http://semantic-scanner:8090",
    )

    assert settings.semantic_service_url == "http://semantic-scanner:8090"
    assert settings.semantic_model_path is None


def test_semantic_service_url_rejects_credentials_and_query_parameters():
    with pytest.raises(ValueError, match="credential-free HTTP base URL"):
        Settings(
            _env_file=None,
            semantic_scanner_mode="shadow",
            semantic_service_url="http://user:secret@semantic.test:8090?token=value",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://user:secret@opa.test:8181",
        "http://opa.test:8181?token=value",
        "http://opa.test:8181/policy",
    ],
)
def test_opa_url_rejects_credentials_query_parameters_and_paths(url):
    with pytest.raises(ValueError, match="credential-free HTTP base URL"):
        Settings(_env_file=None, opa_url=url)


def test_expected_opa_policy_revision_requires_opa_and_exact_identifier():
    with pytest.raises(ValueError, match="requires AGENTOPS_OPA_URL"):
        Settings(_env_file=None, opa_expected_policy_revision="agentops-guard-v1")
    with pytest.raises(ValueError, match="EXPECTED_POLICY_REVISION is invalid"):
        Settings(
            _env_file=None,
            opa_url="http://opa.test:8181",
            opa_expected_policy_revision="agentops guard/v1",
        )


def test_production_opa_requires_exact_expected_policy_revision():
    with pytest.raises(
        ValueError, match="production OPA requires an exact expected policy revision"
    ):
        Settings(
            _env_file=None,
            env="prod",
            component="worker",
            opa_url="http://opa.test:8181",
            allow_schema_bootstrap=False,
        )

    settings = Settings(
        _env_file=None,
        env="prod",
        component="worker",
        opa_url="http://opa.test:8181",
        opa_expected_policy_revision="agentops-guard-v1",
        allow_schema_bootstrap=False,
    )
    assert settings.opa_expected_policy_revision == "agentops-guard-v1"


def test_telemetry_endpoint_rejects_credentials_without_echoing_them():
    canary = "collector-password-canary"

    with pytest.raises(ValueError, match="credential-free HTTP base URL") as error:
        Settings(
            _env_file=None,
            otel_exporter_otlp_endpoint=f"http://user:{canary}@collector.test:4317",
        )

    assert canary not in str(error.value)


def test_telemetry_service_name_rejects_unbounded_metadata_without_echoing_it():
    canary = "private.service=value"

    with pytest.raises(ValueError, match="fixed AgentOps component identifier") as error:
        Settings(_env_file=None, otel_service_name=canary)

    assert canary not in str(error.value)


def test_production_shadow_scanner_requires_isolated_service(tmp_path):
    with pytest.raises(ValueError, match="requires an isolated model service"):
        Settings(
            _env_file=None,
            env="prod",
            api_key="non-default-api-key",
            operator_api_key="non-default-operator-key",
            cors_allowed_origins=["https://guard.example"],
            allow_schema_bootstrap=False,
            semantic_scanner_mode="shadow",
            semantic_model_path=tmp_path,
            semantic_model_sha256="0" * 64,
        )


def test_comma_separated_mcp_allowlists_are_parsed_from_environment(monkeypatch):
    monkeypatch.setenv("AGENTOPS_MCP_ALLOWED_HOSTS", "guard.example, guard.example:*")
    monkeypatch.setenv(
        "AGENTOPS_MCP_ALLOWED_ORIGINS",
        "https://console.example, https://admin.example",
    )

    settings = Settings(_env_file=None)

    assert settings.mcp_allowed_hosts == ["guard.example", "guard.example:*"]
    assert settings.mcp_allowed_origins == [
        "https://console.example",
        "https://admin.example",
    ]


def test_mcp_public_url_rejects_embedded_credentials():
    with pytest.raises(ValueError, match="credential-free /mcp HTTP URL"):
        Settings(
            _env_file=None,
            mcp_public_url="https://user:secret@guard.example/mcp",
        )


def test_production_mcp_public_url_requires_https():
    with pytest.raises(ValueError, match="production MCP public URL must use HTTPS"):
        Settings(
            _env_file=None,
            env="prod",
            api_key="non-default-api-key",
            operator_api_key="non-default-operator-key",
            cors_allowed_origins=["https://guard.example"],
            allow_schema_bootstrap=False,
            mcp_public_url="http://guard.example/mcp",
            mcp_allowed_hosts=["guard.example"],
            mcp_allowed_origins=["https://guard.example"],
            component="gateway",
        )


@pytest.mark.parametrize(
    "component",
    [
        "worker",
        "outbox_dispatcher",
        "semantic_scanner",
        "audit_anchor_exporter",
        "migration",
    ],
)
def test_non_api_production_components_do_not_require_api_management_keys(component):
    settings = Settings(
        _env_file=None,
        env="prod",
        component=component,
        cors_allowed_origins=["*"],
        allow_schema_bootstrap=False,
    )

    assert settings.component == component


def test_production_gateway_still_rejects_default_api_key():
    with pytest.raises(ValueError, match="default development API key"):
        Settings(
            _env_file=None,
            env="prod",
            component="gateway",
            mcp_public_url="https://guard.example/mcp",
            mcp_allowed_hosts=["guard.example"],
            mcp_allowed_origins=["https://guard.example"],
        )
