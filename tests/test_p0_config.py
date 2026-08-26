import pytest

from agentops_guard.backend.config import Settings
from agentops_guard.backend.services.credentials import CredentialVault


def test_SPEC_P0_002_prod_settings_reject_default_dev_key():
    try:
        Settings(env="prod", api_key="dev-agentops-key", cors_allowed_origins=["https://ops.example"])
    except ValueError as exc:
        assert "default development API key" in str(exc)
    else:
        raise AssertionError("prod should reject default dev API key")


def test_SPEC_P0_002_prod_settings_reject_wildcard_cors():
    try:
        Settings(env="prod", api_key="prod-secret-key", operator_api_key="operator-secret", cors_allowed_origins=["*"])
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
