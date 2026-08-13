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
