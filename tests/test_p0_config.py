from agentops_guard.backend.config import Settings


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
