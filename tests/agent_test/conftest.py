"""Shared fixtures for Agent test system."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("AGENTOPS_ENV", "dev")
os.environ.setdefault("AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP", "true")


@pytest.fixture
def mimo_config():
    """MiMo API configuration from environment."""
    from tests.agent_test.mimo_client import MiMoConfig
    config = MiMoConfig()
    config.api_key = os.environ.get("MIMO_API_KEY", config.api_key)
    config.base_url = os.environ.get("MIMO_BASE_URL", config.base_url)
    config.model = os.environ.get("MIMO_MODEL", config.model)
    return config


@pytest.fixture
def mimo_client(mimo_config):
    """MiMo API client instance."""
    from tests.agent_test.mimo_client import MiMoClient
    return MiMoClient(mimo_config)


@pytest.fixture
def attack_cases():
    """All attack cases from the library."""
    from tests.agent_test.attack_cases import ATTACK_CASES
    return ATTACK_CASES


@pytest.fixture
def attack_only_cases():
    """Only non-benign attack cases."""
    from tests.agent_test.attack_cases import get_attack_cases
    return get_attack_cases()


@pytest.fixture
def benign_cases():
    """Only benign cases (should pass through)."""
    from tests.agent_test.attack_cases import get_benign_cases
    return get_benign_cases()
