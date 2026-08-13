"""Shared fixtures for Agent test system."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("AGENTOPS_ENV", "dev")
os.environ.setdefault("AGENTOPS_ALLOW_SCHEMA_BOOTSTRAP", "true")


@pytest.fixture
def attack_cases():
    """All attack cases from the library."""
    from .attack_cases import ATTACK_CASES
    return ATTACK_CASES


@pytest.fixture
def attack_only_cases():
    """Only non-benign attack cases."""
    from .attack_cases import get_attack_cases
    return get_attack_cases()


@pytest.fixture
def benign_cases():
    """Only benign cases (should pass through)."""
    from .attack_cases import get_benign_cases
    return get_benign_cases()
