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
