import base64
import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from agentops_guard.backend.api.routes_credentials import (
    get_credential_vault,
    get_deepseek_transport,
)
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.main import app
from agentops_guard.backend.models import AuditLog, Membership, ServiceCredential, User
from agentops_guard.backend.services.credentials import CredentialVault
from agentops_guard.backend.services.deepseek import DeepSeekTransport
from agentops_guard.backend.services.projects import ensure_project


OPERATOR_HEADERS = {"X-AgentOps-Api-Key": "dev-agentops-key"}
FERNET_KEY = base64.urlsafe_b64encode(b"agentops-guard-test-fernet-key!!").decode()
DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"


class RecordingVault(CredentialVault):
    def __init__(self) -> None:
        super().__init__(key=FERNET_KEY)
        self.encrypt_calls: list[str] = []
        self.decrypt_calls: list[str] = []
        self.decrypt_error: Exception | None = None

    def encrypt(self, secret: str) -> str:
        self.encrypt_calls.append(secret)
        return super().encrypt(secret)

    def decrypt(self, ciphertext: str) -> str:
        self.decrypt_calls.append(ciphertext)
        if self.decrypt_error is not None:
            raise self.decrypt_error
        return super().decrypt(ciphertext)


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def chat_completions(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(
            {
                "credential_ref": kwargs["credential_ref"],
                "model": kwargs["model"],
                "messages": kwargs["messages"],
                "max_tokens": kwargs["max_tokens"],
            }
        )
        return {"id": "chatcmpl-test", "choices": []}


@dataclass
class CredentialHarness:
    client: TestClient
    vault: RecordingVault
    transport: RecordingTransport


@pytest.fixture
def credential_harness() -> Iterator[CredentialHarness]:
    vault = RecordingVault()
    transport = RecordingTransport()
    app.dependency_overrides[get_credential_vault] = lambda: vault
    app.dependency_overrides[get_deepseek_transport] = lambda: transport
    try:
        with TestClient(app) as client:
            yield CredentialHarness(client=client, vault=vault, transport=transport)
    finally:
        app.dependency_overrides.pop(get_credential_vault, None)
        app.dependency_overrides.pop(get_deepseek_transport, None)


def _new_project(prefix: str) -> str:
    project_id = f"{prefix}_{uuid4().hex}"
    db = SessionLocal()
    try:
        ensure_project(db, project_id)
        db.commit()
    finally:
        db.close()
    return project_id


def _create_credential(
    harness: CredentialHarness,
    *,
    project_id: str,
    secret: str,
    allowed_actor_ids: list[str] | None = None,
) -> str:
    response = harness.client.post(
        "/v1/credentials/deepseek",
        headers=OPERATOR_HEADERS,
        json={
            "project_id": project_id,
            "name": "DeepSeek benchmark",
            "secret": secret,
            "allowed_actor_ids": allowed_actor_ids if allowed_actor_ids is not None else [],
        },
    )
    assert response.status_code == 200, response.text
    assert set(response.json()) == {"credential_ref"}
    assert secret not in response.text
    return response.json()["credential_ref"]


def _call_deepseek(
    harness: CredentialHarness,
    *,
    project_id: str,
    credential_ref: str,
    extra: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
):
    payload: dict[str, Any] = {
        "project_id": project_id,
        "credential_ref": credential_ref,
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": "Reply with hello"}],
        "max_tokens": 16,
    }
    payload.update(extra or {})
    return harness.client.post(
        "/v1/deepseek/chat/completions",
        headers=headers or OPERATOR_HEADERS,
        json=payload,
    )


def _create_project_key(
    harness: CredentialHarness,
    *,
    project_id: str,
    scopes: list[str],
) -> tuple[str, dict[str, str]]:
    response = harness.client.post(
        "/v1/api-keys",
        headers=OPERATOR_HEADERS,
        json={
            "project_id": project_id,
            "name": f"credential-test-{uuid4().hex}",
            "scopes": scopes,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["id"], {"X-AgentOps-Api-Key": body["token"]}


def _non_encrypted_orm_values(row: ServiceCredential) -> dict[str, Any]:
    return {
        attribute.key: getattr(row, attribute.key)
        for attribute in inspect(row).mapper.column_attrs
        if attribute.key not in {"encrypted_secret", "binding_ciphertext"}
    }


def test_fernet_vault_round_trip_does_not_store_plaintext():
    secret = f"deepseek-canary-{uuid4().hex}-NEVER-STORE-PLAIN"
    vault = CredentialVault(key=FERNET_KEY)

    ciphertext = vault.encrypt(secret)

    assert isinstance(ciphertext, str)
    assert ciphertext != secret
    assert secret not in ciphertext
    assert vault.decrypt(ciphertext) == secret


def test_admin_create_returns_only_ref_and_plaintext_is_absent_from_metadata_audit_and_logs(
    credential_harness: CredentialHarness,
    capsys: pytest.CaptureFixture[str],
):
    project_id = _new_project("credential_create")
    secret = f"deepseek-canary-{uuid4().hex}-NEVER-LOG"

    credential_ref = _create_credential(
        credential_harness,
        project_id=project_id,
        secret=secret,
        allowed_actor_ids=["operator"],
    )
    captured = capsys.readouterr()

    db = SessionLocal()
    try:
        row = db.get(ServiceCredential, credential_ref)
        assert row is not None
        assert row.encrypted_secret != secret
        assert secret not in row.encrypted_secret
        assert secret not in json.dumps(_non_encrypted_orm_values(row), default=str)

        audits = db.query(AuditLog).filter(AuditLog.project_id == project_id).all()
        assert audits
        audit_payload = [
            {
                "before": audit.before,
                "after": audit.after,
                "metadata": audit.metadata_json,
            }
            for audit in audits
        ]
        assert secret not in json.dumps(audit_payload, default=str)
    finally:
        db.close()

    assert credential_harness.vault.encrypt_calls[0] == secret
    assert len(credential_harness.vault.encrypt_calls) == 2
    assert secret not in captured.out
    assert secret not in captured.err


def test_json_escaping_cannot_hide_plaintext_secret_in_credential_metadata(
    credential_harness: CredentialHarness,
    capsys: pytest.CaptureFixture[str],
):
    project_id = _new_project("credential_metadata_escape")
    secret = 'deepseek-canary-with-"-quote'

    response = credential_harness.client.post(
        "/v1/credentials/deepseek",
        headers=OPERATOR_HEADERS,
        json={
            "project_id": project_id,
            "name": f"managed {secret}",
            "secret": secret,
            "allowed_actor_ids": ["operator"],
        },
    )
    captured = capsys.readouterr()

    assert response.status_code == 400
    assert credential_harness.vault.encrypt_calls == []
    assert secret not in response.text
    assert secret not in captured.out
    assert secret not in captured.err


def test_non_admin_cannot_create_or_encrypt_a_credential(
    credential_harness: CredentialHarness,
    capsys: pytest.CaptureFixture[str],
):
    project_id = _new_project("credential_non_admin")
    secret = f"deepseek-canary-{uuid4().hex}-DENIED"
    suffix = uuid4().hex
    login = credential_harness.client.post(
        "/v1/auth/dev-login",
        json={
            "email": f"reader-{suffix}@example.test",
            "display_name": "Credential Reader",
            "role": "read_only",
            "organization_name": f"Credential Reader {suffix}",
        },
    )
    assert login.status_code == 200
    credential_harness.client.cookies.update(login.cookies)

    response = credential_harness.client.post(
        "/v1/credentials/deepseek",
        json={
            "project_id": project_id,
            "name": "Must not be created",
            "secret": secret,
            "allowed_actor_ids": [],
        },
    )
    captured = capsys.readouterr()

    assert response.status_code == 403
    assert credential_harness.vault.encrypt_calls == []
    assert secret not in response.text
    assert secret not in captured.out
    assert secret not in captured.err


@pytest.mark.parametrize("disabled_record", ["membership", "user"])
def test_disabled_admin_session_immediately_loses_credential_access(
    credential_harness: CredentialHarness,
    disabled_record: str,
):
    suffix = uuid4().hex
    login = credential_harness.client.post(
        "/v1/auth/dev-login",
        json={
            "email": f"disabled-admin-{suffix}@example.test",
            "display_name": "Disabled Admin",
            "role": "admin",
            "organization_name": f"Disabled Admin {suffix}",
        },
    )
    assert login.status_code == 200
    credential_harness.client.cookies.update(login.cookies)
    project_id = login.json()["project_id"]

    db = SessionLocal()
    try:
        membership = db.get(Membership, login.json()["membership"]["id"])
        user = db.get(User, login.json()["user"]["id"])
        assert membership is not None
        assert user is not None
        if disabled_record == "membership":
            membership.status = "disabled"
        else:
            user.status = "disabled"
        db.commit()
    finally:
        db.close()

    response = credential_harness.client.post(
        "/v1/credentials/deepseek",
        json={
            "project_id": project_id,
            "name": "Must not be created",
            "secret": f"deepseek-canary-{uuid4().hex}-DENIED",
            "allowed_actor_ids": [],
        },
    )

    assert response.status_code == 401
    assert credential_harness.vault.encrypt_calls == []


def test_developer_session_cannot_create_a_credential(
    credential_harness: CredentialHarness,
):
    suffix = uuid4().hex
    login = credential_harness.client.post(
        "/v1/auth/dev-login",
        json={
            "email": f"developer-{suffix}@example.test",
            "display_name": "Developer",
            "role": "developer",
            "organization_name": f"Developer {suffix}",
        },
    )
    assert login.status_code == 200
    credential_harness.client.cookies.update(login.cookies)

    response = credential_harness.client.post(
        "/v1/credentials/deepseek",
        json={
            "project_id": login.json()["project_id"],
            "name": "Must not be created",
            "secret": f"deepseek-canary-{uuid4().hex}-DENIED",
            "allowed_actor_ids": [],
        },
    )

    assert response.status_code == 403
    assert credential_harness.vault.encrypt_calls == []


@pytest.mark.parametrize(
    ("extra", "marker"),
    [
        ({"secret": "raw-secret-must-not-echo"}, "raw-secret-must-not-echo"),
        ({"api_key": "raw-api-key-must-not-echo"}, "raw-api-key-must-not-echo"),
        (
            {"authorization": "Bearer raw-header-must-not-echo"},
            "raw-header-must-not-echo",
        ),
        (
            {"headers": {"Authorization": "Bearer nested-header-must-not-echo"}},
            "nested-header-must-not-echo",
        ),
        ({"base_url": "https://attacker.invalid/steal"}, "attacker.invalid"),
        ({"url": "https://attacker.invalid/steal"}, "attacker.invalid"),
        ({"agent_id": "operator"}, "operator"),
        ({"actor_id": "operator"}, "operator"),
        ({"allowed_actor_ids": ["operator"]}, "allowed_actor_ids"),
    ],
)
def test_agent_request_rejects_raw_credentials_destinations_and_spoofed_identity_without_echo_or_io(
    credential_harness: CredentialHarness,
    capsys: pytest.CaptureFixture[str],
    extra: dict[str, Any],
    marker: str,
):
    project_id = _new_project("credential_invalid_input")

    response = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref="cred_invalid_input",
        extra=extra,
    )
    captured = capsys.readouterr()

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert marker not in response.text
    assert marker not in captured.out
    assert marker not in captured.err
    assert credential_harness.vault.decrypt_calls == []
    assert credential_harness.transport.calls == []


@pytest.mark.parametrize(
    ("attribute", "invalid_value"),
    [
        ("project_id", "different-project"),
        ("provider", "openai"),
        ("tool", "responses"),
        ("origin", "https://attacker.invalid"),
        ("status", "revoked"),
        ("version", 0),
        ("allowed_actor_ids", []),
    ],
)
def test_invalid_credential_metadata_is_rejected_before_decryption_or_http(
    credential_harness: CredentialHarness,
    attribute: str,
    invalid_value: Any,
):
    project_id = _new_project("credential_fail_closed")
    credential_ref = _create_credential(
        credential_harness,
        project_id=project_id,
        secret=f"deepseek-canary-{uuid4().hex}-UNUSED",
        allowed_actor_ids=["operator"],
    )
    credential_harness.vault.decrypt_calls.clear()

    db = SessionLocal()
    try:
        row = db.get(ServiceCredential, credential_ref)
        assert row is not None
        setattr(row, attribute, invalid_value)
        db.commit()
    finally:
        db.close()

    response = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref=credential_ref,
    )

    assert 400 <= response.status_code < 500
    assert credential_harness.vault.decrypt_calls == []
    assert credential_harness.transport.calls == []

def test_vault_failure_never_calls_deepseek(
    credential_harness: CredentialHarness,
):
    project_id = _new_project("credential_vault_failure")
    credential_ref = _create_credential(
        credential_harness,
        project_id=project_id,
        secret=f"deepseek-canary-{uuid4().hex}-VAULT-FAIL",
        allowed_actor_ids=["operator"],
    )
    credential_harness.vault.decrypt_calls.clear()
    credential_harness.vault.decrypt_error = ValueError("invalid Fernet token")

    response = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref=credential_ref,
    )

    assert response.status_code >= 400
    assert len(credential_harness.vault.decrypt_calls) == 1
    assert credential_harness.transport.calls == []


def test_unknown_credential_ref_never_decrypts_or_calls_deepseek(
    credential_harness: CredentialHarness,
):
    project_id = _new_project("credential_unknown_ref")

    response = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref=f"cred_missing_{uuid4().hex}",
    )

    assert 400 <= response.status_code < 500
    assert credential_harness.vault.decrypt_calls == []
    assert credential_harness.transport.calls == []


def test_rotate_keeps_reference_increments_version_and_revoke_blocks_before_decryption(
    credential_harness: CredentialHarness,
):
    project_id = _new_project("credential_rotate")
    first_secret = f"deepseek-canary-{uuid4().hex}-V1"
    second_secret = f"deepseek-canary-{uuid4().hex}-V2"
    credential_ref = _create_credential(
        credential_harness,
        project_id=project_id,
        secret=first_secret,
        allowed_actor_ids=["operator"],
    )

    db = SessionLocal()
    try:
        first_row = db.get(ServiceCredential, credential_ref)
        assert first_row is not None
        first_version = first_row.version
        first_ciphertext = first_row.encrypted_secret
    finally:
        db.close()

    rotated = credential_harness.client.put(
        f"/v1/credentials/{credential_ref}/rotate",
        headers=OPERATOR_HEADERS,
        json={"project_id": project_id, "secret": second_secret},
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json() == {"credential_ref": credential_ref}

    db = SessionLocal()
    try:
        rotated_row = db.get(ServiceCredential, credential_ref)
        assert rotated_row is not None
        assert rotated_row.version == first_version + 1
        assert rotated_row.encrypted_secret != first_ciphertext
        assert first_secret not in rotated_row.encrypted_secret
        assert second_secret not in rotated_row.encrypted_secret
    finally:
        db.close()

    revoked = credential_harness.client.delete(
        f"/v1/credentials/{credential_ref}",
        headers=OPERATOR_HEADERS,
        params={"project_id": project_id},
    )
    assert 200 <= revoked.status_code < 300, revoked.text
    credential_harness.vault.decrypt_calls.clear()

    response = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref=credential_ref,
    )

    assert 400 <= response.status_code < 500
    assert credential_harness.vault.decrypt_calls == []
    assert credential_harness.transport.calls == []

    db = SessionLocal()
    try:
        revoked_row = db.get(ServiceCredential, credential_ref)
        assert revoked_row is not None
        revoked_row.status = "active"
        revoked_row.revoked_at = None
        db.commit()
    finally:
        db.close()

    reactivated = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref=credential_ref,
    )
    assert reactivated.status_code == 503
    assert credential_harness.transport.calls == []


def test_rotate_rejects_a_secret_already_present_in_plaintext_metadata(
    credential_harness: CredentialHarness,
):
    project_id = _new_project("credential_rotate_metadata")
    replacement_secret = 'deepseek-canary-with-"-quote'
    created = credential_harness.client.post(
        "/v1/credentials/deepseek",
        headers=OPERATOR_HEADERS,
        json={
            "project_id": project_id,
            "name": f"reserved {replacement_secret}",
            "secret": f"deepseek-canary-{uuid4().hex}-ORIGINAL",
            "allowed_actor_ids": ["operator"],
        },
    )
    assert created.status_code == 200, created.text
    credential_ref = created.json()["credential_ref"]

    db = SessionLocal()
    try:
        row = db.get(ServiceCredential, credential_ref)
        assert row is not None
        original_version = row.version
        original_secret_ciphertext = row.encrypted_secret
        original_binding_ciphertext = row.binding_ciphertext
    finally:
        db.close()
    credential_harness.vault.encrypt_calls.clear()

    response = credential_harness.client.put(
        f"/v1/credentials/{credential_ref}/rotate",
        headers=OPERATOR_HEADERS,
        json={"project_id": project_id, "secret": replacement_secret},
    )

    assert response.status_code == 400
    assert replacement_secret not in response.text
    assert credential_harness.vault.encrypt_calls == []
    db = SessionLocal()
    try:
        row = db.get(ServiceCredential, credential_ref)
        assert row is not None
        assert row.version == original_version
        assert row.encrypted_secret == original_secret_ciphertext
        assert row.binding_ciphertext == original_binding_ciphertext
    finally:
        db.close()


def test_ciphertext_cannot_be_swapped_between_credential_references(
    credential_harness: CredentialHarness,
):
    project_id = _new_project("credential_ciphertext_swap")
    first_ref = _create_credential(
        credential_harness,
        project_id=project_id,
        secret=f"deepseek-canary-{uuid4().hex}-FIRST",
        allowed_actor_ids=["operator"],
    )
    second_ref = _create_credential(
        credential_harness,
        project_id=project_id,
        secret=f"deepseek-canary-{uuid4().hex}-SECOND",
        allowed_actor_ids=["operator"],
    )

    db = SessionLocal()
    try:
        first = db.get(ServiceCredential, first_ref)
        second = db.get(ServiceCredential, second_ref)
        assert first is not None
        assert second is not None
        first.encrypted_secret = second.encrypted_secret
        db.commit()
    finally:
        db.close()
    credential_harness.vault.decrypt_calls.clear()

    response = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref=first_ref,
    )

    assert response.status_code == 503
    assert credential_harness.transport.calls == []


def test_rotate_refuses_to_seal_tampered_actor_binding(
    credential_harness: CredentialHarness,
):
    project_id = _new_project("credential_rotate_tamper")
    credential_ref = _create_credential(
        credential_harness,
        project_id=project_id,
        secret=f"deepseek-canary-{uuid4().hex}-ORIGINAL",
        allowed_actor_ids=["operator"],
    )

    db = SessionLocal()
    try:
        row = db.get(ServiceCredential, credential_ref)
        assert row is not None
        row.allowed_actor_ids = ["attacker"]
        original_version = row.version
        original_secret_ciphertext = row.encrypted_secret
        original_binding_ciphertext = row.binding_ciphertext
        db.commit()
    finally:
        db.close()
    credential_harness.vault.encrypt_calls.clear()

    response = credential_harness.client.put(
        f"/v1/credentials/{credential_ref}/rotate",
        headers=OPERATOR_HEADERS,
        json={
            "project_id": project_id,
            "secret": f"deepseek-canary-{uuid4().hex}-REPLACEMENT",
        },
    )

    assert response.status_code == 409
    assert credential_harness.vault.encrypt_calls == []
    db = SessionLocal()
    try:
        row = db.get(ServiceCredential, credential_ref)
        assert row is not None
        assert row.version == original_version
        assert row.encrypted_secret == original_secret_ciphertext
        assert row.binding_ciphertext == original_binding_ciphertext
    finally:
        db.close()


def test_project_api_key_requires_scope_actor_and_matching_project_before_decrypt(
    credential_harness: CredentialHarness,
):
    project_id = _new_project("credential_project_key")
    other_project_id = _new_project("credential_other_project")
    allowed_id, allowed_headers = _create_project_key(
        credential_harness,
        project_id=project_id,
        scopes=["models:invoke"],
    )
    wrong_actor_id, wrong_actor_headers = _create_project_key(
        credential_harness,
        project_id=project_id,
        scopes=["models:invoke"],
    )
    assert wrong_actor_id != allowed_id
    no_scope_id, no_scope_headers = _create_project_key(
        credential_harness,
        project_id=project_id,
        scopes=["runs:read"],
    )
    credential_ref = _create_credential(
        credential_harness,
        project_id=project_id,
        secret=f"deepseek-canary-{uuid4().hex}-PROJECT-KEY",
        allowed_actor_ids=[allowed_id, no_scope_id],
    )

    credential_harness.vault.decrypt_calls.clear()
    allowed = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref=credential_ref,
        headers=allowed_headers,
    )
    assert allowed.status_code == 200, allowed.text
    assert credential_harness.transport.calls[-1]["credential_ref"] == credential_ref

    credential_harness.vault.decrypt_calls.clear()
    credential_harness.transport.calls.clear()
    no_scope = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref=credential_ref,
        headers=no_scope_headers,
    )
    assert no_scope.status_code == 403
    assert credential_harness.vault.decrypt_calls == []
    assert credential_harness.transport.calls == []

    wrong_actor = _call_deepseek(
        credential_harness,
        project_id=project_id,
        credential_ref=credential_ref,
        headers=wrong_actor_headers,
    )
    assert wrong_actor.status_code == 403
    assert credential_harness.vault.decrypt_calls == []
    assert credential_harness.transport.calls == []

    cross_project = _call_deepseek(
        credential_harness,
        project_id=other_project_id,
        credential_ref=credential_ref,
        headers=allowed_headers,
    )
    assert cross_project.status_code == 403
    assert credential_harness.vault.decrypt_calls == []
    assert credential_harness.transport.calls == []


@pytest.mark.parametrize("secret", ["line-break\nsecret", "非ASCII密钥"])
def test_invalid_credential_secret_is_rejected_without_echo_or_encryption(
    credential_harness: CredentialHarness,
    secret: str,
):
    project_id = _new_project("credential_invalid_secret")

    response = credential_harness.client.post(
        "/v1/credentials/deepseek",
        headers=OPERATOR_HEADERS,
        json={
            "project_id": project_id,
            "name": "invalid secret",
            "secret": secret,
            "allowed_actor_ids": ["operator"],
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert secret not in response.text
    assert credential_harness.vault.encrypt_calls == []


def test_authorized_call_exposes_plaintext_only_in_final_http_authorization_header(
    credential_harness: CredentialHarness,
    capsys: pytest.CaptureFixture[str],
):
    project_id = _new_project("credential_success")
    secret = f"deepseek-canary-{uuid4().hex}-FINAL-HEADER-ONLY"
    credential_ref = _create_credential(
        credential_harness,
        project_id=project_id,
        secret=secret,
        allowed_actor_ids=["operator"],
    )
    provider_response = {
        "id": "chatcmpl-closed-loop",
        "choices": [{"message": {"role": "assistant", "content": "hello"}}],
    }
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=provider_response)

    with httpx.Client(transport=httpx.MockTransport(handler)) as provider_client:
        app.dependency_overrides[get_deepseek_transport] = lambda: DeepSeekTransport(
            client=provider_client
        )
        response = _call_deepseek(
            credential_harness,
            project_id=project_id,
            credential_ref=credential_ref,
        )
    captured = capsys.readouterr()

    assert response.status_code == 200, response.text
    assert response.json() == provider_response
    assert len(requests) == 1
    request = requests[0]
    assert str(request.url) == DEEPSEEK_URL
    assert request.headers.get_list("authorization") == [f"Bearer {secret}"]

    non_authorization_headers = [
        (name, value)
        for name, value in request.headers.multi_items()
        if name.lower() != "authorization"
    ]
    assert secret not in str(request.url)
    assert secret not in request.content.decode()
    assert secret not in json.dumps(non_authorization_headers)
    assert secret not in response.text
    assert secret not in captured.out
    assert secret not in captured.err

    db = SessionLocal()
    try:
        row = db.get(ServiceCredential, credential_ref)
        assert row is not None
        assert secret not in json.dumps(_non_encrypted_orm_values(row), default=str)
        audits = db.query(AuditLog).filter(AuditLog.project_id == project_id).all()
        assert secret not in json.dumps(
            [
                {
                    "before": audit.before,
                    "after": audit.after,
                    "metadata": audit.metadata_json,
                }
                for audit in audits
            ],
            default=str,
        )
    finally:
        db.close()
