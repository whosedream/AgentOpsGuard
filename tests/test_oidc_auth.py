from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from agentops_guard.backend import auth
from agentops_guard.backend.database import SessionLocal
from agentops_guard.backend.main import app
from agentops_guard.backend.models import Membership, Organization, Project, User
from agentops_guard.backend.services import oidc
from agentops_guard.backend.services.content import new_id
from agentops_guard.backend.services.oidc import oidc_external_subject


def _auth_settings() -> SimpleNamespace:
    return SimpleNamespace(
        effective_operator_api_key="dev-agentops-key",
        oidc_issuer="https://issuer.example",
    )


def test_workload_token_binds_project_and_agent(monkeypatch):
    project_id = f"oidc_workload_{uuid4().hex}"
    db = SessionLocal()
    try:
        organization = Organization(
            id=new_id("org"),
            slug=f"oidc-{uuid4().hex}",
            name="OIDC workload test",
        )
        db.add(organization)
        db.flush()
        db.add(Project(id=project_id, organization_id=organization.id, name=project_id))
        db.commit()
    finally:
        db.close()

    monkeypatch.setattr(auth, "get_settings", _auth_settings)
    monkeypatch.setattr(
        auth,
        "verify_oidc_token",
        lambda _token: {
            "sub": "workload-123",
            "token_use": "agent",
            "project_id": project_id,
            "agent_id": "trusted-agent",
            "scope": "runs:write mcp:invoke",
        },
    )
    client = TestClient(app)
    headers = {"Authorization": "Bearer header.payload.signature"}

    forged = client.post(
        "/v1/runs",
        headers=headers,
        json={"project_id": project_id, "agent_id": "forged-agent"},
    )
    assert forged.status_code == 403
    created = client.post(
        "/v1/runs",
        headers=headers,
        json={"project_id": project_id, "agent_id": "trusted-agent"},
    )
    assert created.status_code == 200
    assert created.json()["agent_id"] == "trusted-agent"


def test_preprovisioned_oidc_user_gets_database_membership_capabilities(monkeypatch):
    issuer = "https://issuer.example"
    subject = f"person-{uuid4().hex}"
    db = SessionLocal()
    try:
        organization = Organization(
            id=new_id("org"),
            slug=f"oidc-user-{uuid4().hex}",
            name="OIDC user test",
        )
        user = User(
            id=new_id("user"),
            email=f"{uuid4().hex}@example.com",
            display_name="OIDC user",
            auth_provider="oidc",
            external_subject=oidc_external_subject(issuer, subject),
            status="active",
        )
        db.add_all([organization, user])
        db.flush()
        membership = Membership(
            id=new_id("membership"),
            organization_id=organization.id,
            user_id=user.id,
            role="developer",
            status="active",
        )
        project = Project(
            id=new_id("project"),
            organization_id=organization.id,
            name="OIDC project",
        )
        db.add_all([membership, project])
        db.commit()
        organization_id = organization.id
    finally:
        db.close()

    monkeypatch.setattr(auth, "get_settings", _auth_settings)
    monkeypatch.setattr(
        auth,
        "verify_oidc_token",
        lambda _token: {
            "sub": subject,
            "organization_id": organization_id,
        },
    )
    response = TestClient(app).get(
        "/v1/auth/context",
        headers={"Authorization": "Bearer header.payload.signature"},
    )

    assert response.status_code == 200
    assert response.json()["kind"] == "oidc_user"
    assert "mcp:invoke" in response.json()["capabilities"]


def test_oidc_verifier_rejects_wrong_audience(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "subject",
            "iss": "https://issuer.example",
            "aud": "wrong-audience",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    monkeypatch.setattr(
        oidc,
        "get_settings",
        lambda: SimpleNamespace(
            oidc_issuer="https://issuer.example",
            oidc_audience="agentops-guard",
            oidc_jwks_url="https://issuer.example/jwks",
            oidc_timeout_seconds=1.0,
            oidc_max_token_bytes=16_384,
            oidc_max_token_lifetime_seconds=900,
        ),
    )
    monkeypatch.setattr(
        oidc,
        "_jwks_client",
        lambda *_args: SimpleNamespace(
            get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=private_key.public_key())
        ),
    )

    try:
        oidc.verify_oidc_token(token)
    except oidc.OidcTokenInvalid:
        pass
    else:
        raise AssertionError("a token for another audience must be rejected")


def test_oidc_verifier_rejects_excessive_token_lifetime(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "subject",
            "iss": "https://issuer.example",
            "aud": "agentops-guard",
            "iat": now,
            "exp": now + timedelta(hours=1),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    monkeypatch.setattr(
        oidc,
        "get_settings",
        lambda: SimpleNamespace(
            oidc_issuer="https://issuer.example",
            oidc_audience="agentops-guard",
            oidc_jwks_url="https://issuer.example/jwks",
            oidc_timeout_seconds=1.0,
            oidc_max_token_bytes=16_384,
            oidc_max_token_lifetime_seconds=900,
        ),
    )
    monkeypatch.setattr(
        oidc,
        "_jwks_client",
        lambda *_args: SimpleNamespace(
            get_signing_key_from_jwt=lambda _token: SimpleNamespace(
                key=private_key.public_key()
            )
        ),
    )

    with pytest.raises(oidc.OidcTokenInvalid, match="lifetime"):
        oidc.verify_oidc_token(token)


def test_oidc_verifier_rejects_oversized_token_before_jwks_fetch(monkeypatch):
    fetched = False

    def unexpected_fetch(*_args):
        nonlocal fetched
        fetched = True

    monkeypatch.setattr(
        oidc,
        "get_settings",
        lambda: SimpleNamespace(
            oidc_issuer="https://issuer.example",
            oidc_audience="agentops-guard",
            oidc_jwks_url="https://issuer.example/jwks",
            oidc_timeout_seconds=1.0,
            oidc_max_token_bytes=1024,
            oidc_max_token_lifetime_seconds=900,
        ),
    )
    monkeypatch.setattr(oidc, "_jwks_client", unexpected_fetch)

    with pytest.raises(oidc.OidcTokenInvalid, match="size"):
        oidc.verify_oidc_token("x" * 1025)

    assert fetched is False


@pytest.mark.parametrize(
    "scope",
    (
        "",
        "duplicate duplicate",
        " ".join(f"scope:{index}" for index in range(33)),
        "scope\\invalid",
    ),
)
def test_workload_scope_claim_is_bounded_and_unambiguous(scope):
    with pytest.raises(oidc.OidcTokenInvalid, match="scope"):
        auth.oidc_auth_context(
            SimpleNamespace(get=lambda *_args: None),
            {
                "sub": "workload",
                "token_use": "agent",
                "project_id": "project",
                "agent_id": "agent",
                "scope": scope,
            },
            "https://issuer.example",
        )
