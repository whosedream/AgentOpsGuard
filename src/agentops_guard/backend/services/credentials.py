from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol
from urllib.parse import quote

import httpx
from cryptography.fernet import Fernet

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.telemetry import inject_trace_headers


class CredentialStoreUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredCredential:
    secret_ref: str
    binding_proof: str


class CredentialStore(Protocol):
    def store_credential(
        self, credential_ref: str, secret: str, binding: dict[str, Any]
    ) -> StoredCredential:
        ...

    def resolve_credential(
        self,
        credential_ref: str,
        secret_ref: str,
        binding_proof: str,
        binding: dict[str, Any],
    ) -> str:
        ...

    def rebind_credential(
        self,
        credential_ref: str,
        secret_ref: str,
        binding_proof: str,
        binding: dict[str, Any],
    ) -> str:
        ...


class CredentialVault:
    """Encrypt outbound credentials with an API-process-only master key."""

    def __init__(self, key: str) -> None:
        self._fernet = Fernet(key.encode("ascii"))

    def encrypt(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")

    def store_credential(
        self, credential_ref: str, secret: str, binding: dict[str, Any]
    ) -> StoredCredential:
        ciphertext = self.encrypt(secret)
        proof = self.encrypt(_binding_digest(binding, ciphertext))
        return StoredCredential(secret_ref=ciphertext, binding_proof=proof)

    def resolve_credential(
        self,
        credential_ref: str,
        secret_ref: str,
        binding_proof: str,
        binding: dict[str, Any],
    ) -> str:
        if self.decrypt(binding_proof) != _binding_digest(binding, secret_ref):
            raise ValueError("credential binding mismatch")
        return self.decrypt(secret_ref)

    def rebind_credential(
        self,
        credential_ref: str,
        secret_ref: str,
        binding_proof: str,
        binding: dict[str, Any],
    ) -> str:
        self.resolve_credential(
            credential_ref,
            secret_ref,
            binding_proof,
            {**binding, "status": "active", "revoked_at": None},
        )
        return self.encrypt(_binding_digest(binding, secret_ref))


class OpenBaoCredentialStore:
    """Store secrets in a fixed OpenBao KV v2 path and keep only locators in SQL."""

    def __init__(
        self,
        *,
        url: str,
        token: str,
        mount: str = "secret",
        timeout: float = 5.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._url = url.rstrip("/")
        self._token = token
        self._mount = mount
        self._timeout = timeout
        self._client = client

    def store_credential(
        self, credential_ref: str, secret: str, binding: dict[str, Any]
    ) -> StoredCredential:
        secret_ref = self._secret_ref(credential_ref)
        digest = _binding_digest(binding, secret_ref)
        version = self._write(credential_ref, secret, digest)
        return StoredCredential(secret_ref=secret_ref, binding_proof=f"openbao-version:{version}")

    def resolve_credential(
        self,
        credential_ref: str,
        secret_ref: str,
        binding_proof: str,
        binding: dict[str, Any],
    ) -> str:
        if secret_ref != self._secret_ref(credential_ref):
            raise ValueError("credential locator mismatch")
        secret, stored_digest, version = self._read(credential_ref)
        if binding_proof != f"openbao-version:{version}":
            raise ValueError("credential version mismatch")
        if stored_digest != _binding_digest(binding, secret_ref):
            raise ValueError("credential binding mismatch")
        return secret

    def rebind_credential(
        self,
        credential_ref: str,
        secret_ref: str,
        binding_proof: str,
        binding: dict[str, Any],
    ) -> str:
        previous_binding = {**binding, "status": "active", "revoked_at": None}
        secret = self.resolve_credential(
            credential_ref,
            secret_ref,
            binding_proof,
            previous_binding,
        )
        version = self._write(
            credential_ref,
            secret,
            _binding_digest(binding, secret_ref),
        )
        return f"openbao-version:{version}"

    def check_health(self) -> None:
        try:
            response = self._request_url("GET", "/v1/sys/health")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise CredentialStoreUnavailable("OpenBao health check failed") from exc

    def _write(self, credential_ref: str, secret: str, binding_digest: str) -> int:
        try:
            response = self._request(
                "POST",
                credential_ref,
                json={"data": {"secret": secret, "binding_digest": binding_digest}},
            )
            response.raise_for_status()
            return int(response.json()["data"]["version"])
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise CredentialStoreUnavailable("OpenBao credential write failed") from exc

    def _read(self, credential_ref: str) -> tuple[str, str, int]:
        try:
            response = self._request("GET", credential_ref)
            response.raise_for_status()
            data = response.json()["data"]
            values = data["data"]
            return (
                str(values["secret"]),
                str(values["binding_digest"]),
                int(data["metadata"]["version"]),
            )
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise CredentialStoreUnavailable("OpenBao credential read failed") from exc

    def _request(self, method: str, credential_ref: str, **kwargs: Any) -> httpx.Response:
        path = f"/v1/{quote(self._mount, safe='')}/data/agentops/{quote(credential_ref, safe='')}"
        return self._request_url(method, path, **kwargs)

    def _request_url(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = {"X-Vault-Token": self._token}
        inject_trace_headers(headers)
        if self._client is not None:
            return self._client.request(method, f"{self._url}{path}", headers=headers, **kwargs)
        with httpx.Client(
            timeout=self._timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            return client.request(method, f"{self._url}{path}", headers=headers, **kwargs)

    def _secret_ref(self, credential_ref: str) -> str:
        return f"openbao:{self._mount}/agentops/{credential_ref}"


def configured_credential_store() -> CredentialStore:
    settings = get_settings()
    if settings.credential_store == "openbao":
        assert settings.openbao_url is not None
        assert settings.openbao_token is not None
        return OpenBaoCredentialStore(
            url=settings.openbao_url,
            token=settings.openbao_token.get_secret_value(),
            mount=settings.openbao_kv_mount,
            timeout=settings.openbao_timeout_seconds,
        )
    if settings.credential_encryption_key is None:
        raise CredentialStoreUnavailable("Fernet credential store is not configured")
    return CredentialVault(settings.credential_encryption_key.get_secret_value())


def _binding_digest(binding: dict[str, Any], secret_ref: str) -> str:
    payload = {
        **binding,
        "secret_ref_sha256": sha256(secret_ref.encode("utf-8")).hexdigest(),
    }
    return sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
