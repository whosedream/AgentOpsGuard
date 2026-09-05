from functools import lru_cache
from pathlib import Path
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


_OTEL_SERVICE_NAME = re.compile(r"^agentops-guard-[a-z0-9][a-z0-9-]{0,47}$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTOPS_",
        env_file=".env",
        extra="ignore",
        hide_input_in_errors=True,
    )

    app_name: str = "AgentOps Guard"
    env: Literal["dev", "test", "prod"] = "dev"
    component: Literal[
        "api",
        "gateway",
        "worker",
        "outbox_dispatcher",
        "semantic_scanner",
        "audit_anchor_exporter",
        "migration",
    ] = "api"
    api_key: str = "dev-agentops-key"
    operator_api_key: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_timeout_seconds: float = Field(default=5.0, gt=0)
    oidc_max_token_bytes: int = Field(default=16_384, ge=1_024, le=65_536)
    oidc_max_token_lifetime_seconds: int = Field(default=900, ge=30, le=86_400)
    database_url: str = "sqlite:///./agentops_guard.sqlite3"
    redis_url: str = "redis://localhost:6379/0"
    opa_url: str | None = None
    opa_timeout_seconds: float = Field(default=2.0, gt=0)
    opa_expected_policy_revision: str | None = None
    retention_days: int = 30
    store_raw_content: bool = False
    policy_fail_mode: Literal["open", "closed", "closed_for_high_risk"] = "closed_for_high_risk"
    policy_dir: Path = Field(default_factory=lambda: Path("policies"))
    allow_schema_bootstrap: bool = False
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["*"])
    gateway_startup_timeout_seconds: float = 5.0
    gateway_call_timeout_seconds: float = 10.0
    gateway_max_response_bytes: int = 262_144
    gateway_max_stderr_bytes: int = 4_096
    gateway_max_concurrency_per_server: int = 1
    gateway_capacity_wait_seconds: float = Field(default=1.0, ge=0)
    gateway_concurrency_backend: Literal["local", "redis"] = "local"
    gateway_concurrency_lease_seconds: float = Field(default=60.0, gt=0)
    mcp_public_url: str = "http://localhost:8001/mcp"
    mcp_allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["localhost", "localhost:*", "127.0.0.1", "127.0.0.1:*"]
    )
    mcp_allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"]
    )
    mcp_page_size: int = Field(default=100, ge=1, le=1_000)
    scanner_plugins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    semantic_scanner_mode: Literal["disabled", "shadow", "enforce"] = "disabled"
    semantic_model_path: Path | None = None
    semantic_model_sha256: str | None = None
    semantic_scanner_threshold: float = Field(default=0.9, ge=0.9, le=1.0)
    semantic_service_url: str | None = None
    semantic_service_timeout_seconds: float = Field(default=2.0, gt=0)
    credential_store: Literal["fernet", "openbao"] = "fernet"
    credential_encryption_key: SecretStr | None = None
    openbao_url: str | None = None
    openbao_auth_method: Literal["token", "approle", "proxy"] = "token"
    openbao_token: SecretStr | None = None
    openbao_approle_role_id: str | None = None
    openbao_approle_secret_id_file: Path | None = None
    openbao_approle_mount: str = "approle"
    openbao_kv_mount: str = "secret"
    openbao_timeout_seconds: float = Field(default=5.0, gt=0)
    audit_checkpoint_backend: Literal["disabled", "openbao"] = "disabled"
    openbao_transit_mount: str = "transit"
    audit_checkpoint_key_name: str = "agentops-audit"
    audit_anchor_backend: Literal["disabled", "s3_object_lock"] = "disabled"
    audit_anchor_s3_bucket: str | None = None
    audit_anchor_s3_prefix: str = "agentops-audit-checkpoints"
    audit_anchor_s3_region: str | None = None
    audit_anchor_s3_endpoint_url: str | None = None
    audit_anchor_s3_retention_days: int = Field(default=2555, ge=1)
    audit_anchor_s3_expected_bucket_owner: str | None = None
    otel_enabled: bool = False
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_service_name: str | None = None
    otel_trace_sample_ratio: float = Field(default=1.0, ge=0.0, le=1.0)
    otel_export_timeout_seconds: float = Field(default=5.0, gt=0)

    @field_validator("credential_encryption_key", mode="before")
    @classmethod
    def _empty_credential_encryption_key_is_unset(cls, value: object) -> object:
        if value == "":
            return None
        return value

    @field_validator(
        "openbao_url",
        "openbao_token",
        "openbao_approle_role_id",
        "openbao_approle_secret_id_file",
        "oidc_issuer",
        "oidc_audience",
        "oidc_jwks_url",
        "opa_url",
        "opa_expected_policy_revision",
        "semantic_service_url",
        "audit_anchor_s3_bucket",
        "audit_anchor_s3_region",
        "audit_anchor_s3_endpoint_url",
        "audit_anchor_s3_expected_bucket_owner",
        "otel_service_name",
        mode="before",
    )
    @classmethod
    def _empty_openbao_configuration_is_unset(cls, value: object) -> object:
        if value == "":
            return None
        return value

    @field_validator("otel_service_name")
    @classmethod
    def _validate_otel_service_name(cls, value: str | None) -> str | None:
        if value is not None and _OTEL_SERVICE_NAME.fullmatch(value) is None:
            raise ValueError("OTel service name must be a fixed AgentOps component identifier")
        return value

    @field_validator(
        "cors_allowed_origins",
        "mcp_allowed_hosts",
        "mcp_allowed_origins",
        mode="before",
    )
    @classmethod
    def _parse_cors_allowed_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("scanner_plugins", mode="before")
    @classmethod
    def _parse_scanner_plugins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _validate_runtime_guards(self) -> "Settings":
        parsed_otel_url = urlsplit(self.otel_exporter_otlp_endpoint)
        if (
            parsed_otel_url.scheme not in {"http", "https"}
            or not parsed_otel_url.hostname
            or parsed_otel_url.username is not None
            or parsed_otel_url.password is not None
            or parsed_otel_url.query
            or parsed_otel_url.fragment
            or parsed_otel_url.path not in {"", "/"}
        ):
            raise ValueError(
                "AGENTOPS_OTEL_EXPORTER_OTLP_ENDPOINT must be a credential-free HTTP base URL"
            )
        if self.opa_url is not None:
            parsed_opa_url = urlsplit(self.opa_url)
            if (
                parsed_opa_url.scheme not in {"http", "https"}
                or not parsed_opa_url.hostname
                or parsed_opa_url.username is not None
                or parsed_opa_url.password is not None
                or parsed_opa_url.query
                or parsed_opa_url.fragment
                or parsed_opa_url.path not in {"", "/"}
            ):
                raise ValueError("AGENTOPS_OPA_URL must be a credential-free HTTP base URL")
        if self.opa_expected_policy_revision is not None:
            if not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.opa_expected_policy_revision
            ):
                raise ValueError("AGENTOPS_OPA_EXPECTED_POLICY_REVISION is invalid")
            if self.opa_url is None:
                raise ValueError("expected OPA policy revision requires AGENTOPS_OPA_URL")
        oidc_values = (self.oidc_issuer, self.oidc_audience, self.oidc_jwks_url)
        if any(oidc_values) and not all(oidc_values):
            raise ValueError(
                "OIDC authentication requires AGENTOPS_OIDC_ISSUER, "
                "AGENTOPS_OIDC_AUDIENCE, and AGENTOPS_OIDC_JWKS_URL"
            )
        if self.oidc_jwks_url is not None:
            parsed_jwks_url = urlsplit(self.oidc_jwks_url)
            if (
                parsed_jwks_url.scheme not in {"http", "https"}
                or not parsed_jwks_url.hostname
                or parsed_jwks_url.username is not None
                or parsed_jwks_url.password is not None
                or parsed_jwks_url.query
                or parsed_jwks_url.fragment
            ):
                raise ValueError("AGENTOPS_OIDC_JWKS_URL must be a credential-free HTTP URL")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", self.openbao_kv_mount):
            raise ValueError("AGENTOPS_OPENBAO_KV_MOUNT must be a single path segment")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", self.openbao_approle_mount):
            raise ValueError("AGENTOPS_OPENBAO_APPROLE_MOUNT must be a single path segment")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", self.openbao_transit_mount):
            raise ValueError("AGENTOPS_OPENBAO_TRANSIT_MOUNT must be a single path segment")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.audit_checkpoint_key_name):
            raise ValueError("AGENTOPS_AUDIT_CHECKPOINT_KEY_NAME is invalid")
        if not re.fullmatch(r"[A-Za-z0-9/_-]+", self.audit_anchor_s3_prefix):
            raise ValueError("AGENTOPS_AUDIT_ANCHOR_S3_PREFIX is invalid")
        if self.audit_anchor_backend == "s3_object_lock":
            if self.audit_checkpoint_backend != "openbao":
                raise ValueError("S3 audit anchors require OpenBao-signed audit checkpoints")
            if self.audit_anchor_s3_bucket is None or not re.fullmatch(
                r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", self.audit_anchor_s3_bucket
            ):
                raise ValueError("S3 audit anchors require a valid bucket name")
            if self.audit_anchor_s3_expected_bucket_owner is not None and not re.fullmatch(
                r"[0-9]{12}", self.audit_anchor_s3_expected_bucket_owner
            ):
                raise ValueError("S3 expected bucket owner must be a 12-digit account ID")
            if self.audit_anchor_s3_endpoint_url is not None:
                parsed_anchor_url = urlsplit(self.audit_anchor_s3_endpoint_url)
                if (
                    parsed_anchor_url.scheme not in {"http", "https"}
                    or not parsed_anchor_url.hostname
                    or parsed_anchor_url.username is not None
                    or parsed_anchor_url.password is not None
                    or parsed_anchor_url.query
                    or parsed_anchor_url.fragment
                    or parsed_anchor_url.path not in {"", "/"}
                ):
                    raise ValueError(
                        "AGENTOPS_AUDIT_ANCHOR_S3_ENDPOINT_URL must be a credential-free base URL"
                    )
        if self.credential_store == "openbao" or self.audit_checkpoint_backend == "openbao":
            if self.openbao_url is None:
                raise ValueError("OpenBao integration requires AGENTOPS_OPENBAO_URL")
            parsed_openbao_url = urlsplit(self.openbao_url)
            if (
                parsed_openbao_url.scheme not in {"http", "https"}
                or not parsed_openbao_url.hostname
                or parsed_openbao_url.username is not None
                or parsed_openbao_url.password is not None
                or parsed_openbao_url.query
                or parsed_openbao_url.fragment
                or parsed_openbao_url.path not in {"", "/"}
            ):
                raise ValueError("AGENTOPS_OPENBAO_URL must be a credential-free HTTP base URL")
            if self.openbao_auth_method == "token":
                if self.openbao_token is None:
                    raise ValueError("OpenBao token authentication requires AGENTOPS_OPENBAO_TOKEN")
            elif self.openbao_auth_method == "approle":
                if (
                    self.openbao_approle_role_id is None
                    or self.openbao_approle_secret_id_file is None
                ):
                    raise ValueError(
                        "OpenBao AppRole authentication requires role ID and SecretID file"
                    )
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,512}", self.openbao_approle_role_id):
                    raise ValueError("AGENTOPS_OPENBAO_APPROLE_ROLE_ID is invalid")
                if not self.openbao_approle_secret_id_file.is_absolute():
                    raise ValueError(
                        "AGENTOPS_OPENBAO_APPROLE_SECRET_ID_FILE must be an absolute path"
                    )
            else:
                if parsed_openbao_url.hostname not in {"127.0.0.1", "localhost"}:
                    raise ValueError("OpenBao Proxy must use a loopback URL")
                if any(
                    (
                        self.openbao_token,
                        self.openbao_approle_role_id,
                        self.openbao_approle_secret_id_file,
                    )
                ):
                    raise ValueError(
                        "OpenBao Proxy application configuration cannot receive direct credentials"
                    )
        if self.semantic_scanner_mode == "enforce":
            raise ValueError("semantic scanner enforce mode has not passed the promotion gates")
        if self.semantic_service_url is not None:
            parsed_semantic_url = urlsplit(self.semantic_service_url)
            if (
                parsed_semantic_url.scheme not in {"http", "https"}
                or not parsed_semantic_url.hostname
                or parsed_semantic_url.username is not None
                or parsed_semantic_url.password is not None
                or parsed_semantic_url.query
                or parsed_semantic_url.fragment
                or parsed_semantic_url.path not in {"", "/"}
            ):
                raise ValueError(
                    "AGENTOPS_SEMANTIC_SERVICE_URL must be a credential-free HTTP base URL"
                )
        parsed_mcp_url = urlsplit(self.mcp_public_url)
        if (
            parsed_mcp_url.scheme not in {"http", "https"}
            or not parsed_mcp_url.hostname
            or parsed_mcp_url.username is not None
            or parsed_mcp_url.password is not None
            or parsed_mcp_url.query
            or parsed_mcp_url.fragment
            or parsed_mcp_url.path != "/mcp"
        ):
            raise ValueError("AGENTOPS_MCP_PUBLIC_URL must be a credential-free /mcp HTTP URL")
        if not self.mcp_allowed_hosts:
            raise ValueError("AGENTOPS_MCP_ALLOWED_HOSTS cannot be empty")
        if self.semantic_scanner_mode != "disabled":
            if self.semantic_service_url is None and (
                self.semantic_model_path is None or self.semantic_model_sha256 is None
            ):
                raise ValueError(
                    "semantic scanning requires AGENTOPS_SEMANTIC_SERVICE_URL or reviewed local "
                    "model configuration"
                )
            if self.semantic_model_path is not None and not self.semantic_model_path.is_absolute():
                raise ValueError("AGENTOPS_SEMANTIC_MODEL_PATH must be an absolute local path")
            if self.semantic_model_sha256 is not None and not re.fullmatch(
                r"[0-9a-f]{64}", self.semantic_model_sha256
            ):
                raise ValueError("AGENTOPS_SEMANTIC_MODEL_SHA256 must be a lowercase SHA-256")
        if self.env == "prod":
            if self.component in {"api", "gateway"} and self.api_key == "dev-agentops-key":
                raise ValueError(
                    "production configuration cannot use the default development API key"
                )
            if self.component == "api" and not self.operator_api_key:
                raise ValueError("production configuration requires AGENTOPS_OPERATOR_API_KEY")
            if self.component == "api" and "*" in self.cors_allowed_origins:
                raise ValueError("production configuration cannot use wildcard CORS origins")
            if self.allow_schema_bootstrap:
                raise ValueError("production configuration cannot enable runtime schema bootstrap")
            if self.oidc_jwks_url is not None and not self.oidc_jwks_url.startswith("https://"):
                raise ValueError("production OIDC JWKS must use HTTPS")
            if self.opa_url is not None and self.opa_expected_policy_revision is None:
                raise ValueError("production OPA requires an exact expected policy revision")
            if (
                self.audit_anchor_s3_endpoint_url is not None
                and not self.audit_anchor_s3_endpoint_url.startswith("https://")
            ):
                raise ValueError("production S3 audit anchor endpoint must use HTTPS")
            if self.semantic_scanner_mode != "disabled" and self.semantic_service_url is None:
                raise ValueError("production semantic scanning requires an isolated model service")
            if self.component == "gateway" and not self.mcp_public_url.startswith("https://"):
                raise ValueError("production MCP public URL must use HTTPS")
            if self.component == "gateway" and (
                "*" in self.mcp_allowed_hosts or "*" in self.mcp_allowed_origins
            ):
                raise ValueError("production MCP host and origin allowlists cannot be wildcard")
            if (
                self.credential_store == "openbao" or self.audit_checkpoint_backend == "openbao"
            ) and self.openbao_auth_method != "proxy":
                raise ValueError("production OpenBao integration requires OpenBao Proxy")
        return self

    @property
    def effective_operator_api_key(self) -> str:
        return self.operator_api_key or self.api_key


@lru_cache
def get_settings() -> Settings:
    return Settings()
