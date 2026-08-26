from functools import lru_cache
from pathlib import Path
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTOPS_", env_file=".env", extra="ignore")

    app_name: str = "AgentOps Guard"
    env: Literal["dev", "test", "prod"] = "dev"
    api_key: str = "dev-agentops-key"
    operator_api_key: str | None = None
    database_url: str = "sqlite:///./agentops_guard.sqlite3"
    redis_url: str = "redis://localhost:6379/0"
    opa_url: str | None = None
    opa_timeout_seconds: float = Field(default=2.0, gt=0)
    retention_days: int = 30
    store_raw_content: bool = False
    policy_fail_mode: Literal["open", "closed", "closed_for_high_risk"] = (
        "closed_for_high_risk"
    )
    policy_dir: Path = Field(default_factory=lambda: Path("policies"))
    allow_schema_bootstrap: bool = False
    cors_allowed_origins: list[str] = Field(default_factory=lambda: ["*"])
    gateway_startup_timeout_seconds: float = 5.0
    gateway_call_timeout_seconds: float = 10.0
    gateway_max_response_bytes: int = 262_144
    gateway_max_stderr_bytes: int = 4_096
    gateway_max_concurrency_per_server: int = 1
    scanner_plugins: list[str] = Field(default_factory=list)
    semantic_scanner_mode: Literal["disabled", "shadow", "enforce"] = "disabled"
    semantic_model_path: Path | None = None
    semantic_model_sha256: str | None = None
    semantic_scanner_threshold: float = Field(default=0.9, ge=0.9, le=1.0)
    credential_store: Literal["fernet", "openbao"] = "fernet"
    credential_encryption_key: SecretStr | None = None
    openbao_url: str | None = None
    openbao_token: SecretStr | None = None
    openbao_kv_mount: str = "secret"
    openbao_timeout_seconds: float = Field(default=5.0, gt=0)
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

    @field_validator("openbao_url", "openbao_token", mode="before")
    @classmethod
    def _empty_openbao_configuration_is_unset(cls, value: object) -> object:
        if value == "":
            return None
        return value

    @field_validator("cors_allowed_origins", mode="before")
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
        if not re.fullmatch(r"[A-Za-z0-9_-]+", self.openbao_kv_mount):
            raise ValueError("AGENTOPS_OPENBAO_KV_MOUNT must be a single path segment")
        if self.credential_store == "openbao":
            if self.openbao_url is None or self.openbao_token is None:
                raise ValueError(
                    "OpenBao credential storage requires AGENTOPS_OPENBAO_URL and "
                    "AGENTOPS_OPENBAO_TOKEN"
                )
            parsed_openbao_url = urlsplit(self.openbao_url)
            if (
                parsed_openbao_url.scheme not in {"http", "https"}
                or not parsed_openbao_url.hostname
                or parsed_openbao_url.username is not None
                or parsed_openbao_url.password is not None
                or parsed_openbao_url.query
                or parsed_openbao_url.fragment
            ):
                raise ValueError("AGENTOPS_OPENBAO_URL must be a credential-free HTTP base URL")
        if self.semantic_scanner_mode == "enforce":
            raise ValueError("semantic scanner enforce mode has not passed the promotion gates")
        if self.semantic_scanner_mode != "disabled":
            if self.semantic_model_path is None or self.semantic_model_sha256 is None:
                raise ValueError(
                    "semantic scanning requires AGENTOPS_SEMANTIC_MODEL_PATH and "
                    "AGENTOPS_SEMANTIC_MODEL_SHA256"
                )
            if not self.semantic_model_path.is_absolute():
                raise ValueError("AGENTOPS_SEMANTIC_MODEL_PATH must be an absolute local path")
            if not re.fullmatch(r"[0-9a-f]{64}", self.semantic_model_sha256):
                raise ValueError("AGENTOPS_SEMANTIC_MODEL_SHA256 must be a lowercase SHA-256")
        if self.env == "prod":
            if self.api_key == "dev-agentops-key":
                raise ValueError("production configuration cannot use the default development API key")
            if not self.operator_api_key:
                raise ValueError("production configuration requires AGENTOPS_OPERATOR_API_KEY")
            if "*" in self.cors_allowed_origins:
                raise ValueError("production configuration cannot use wildcard CORS origins")
            if self.allow_schema_bootstrap:
                raise ValueError("production configuration cannot enable runtime schema bootstrap")
        return self

    @property
    def effective_operator_api_key(self) -> str:
        return self.operator_api_key or self.api_key


@lru_cache
def get_settings() -> Settings:
    return Settings()
