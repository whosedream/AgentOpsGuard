from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
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
    retention_days: int = 30
    store_raw_content: bool = False
    policy_fail_mode: str = "closed_for_high_risk"
    policy_dir: Path = Field(default_factory=lambda: Path("policies"))
    allow_schema_bootstrap: bool = False
    cors_allowed_origins: list[str] = Field(default_factory=lambda: ["*"])
    gateway_startup_timeout_seconds: float = 5.0
    gateway_call_timeout_seconds: float = 10.0
    gateway_max_response_bytes: int = 262_144
    gateway_max_stderr_bytes: int = 4_096
    gateway_max_concurrency_per_server: int = 1
    scanner_plugins: list[str] = Field(default_factory=list)

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
