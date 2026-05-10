from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTOPS_", env_file=".env", extra="ignore")

    app_name: str = "AgentOps Guard"
    api_key: str = "dev-agentops-key"
    database_url: str = "sqlite:///./agentops_guard.sqlite3"
    redis_url: str = "redis://localhost:6379/0"
    opa_url: str | None = None
    retention_days: int = 30
    store_raw_content: bool = False
    policy_fail_mode: str = "closed_for_high_risk"
    policy_dir: Path = Field(default_factory=lambda: Path("policies"))


@lru_cache
def get_settings() -> Settings:
    return Settings()
