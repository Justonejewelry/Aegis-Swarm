"""Central configuration via environment variables."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    env: str = "development"
    database_url: str = "postgresql+asyncpg://aegis:aegis_dev_only@localhost:5432/aegis"
    redis_url: str = "redis://localhost:6379/0"

    # Ingestion connector endpoints / credentials (optional — stubs still work without them)
    elastic_url: str | None = None
    elastic_api_key: str | None = None
    elastic_index: str = "logs-*"
    sentinel_workspace_id: str | None = None
    sentinel_client_id: str | None = None
    sentinel_client_secret: str | None = None
    sentinel_tenant_id: str | None = None
    crowdstrike_base_url: str = "https://api.crowdstrike.com"
    crowdstrike_client_id: str | None = None
    crowdstrike_client_secret: str | None = None
    defender_tenant_id: str | None = None
    defender_client_id: str | None = None
    defender_client_secret: str | None = None

    # Feature flags
    persist_findings: bool = True
    persist_audit: bool = True
    enable_graph_store: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
