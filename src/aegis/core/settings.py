"""Central configuration via environment variables."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    env: str = "development"
    database_url: str = "postgresql+asyncpg://aegis:aegis_dev_only@localhost:5432/aegis"
    redis_url: str = "redis://localhost:6379/0"
    redis_mode: Literal["standalone", "sentinel", "cluster"] = "standalone"
    redis_sentinels: str | None = None
    redis_master_name: str = "aegis-master"
    redis_password: str | None = None

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

    persist_findings: bool = True
    persist_audit: bool = True
    enable_graph_store: bool = True
    enable_cache: bool = True
    cache_engagement_ttl: int = 300
    cache_findings_ttl: int = 120
    enable_metrics: bool = True
    api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
