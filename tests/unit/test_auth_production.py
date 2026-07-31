import pytest
from fastapi import HTTPException
from aegis.auth import deps
from aegis.core.settings import get_settings

@pytest.fixture(autouse=True)
def clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()

@pytest.mark.asyncio
async def test_production_requires_auth_config(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_OIDC_ISSUER", raising=False)
    get_settings.cache_clear()
    with pytest.raises(HTTPException) as ei:
        await deps.require_auth(x_api_key=None, authorization=None)
    assert ei.value.status_code == 503

@pytest.mark.asyncio
async def test_development_allows_open(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "development")
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_OIDC_ISSUER", raising=False)
    get_settings.cache_clear()
    assert await deps.require_auth(x_api_key=None, authorization=None) is None
