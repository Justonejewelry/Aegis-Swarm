"""API key gate tests."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from aegis.auth.api_key import require_api_key
from aegis.core.settings import get_settings


@pytest.mark.asyncio
async def test_api_key_disabled_allows():
    get_settings.cache_clear()
    await require_api_key(x_api_key=None)


@pytest.mark.asyncio
async def test_api_key_enforced(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setenv("AEGIS_API_KEY", "secret-test-key")
    get_settings.cache_clear()
    with pytest.raises(HTTPException) as ei:
        await require_api_key(x_api_key=None)
    assert ei.value.status_code == 401
    with pytest.raises(HTTPException):
        await require_api_key(x_api_key="wrong")
    await require_api_key(x_api_key="secret-test-key")
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    get_settings.cache_clear()
