"""OpenID discovery + approver role gate tests."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from aegis.auth.deps import require_approver_role
from aegis.auth.oidc import Principal, get_discovery_cache, resolve_jwks_url
from aegis.core.settings import get_settings


@pytest.fixture(autouse=True)
def _reset():
    get_settings.cache_clear()
    get_discovery_cache().clear()
    yield
    get_settings.cache_clear()
    get_discovery_cache().clear()


@pytest.mark.asyncio
async def test_discovery_resolves_jwks_uri(monkeypatch):
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.delenv("AEGIS_OIDC_JWKS_URL", raising=False)
    get_settings.cache_clear()

    async def fake_get(url):
        resp = AsyncMock()
        resp.raise_for_status = lambda: None
        if "openid-configuration" in url:
            resp.json = lambda: {
                "issuer": "https://idp.example.com",
                "jwks_uri": "https://idp.example.com/oauth2/v1/keys",
            }
        else:
            resp.json = lambda: {"keys": []}
        return resp

    with patch("httpx.AsyncClient") as client_cls:
        instance = AsyncMock()
        instance.__aenter__.return_value = instance
        instance.__aexit__.return_value = None
        instance.get = fake_get
        client_cls.return_value = instance
        url = await resolve_jwks_url("https://idp.example.com", None)
    assert url == "https://idp.example.com/oauth2/v1/keys"


@pytest.mark.asyncio
async def test_explicit_jwks_url_skips_discovery(monkeypatch):
    url = await resolve_jwks_url("https://idp.example.com", "https://custom.example/jwks")
    assert url == "https://custom.example/jwks"


@pytest.mark.asyncio
async def test_approver_role_denied(monkeypatch):
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("AEGIS_OIDC_APPROVER_ROLES", "soc-lead,admin")
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    get_settings.cache_clear()

    async def fake_verify(token):
        return Principal(sub="u1", roles=["analyst"])

    with patch("aegis.auth.deps.verify_bearer_token", side_effect=fake_verify):
        with pytest.raises(HTTPException) as ei:
            await require_approver_role(x_api_key=None, authorization="Bearer fake.jwt.token")
    assert ei.value.status_code == 403


@pytest.mark.asyncio
async def test_approver_role_allowed(monkeypatch):
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("AEGIS_OIDC_APPROVER_ROLES", "soc-lead,admin")
    get_settings.cache_clear()

    async def fake_verify(token):
        return Principal(sub="lead", roles=["soc-lead", "analyst"])

    with patch("aegis.auth.deps.verify_bearer_token", side_effect=fake_verify):
        p = await require_approver_role(x_api_key=None, authorization="Bearer fake.jwt.token")
    assert p is not None and p.sub == "lead"


@pytest.mark.asyncio
async def test_approver_api_key_bypass(monkeypatch):
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("AEGIS_API_KEY", "break-glass")
    get_settings.cache_clear()
    p = await require_approver_role(x_api_key="break-glass", authorization=None)
    assert p is None
