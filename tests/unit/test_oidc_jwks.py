"""OIDC JWKS verification tests using a local RSA key pair."""
from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jose import jwt

from aegis.auth.oidc import get_jwks_cache, verify_bearer_token
from aegis.core.settings import get_settings


def _rsa_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_numbers = key.public_key().public_numbers()

    def b64url_uint(val: int) -> str:
        import base64

        length = (val.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(val.to_bytes(length, "big")).rstrip(b"=").decode()

    jwk = {
        "kty": "RSA",
        "kid": "test-key-1",
        "use": "sig",
        "alg": "RS256",
        "n": b64url_uint(public_numbers.n),
        "e": b64url_uint(public_numbers.e),
    }
    return private_pem, jwk


@pytest.fixture
def rsa_material():
    return _rsa_pair()


@pytest.fixture
def oidc_env(monkeypatch, rsa_material):
    get_settings.cache_clear()
    get_jwks_cache().clear()
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("AEGIS_OIDC_AUDIENCE", "aegis-api")
    monkeypatch.setenv("AEGIS_OIDC_JWKS_URL", "https://idp.example.com/.well-known/jwks.json")
    get_settings.cache_clear()
    yield rsa_material
    get_settings.cache_clear()
    get_jwks_cache().clear()


def _mint(private_pem, claims: dict) -> str:
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": "test-key-1"})


@pytest.mark.asyncio
async def test_verify_valid_token(oidc_env, rsa_material):
    private_pem, jwk = rsa_material
    now = int(time.time())
    token = _mint(
        private_pem,
        {
            "sub": "user-42",
            "email": "analyst@example.com",
            "iss": "https://idp.example.com",
            "aud": "aegis-api",
            "exp": now + 600,
            "iat": now,
            "roles": ["analyst", "soc"],
        },
    )

    async def fake_get(url):
        resp = AsyncMock()
        resp.raise_for_status = lambda: None
        resp.json = lambda: {"keys": [jwk]}
        return resp

    with patch("httpx.AsyncClient") as client_cls:
        instance = AsyncMock()
        instance.__aenter__.return_value = instance
        instance.__aexit__.return_value = None
        instance.get = fake_get
        client_cls.return_value = instance
        principal = await verify_bearer_token(token)

    assert principal.sub == "user-42"
    assert principal.email == "analyst@example.com"
    assert "analyst" in principal.roles


@pytest.mark.asyncio
async def test_reject_expired(oidc_env, rsa_material):
    private_pem, jwk = rsa_material
    now = int(time.time())
    token = _mint(
        private_pem,
        {
            "sub": "user-42",
            "iss": "https://idp.example.com",
            "aud": "aegis-api",
            "exp": now - 10,
            "iat": now - 100,
        },
    )

    async def fake_get(url):
        resp = AsyncMock()
        resp.raise_for_status = lambda: None
        resp.json = lambda: {"keys": [jwk]}
        return resp

    with patch("httpx.AsyncClient") as client_cls:
        instance = AsyncMock()
        instance.__aenter__.return_value = instance
        instance.__aexit__.return_value = None
        instance.get = fake_get
        client_cls.return_value = instance
        with pytest.raises(HTTPException) as ei:
            await verify_bearer_token(token)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_reject_wrong_audience(oidc_env, rsa_material):
    private_pem, jwk = rsa_material
    now = int(time.time())
    token = _mint(
        private_pem,
        {
            "sub": "user-42",
            "iss": "https://idp.example.com",
            "aud": "other-api",
            "exp": now + 600,
            "iat": now,
        },
    )

    async def fake_get(url):
        resp = AsyncMock()
        resp.raise_for_status = lambda: None
        resp.json = lambda: {"keys": [jwk]}
        return resp

    with patch("httpx.AsyncClient") as client_cls:
        instance = AsyncMock()
        instance.__aenter__.return_value = instance
        instance.__aexit__.return_value = None
        instance.get = fake_get
        client_cls.return_value = instance
        with pytest.raises(HTTPException) as ei:
            await verify_bearer_token(token)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_reject_unknown_kid(oidc_env, rsa_material):
    private_pem, jwk = rsa_material
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "user-42",
            "iss": "https://idp.example.com",
            "aud": "aegis-api",
            "exp": now + 600,
            "iat": now,
        },
        private_pem,
        algorithm="RS256",
        headers={"kid": "rotated-away"},
    )

    async def fake_get(url):
        resp = AsyncMock()
        resp.raise_for_status = lambda: None
        resp.json = lambda: {"keys": [jwk]}
        return resp

    with patch("httpx.AsyncClient") as client_cls:
        instance = AsyncMock()
        instance.__aenter__.return_value = instance
        instance.__aexit__.return_value = None
        instance.get = fake_get
        client_cls.return_value = instance
        with pytest.raises(HTTPException) as ei:
            await verify_bearer_token(token)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_require_auth_api_key(monkeypatch):
    from aegis.auth.deps import require_auth

    get_settings.cache_clear()
    monkeypatch.setenv("AEGIS_API_KEY", "svc-key")
    monkeypatch.delenv("AEGIS_OIDC_ISSUER", raising=False)
    get_settings.cache_clear()
    with pytest.raises(HTTPException):
        await require_auth(x_api_key=None, authorization=None)
    assert await require_auth(x_api_key="svc-key", authorization=None) is None
    get_settings.cache_clear()
