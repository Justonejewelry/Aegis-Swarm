"""OIDC JWT verification via issuer JWKS.

When AEGIS_OIDC_ISSUER is unset, OIDC is disabled (API-key-only / open dev).
When set, Bearer tokens are validated against JWKS (RS256/ES256).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import Header, HTTPException
from jose import JWTError, jwt
from jose.exceptions import JOSEError

from aegis.core.settings import get_settings

logger = logging.getLogger(__name__)

DEFAULT_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
JWKS_TTL = 3600


@dataclass
class Principal:
    sub: str
    email: str | None = None
    name: str | None = None
    roles: list[str] = field(default_factory=list)
    claims: dict[str, Any] = field(default_factory=dict)


class JWKSCache:
    """Fetch and cache OpenID provider JWKS with simple TTL refresh."""

    def __init__(self) -> None:
        self._keys: dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._jwks_url: str | None = None

    def clear(self) -> None:
        self._keys = {}
        self._fetched_at = 0.0
        self._jwks_url = None

    async def get_key(self, jwks_url: str, kid: str | None) -> dict[str, Any] | None:
        now = time.time()
        if self._jwks_url != jwks_url or now - self._fetched_at > JWKS_TTL or not self._keys:
            await self._refresh(jwks_url)
        if kid and kid in self._keys:
            return self._keys[kid]
        if not kid and len(self._keys) == 1:
            return next(iter(self._keys.values()))
        if kid and kid not in self._keys:
            await self._refresh(jwks_url)
            return self._keys.get(kid) if kid else None
        return None

    async def _refresh(self, jwks_url: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(jwks_url)
                resp.raise_for_status()
                payload = resp.json()
        except Exception as e:
            logger.error("JWKS fetch failed url=%s err=%s", jwks_url, e)
            if not self._keys:
                raise HTTPException(503, f"JWKS unavailable: {e}") from e
            logger.warning("using stale JWKS cache")
            return
        keys: dict[str, Any] = {}
        for k in payload.get("keys", []):
            kid = k.get("kid") or f"idx-{len(keys)}"
            keys[kid] = k
        self._keys = keys
        self._fetched_at = time.time()
        self._jwks_url = jwks_url
        logger.info("JWKS refreshed url=%s keys=%d", jwks_url, len(keys))


_jwks_cache = JWKSCache()


def resolve_jwks_url(issuer: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit.rstrip("/")
    return f"{issuer.rstrip('/')}/.well-known/jwks.json"


def _roles_from_claims(claims: dict[str, Any]) -> list[str]:
    roles: list[str] = []
    for key in ("roles", "groups", "realm_access"):
        val = claims.get(key)
        if isinstance(val, list):
            roles.extend(str(x) for x in val)
        elif isinstance(val, dict) and "roles" in val:
            roles.extend(str(x) for x in val.get("roles") or [])
    return list(dict.fromkeys(roles))


async def verify_bearer_token(token: str) -> Principal:
    settings = get_settings()
    issuer = settings.oidc_issuer
    if not issuer:
        raise HTTPException(500, "OIDC not configured")

    jwks_url = resolve_jwks_url(issuer, settings.oidc_jwks_url)
    audience = settings.oidc_audience

    try:
        header = jwt.get_unverified_header(token)
    except JWTError as e:
        raise HTTPException(401, f"invalid token header: {e}") from e

    alg = header.get("alg", "RS256")
    if alg not in DEFAULT_ALGORITHMS:
        raise HTTPException(401, f"disallowed algorithm: {alg}")

    kid = header.get("kid")
    jwk = await _jwks_cache.get_key(jwks_url, kid)
    if not jwk:
        raise HTTPException(401, "signing key not found in JWKS")

    options: dict[str, Any] = {
        "verify_aud": bool(audience),
        "verify_iss": True,
        "require_exp": True,
        "require_iat": False,
    }
    try:
        claims = jwt.decode(
            token,
            jwk,
            algorithms=list(DEFAULT_ALGORITHMS),
            audience=audience if audience else None,
            issuer=issuer.rstrip("/"),
            options=options,
        )
    except JWTError as e:
        try:
            claims = jwt.decode(
                token,
                jwk,
                algorithms=list(DEFAULT_ALGORITHMS),
                audience=audience if audience else None,
                issuer=issuer.rstrip("/") + "/",
                options=options,
            )
        except JWTError:
            logger.info("JWT validation failed: %s", e)
            raise HTTPException(401, f"token validation failed: {e}") from e
    except JOSEError as e:
        raise HTTPException(401, f"token validation failed: {e}") from e

    sub = claims.get("sub")
    if not sub:
        raise HTTPException(401, "token missing sub")

    return Principal(
        sub=str(sub),
        email=claims.get("email") or claims.get("preferred_username"),
        name=claims.get("name"),
        roles=_roles_from_claims(claims),
        claims=dict(claims),
    )


async def optional_oidc_principal(
    authorization: str | None = Header(default=None),
) -> Principal | None:
    settings = get_settings()
    if not settings.oidc_issuer:
        return None
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(401, "empty bearer token")
    return await verify_bearer_token(token)


async def require_oidc_principal(
    authorization: str | None = Header(default=None),
) -> Principal:
    settings = get_settings()
    if not settings.oidc_issuer:
        raise HTTPException(503, "OIDC not configured (set AEGIS_OIDC_ISSUER)")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(401, "empty bearer token")
    return await verify_bearer_token(token)


def get_jwks_cache() -> JWKSCache:
    return _jwks_cache
