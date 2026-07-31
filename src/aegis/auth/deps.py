"""Shared FastAPI auth dependencies."""
from __future__ import annotations

from fastapi import Header, HTTPException

from aegis.auth.oidc import Principal, verify_bearer_token
from aegis.core.settings import get_settings


async def require_auth(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
) -> Principal | None:
    """
    Control-plane gate for mutating routes:

    - If neither API key nor OIDC is configured → allow (dev).
    - If API key configured and matches → allow (Principal None = service).
    - If OIDC configured and Bearer valid → allow with Principal.
    - If either is configured and neither credential succeeds → 401.
    """
    settings = get_settings()
    api_key = settings.api_key
    oidc_on = bool(settings.oidc_issuer)

    if not api_key and not oidc_on:
        return None

    if api_key and x_api_key and x_api_key == api_key:
        return None

    if oidc_on and authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if token:
            return await verify_bearer_token(token)

    if api_key and not oidc_on:
        raise HTTPException(401, "invalid or missing X-API-Key")
    if oidc_on and not api_key:
        raise HTTPException(401, "Bearer token required")
    raise HTTPException(401, "authentication required (X-API-Key or Bearer)")
