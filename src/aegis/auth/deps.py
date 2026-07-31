"""Shared FastAPI auth dependencies."""
from __future__ import annotations

from fastapi import Header, HTTPException

from aegis.auth.oidc import Principal, verify_bearer_token
from aegis.core.settings import get_settings


async def require_auth(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
) -> Principal | None:
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


def _parse_roles(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


async def require_approver_role(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
) -> Principal | None:
    principal = await require_auth(x_api_key=x_api_key, authorization=authorization)
    settings = get_settings()
    if not settings.oidc_issuer:
        return principal
    if settings.api_key and x_api_key and x_api_key == settings.api_key:
        return None
    required = _parse_roles(settings.oidc_approver_roles) or ["soc-lead", "admin", "approver"]
    if principal is None:
        raise HTTPException(403, "approver role required")
    if not principal.has_any_role(required):
        raise HTTPException(403, f"insufficient role: need one of {required}, have {principal.roles}")
    return principal
