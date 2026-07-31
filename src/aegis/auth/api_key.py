"""Optional API key gate for mutating control-plane routes."""
from __future__ import annotations

from fastapi import Header, HTTPException

from aegis.core.settings import get_settings


async def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """
    If AEGIS_API_KEY is set, require matching X-API-Key header.
    When unset (dev default), all requests are allowed.
    """
    settings = get_settings()
    expected = settings.api_key
    if not expected:
        return
    if not x_api_key or x_api_key != expected:
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")
