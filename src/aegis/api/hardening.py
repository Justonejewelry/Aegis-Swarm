"""Production hardening middleware: TrustedHost, CORS, rate limit, body size."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, PlainTextResponse

from aegis.core.settings import get_settings

_DEV_ORIGINS = [
    "http://127.0.0.1:8765",
    "http://localhost:8765",
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        limit = settings.max_request_body_bytes or 0
        if limit > 0 and request.method in {"POST", "PUT", "PATCH"}:
            cl = request.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > limit:
                return PlainTextResponse("request body too large", status_code=413)
        return await call_next(request)


class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_per_minute: int = 0):
        super().__init__(app)
        self.max_per_minute = max_per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        limit = settings.rate_limit_per_minute or self.max_per_minute
        if limit <= 0:
            return await call_next(request)
        if request.url.path in {"/health", "/metrics"}:
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        now = time.time()
        window = self._hits[client]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit:
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        window.append(now)
        return await call_next(request)


def apply_hardening(app: FastAPI) -> None:
    settings = get_settings()
    hosts = [h.strip() for h in (settings.trusted_hosts or "").split(",") if h.strip()]
    if hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    origins = [o.strip() for o in (settings.cors_origins or "").split(",") if o.strip()]
    env = (settings.env or "development").lower()
    # Dev: always allow console (8765) + local API origins unless production
    if env not in {"prod", "production"}:
        for o in _DEV_ORIGINS:
            if o not in origins:
                origins.append(o)

    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(SimpleRateLimitMiddleware, max_per_minute=settings.rate_limit_per_minute)
