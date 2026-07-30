"""Redis caching layer for AEGIS hot paths (engagements, findings).

Falls back to an in-process dict when Redis is unavailable so unit tests and
dev without Redis keep working. Invalidation is explicit on write paths.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any
from uuid import UUID

logger = logging.getLogger(__name__)

try:
    import redis.asyncio as redis
except ImportError:  # pragma: no cover
    redis = None  # type: ignore

from aegis.core.models import Engagement, Finding

# Key prefixes
ENG_KEY = "aegis:eng:{id}"
FINDINGS_KEY = "aegis:findings:{id}"
ENG_LIST_KEY = "aegis:eng:list:recent"

DEFAULT_ENG_TTL = 300  # seconds
DEFAULT_FINDINGS_TTL = 120


class Cache:
    """Async Redis cache with in-memory fallback."""

    def __init__(
        self,
        url: str | None = None,
        eng_ttl: int = DEFAULT_ENG_TTL,
        findings_ttl: int = DEFAULT_FINDINGS_TTL,
        enabled: bool = True,
    ) -> None:
        self.url = url or os.getenv("AEGIS_REDIS_URL", "redis://localhost:6379/0")
        self.eng_ttl = eng_ttl
        self.findings_ttl = findings_ttl
        self.enabled = enabled
        self._client: Any = None
        self._memory: dict[str, str] = {}
        self._connected = False
        self.hits = 0
        self.misses = 0

    async def connect(self) -> None:
        if not self.enabled:
            logger.info("cache disabled via settings")
            return
        if redis is None:
            logger.warning("redis package missing — in-memory cache only")
            return
        try:
            self._client = redis.from_url(self.url, decode_responses=True)
            await self._client.ping()
            self._connected = True
            logger.info("cache connected to Redis %s", self.url)
        except Exception as e:
            logger.warning("Redis cache unavailable (%s) — in-memory only", e)
            self._client = None
            self._connected = False

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            self._connected = False

    @property
    def backend(self) -> str:
        if not self.enabled:
            return "disabled"
        return "redis" if self._connected and self._client else "memory"

    def stats(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "hits": self.hits,
            "misses": self.misses,
            "memory_keys": len(self._memory),
            "eng_ttl": self.eng_ttl,
            "findings_ttl": self.findings_ttl,
        }

    async def get_raw(self, key: str) -> str | None:
        if not self.enabled:
            return None
        if self._client is not None:
            try:
                val = await self._client.get(key)
                if val is not None:
                    self.hits += 1
                else:
                    self.misses += 1
                return val
            except Exception as e:
                logger.debug("cache get failed: %s", e)
                self.misses += 1
                return self._memory.get(key)
        val = self._memory.get(key)
        if val is not None:
            self.hits += 1
        else:
            self.misses += 1
        return val

    async def set_raw(self, key: str, value: str, ttl: int) -> None:
        if not self.enabled:
            return
        if self._client is not None:
            try:
                await self._client.set(key, value, ex=ttl)
                return
            except Exception as e:
                logger.debug("cache set failed: %s", e)
        self._memory[key] = value

    async def delete(self, *keys: str) -> None:
        if not self.enabled or not keys:
            return
        if self._client is not None:
            try:
                await self._client.delete(*keys)
            except Exception as e:
                logger.debug("cache delete failed: %s", e)
        for k in keys:
            self._memory.pop(k, None)

    def _eng_key(self, engagement_id: UUID | str) -> str:
        return ENG_KEY.format(id=str(engagement_id))

    def _findings_key(self, engagement_id: UUID | str) -> str:
        return FINDINGS_KEY.format(id=str(engagement_id))

    async def get_engagement(self, engagement_id: UUID | str) -> Engagement | None:
        raw = await self.get_raw(self._eng_key(engagement_id))
        if not raw:
            return None
        try:
            data = json.loads(raw)
            return Engagement.model_validate(data)
        except Exception as e:
            logger.debug("cache engagement decode failed: %s", e)
            await self.delete(self._eng_key(engagement_id))
            return None

    async def set_engagement(self, eng: Engagement, ttl: int | None = None) -> None:
        payload = eng.model_dump(mode="json")
        await self.set_raw(
            self._eng_key(eng.engagement_id),
            json.dumps(payload, default=str),
            ttl if ttl is not None else self.eng_ttl,
        )

    async def invalidate_engagement(self, engagement_id: UUID | str) -> None:
        await self.delete(
            self._eng_key(engagement_id),
            self._findings_key(engagement_id),
            ENG_LIST_KEY,
        )

    async def get_findings(self, engagement_id: UUID | str) -> list[Finding] | None:
        raw = await self.get_raw(self._findings_key(engagement_id))
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            return [Finding.model_validate(item) for item in data]
        except Exception as e:
            logger.debug("cache findings decode failed: %s", e)
            await self.delete(self._findings_key(engagement_id))
            return None

    async def set_findings(
        self, engagement_id: UUID | str, findings: list[Finding], ttl: int | None = None
    ) -> None:
        payload = [f.model_dump(mode="json") for f in findings]
        await self.set_raw(
            self._findings_key(engagement_id),
            json.dumps(payload, default=str),
            ttl if ttl is not None else self.findings_ttl,
        )

    async def invalidate_findings(self, engagement_id: UUID | str) -> None:
        await self.delete(self._findings_key(engagement_id))


_cache: Cache | None = None


async def get_cache() -> Cache:
    global _cache
    if _cache is None:
        from aegis.core.settings import get_settings

        settings = get_settings()
        _cache = Cache(
            url=settings.redis_url,
            eng_ttl=settings.cache_engagement_ttl,
            findings_ttl=settings.cache_findings_ttl,
            enabled=settings.enable_cache,
        )
        await _cache.connect()
    return _cache


def reset_cache_for_tests() -> None:
    global _cache
    _cache = None
