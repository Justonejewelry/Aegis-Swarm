"""Redis client factory — standalone | sentinel | cluster.

Used by TaskBus and Cache so topology is a settings concern, not agent logic.
Falls back to None when redis is unavailable (callers use in-memory paths).
"""
from __future__ import annotations

import logging
from typing import Any, Literal

logger = logging.getLogger(__name__)

try:
    import redis.asyncio as redis
    from redis.asyncio.cluster import RedisCluster
except ImportError:  # pragma: no cover
    redis = None  # type: ignore
    RedisCluster = None  # type: ignore

RedisMode = Literal["standalone", "sentinel", "cluster"]


async def create_redis_client(
    *,
    mode: RedisMode = "standalone",
    url: str = "redis://localhost:6379/0",
    sentinels: str | None = None,
    master_name: str = "aegis-master",
    password: str | None = None,
    decode_responses: bool = True,
) -> Any | None:
    if redis is None:
        logger.warning("redis package missing")
        return None

    try:
        if mode == "cluster":
            if RedisCluster is None:
                logger.warning("RedisCluster unavailable in this redis version")
                return None
            client = RedisCluster.from_url(url, decode_responses=decode_responses)
            await client.ping()
            logger.info("RedisCluster connected via %s", url)
            return client

        if mode == "sentinel":
            if not sentinels:
                logger.warning("sentinel mode requires AEGIS_REDIS_SENTINELS")
                return None
            nodes = []
            for part in sentinels.split(","):
                part = part.strip()
                if not part:
                    continue
                host, _, port = part.partition(":")
                nodes.append((host, int(port or 26379)))
            from redis.asyncio.sentinel import Sentinel

            sentinel = Sentinel(
                nodes,
                socket_timeout=2.0,
                password=password,
            )
            client = sentinel.master_for(
                master_name,
                decode_responses=decode_responses,
                password=password,
            )
            await client.ping()
            logger.info("Redis Sentinel primary '%s' via %s", master_name, sentinels)
            return client

        client = redis.from_url(url, decode_responses=decode_responses)
        await client.ping()
        logger.info("Redis standalone connected %s", url)
        return client
    except Exception as e:
        logger.warning("Redis connect failed (%s mode): %s", mode, e)
        return None
