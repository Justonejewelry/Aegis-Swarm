"""Redis Streams task bus for AEGIS workers.

Supports a default stream and optional domain-partitioned streams
(aegis:tasks:blue, aegis:tasks:intel, ...) for horizontal scale.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

try:
    import redis.asyncio as redis
except ImportError:  # pragma: no cover
    redis = None  # type: ignore


DEFAULT_STREAM = "aegis:tasks"
DEFAULT_GROUP = "aegis-workers"
DEFAULT_RESULT_STREAM = "aegis:results"
DEFAULT_DLQ_STREAM = "aegis:dlq"

KNOWN_DOMAINS = frozenset(
    {"blue", "intel", "purple", "red", "dfir", "command", "reporting", "default"}
)


def stream_for_domain(domain: str | None = None) -> str:
    if not domain or domain == "default":
        return DEFAULT_STREAM
    d = domain.lower().strip()
    if d not in KNOWN_DOMAINS:
        return DEFAULT_STREAM
    return f"{DEFAULT_STREAM}:{d}"


class TaskBus:
    def __init__(
        self,
        url: str | None = None,
        stream: str = DEFAULT_STREAM,
        group: str = DEFAULT_GROUP,
        result_stream: str = DEFAULT_RESULT_STREAM,
        dlq_stream: str = DEFAULT_DLQ_STREAM,
        domains: list[str] | None = None,
    ) -> None:
        self.url = url or os.getenv("AEGIS_REDIS_URL", "redis://localhost:6379/0")
        self.stream = stream
        self.group = group
        self.result_stream = result_stream
        self.dlq_stream = dlq_stream
        self.domains = [d for d in (domains or []) if d in KNOWN_DOMAINS]
        self._client: Any = None
        self._memory: list[dict[str, Any]] = []
        self._memory_results: list[dict[str, Any]] = []
        self._memory_dlq: list[dict[str, Any]] = []
        self._ensured_groups: set[str] = set()

    async def connect(self) -> None:
        if redis is None:
            logger.warning("redis package missing — using in-memory bus")
            return
        try:
            from aegis.core.redis_client import create_redis_client
            from aegis.core.settings import get_settings

            settings = get_settings()
            self._client = await create_redis_client(
                mode=settings.redis_mode,
                url=self.url or settings.redis_url,
                sentinels=settings.redis_sentinels,
                master_name=settings.redis_master_name,
                password=settings.redis_password,
            )
            if self._client is None:
                logger.warning("Redis unavailable — in-memory bus")
                return
            await self._ensure_group(self.stream)
            for d in self.domains:
                await self._ensure_group(stream_for_domain(d))
            logger.info(
                "connected to Redis bus mode=%s domains=%s",
                settings.redis_mode,
                self.domains or ["default"],
            )
        except Exception as e:
            logger.warning("Redis unavailable (%s) — in-memory bus", e)
            self._client = None

    async def _ensure_group(self, stream: str) -> None:
        if stream in self._ensured_groups or self._client is None:
            return
        try:
            await self._client.xgroup_create(stream, self.group, id="0", mkstream=True)
        except Exception:
            pass
        self._ensured_groups.add(stream)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def enqueue(self, task: dict[str, Any], domain: str | None = None) -> str:
        task_id = task.get("task_id") or str(uuid4())
        domain = domain or task.get("domain")
        stream = stream_for_domain(domain if isinstance(domain, str) else None)
        task = {**task, "task_id": task_id}
        if domain:
            task["domain"] = domain
        body = json.dumps(task, default=str)
        if self._client is None:
            self._memory.append(task)
            return task_id
        await self._ensure_group(stream)
        await self._client.xadd(stream, {"payload": body})
        return task_id

    async def dequeue(
        self,
        consumer: str,
        count: int = 1,
        block_ms: int = 2000,
        domains: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        if self._client is None:
            out = self._memory[:count]
            self._memory = self._memory[count:]
            return out

        streams: dict[str, str] = {}
        if domains and ("*" in domains or "all" in domains):
            streams[self.stream] = ">"
            for d in KNOWN_DOMAINS:
                if d == "default":
                    continue
                s = stream_for_domain(d)
                await self._ensure_group(s)
                streams[s] = ">"
        elif domains:
            for d in domains:
                s = stream_for_domain(d)
                await self._ensure_group(s)
                streams[s] = ">"
        else:
            streams[self.stream] = ">"

        messages = await self._client.xreadgroup(
            self.group, consumer, streams=streams, count=count, block=block_ms
        )
        results: list[dict[str, Any]] = []
        for stream_name, entries in messages or []:
            for msg_id, fields in entries:
                payload = json.loads(fields.get("payload", "{}"))
                payload["_redis_id"] = msg_id
                payload["_redis_stream"] = stream_name
                results.append(payload)
        return results

    async def ack(self, msg_id: str, stream: str | None = None) -> None:
        if self._client is None or not msg_id:
            return
        await self._client.xack(stream or self.stream, self.group, msg_id)

    async def publish_result(self, result: dict[str, Any]) -> None:
        body = json.dumps(result, default=str)
        if self._client is None:
            self._memory_results.append(result)
            return
        await self._client.xadd(self.result_stream, {"payload": body})

    async def dead_letter(self, task: dict[str, Any], error: str) -> None:
        entry = {**task, "dlq_error": error, "dlq_task_id": task.get("task_id")}
        body = json.dumps(entry, default=str)
        if self._client is None:
            self._memory_dlq.append(entry)
            return
        await self._client.xadd(self.dlq_stream, {"payload": body})
        if task.get("_redis_id"):
            await self.ack(task["_redis_id"], stream=task.get("_redis_stream"))
