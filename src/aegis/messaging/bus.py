"""Redis Streams task bus for AEGIS workers."""
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


class TaskBus:
    """Thin wrapper over Redis Streams with in-memory fallback."""

    def __init__(
        self,
        url: str | None = None,
        stream: str = DEFAULT_STREAM,
        group: str = DEFAULT_GROUP,
        result_stream: str = DEFAULT_RESULT_STREAM,
    ) -> None:
        self.url = url or os.getenv("AEGIS_REDIS_URL", "redis://localhost:6379/0")
        self.stream = stream
        self.group = group
        self.result_stream = result_stream
        self._client: Any = None
        self._memory: list[dict[str, Any]] = []
        self._memory_results: list[dict[str, Any]] = []

    async def connect(self) -> None:
        if redis is None:
            logger.warning("redis package missing — using in-memory bus")
            return
        try:
            self._client = redis.from_url(self.url, decode_responses=True)
            await self._client.ping()
            try:
                await self._client.xgroup_create(self.stream, self.group, id="0", mkstream=True)
            except Exception:
                pass
            logger.info("connected to Redis bus %s", self.url)
        except Exception as e:
            logger.warning("Redis unavailable (%s) — in-memory bus", e)
            self._client = None

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def enqueue(self, task: dict[str, Any]) -> str:
        task_id = task.get("task_id") or str(uuid4())
        task = {**task, "task_id": task_id}
        body = json.dumps(task, default=str)
        if self._client is None:
            self._memory.append(task)
            return task_id
        await self._client.xadd(self.stream, {"payload": body})
        return task_id

    async def dequeue(self, consumer: str, count: int = 1, block_ms: int = 2000) -> list[dict[str, Any]]:
        if self._client is None:
            out = self._memory[:count]
            self._memory = self._memory[count:]
            return out
        messages = await self._client.xreadgroup(
            self.group, consumer, streams={self.stream: ">"}, count=count, block=block_ms
        )
        results: list[dict[str, Any]] = []
        for _stream, entries in messages or []:
            for msg_id, fields in entries:
                payload = json.loads(fields.get("payload", "{}"))
                payload["_redis_id"] = msg_id
                results.append(payload)
        return results

    async def ack(self, msg_id: str) -> None:
        if self._client is None or not msg_id:
            return
        await self._client.xack(self.stream, self.group, msg_id)

    async def publish_result(self, result: dict[str, Any]) -> None:
        body = json.dumps(result, default=str)
        if self._client is None:
            self._memory_results.append(result)
            return
        await self._client.xadd(self.result_stream, {"payload": body})
