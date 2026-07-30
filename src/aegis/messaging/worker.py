"""AEGIS worker loop — consumes task bus and dispatches to agents."""
from __future__ import annotations

import asyncio
import logging
from typing import Any
from uuid import UUID

from aegis.core.models import AgentMessage, Engagement, EngagementMode, EngagementStatus, MsgType, Scope
from aegis.core.orchestrator import Orchestrator
from aegis.core.registry import build_default_agents
from aegis.messaging.bus import TaskBus

logger = logging.getLogger(__name__)


class Worker:
    def __init__(self, bus: TaskBus | None = None, consumer_name: str = "worker-1") -> None:
        self.bus = bus or TaskBus()
        self.consumer_name = consumer_name
        self.orch = Orchestrator()
        for agent in build_default_agents():
            self.orch.register(agent)
        self._running = False

    def ensure_engagement(self, engagement_id: str | UUID, payload: dict[str, Any]) -> None:
        eid = UUID(str(engagement_id))
        if eid in self.orch.engagements:
            return
        mode_raw = payload.get("mode", "assess")
        try:
            mode = EngagementMode(mode_raw)
        except ValueError:
            mode = EngagementMode.ASSESS
        scope_raw = payload.get("scope")
        scope = Scope(**scope_raw) if isinstance(scope_raw, dict) else Scope()
        eng = Engagement(
            engagement_id=eid,
            name=payload.get("engagement_name", "worker-engagement"),
            mode=mode,
            scope=scope,
            status=EngagementStatus.ACTIVE,
        )
        self.orch.register_engagement(eng)

    async def process_task(self, task: dict[str, Any]) -> dict[str, Any]:
        engagement_id = task.get("engagement_id")
        recipient = task.get("recipient") or task.get("agent_id")
        if not engagement_id or not recipient:
            return {"ok": False, "error": "engagement_id and recipient required"}
        self.ensure_engagement(engagement_id, task)
        msg = AgentMessage(
            engagement_id=UUID(str(engagement_id)),
            sender=task.get("sender", "worker"),
            recipient=recipient,
            msg_type=MsgType(task.get("msg_type", "task")),
            priority=int(task.get("priority", 3)),
            payload=task.get("payload") or {},
        )
        try:
            result = await self.orch.dispatch(msg)
            if hasattr(result, "model_dump"):
                data: Any = result.model_dump(mode="json")
            elif isinstance(result, list):
                data = [r.model_dump(mode="json") if hasattr(r, "model_dump") else r for r in result]
            else:
                data = result
            return {"ok": True, "task_id": task.get("task_id"), "result": data}
        except Exception as e:
            logger.exception("task failed")
            return {"ok": False, "task_id": task.get("task_id"), "error": str(e)}

    async def run_forever(self, poll_interval: float = 0.1) -> None:
        await self.bus.connect()
        self._running = True
        logger.info("worker %s started (%d agents)", self.consumer_name, len(self.orch.agents))
        while self._running:
            tasks = await self.bus.dequeue(self.consumer_name, count=5, block_ms=2000)
            if not tasks:
                await asyncio.sleep(poll_interval)
                continue
            for task in tasks:
                result = await self.process_task(task)
                await self.bus.publish_result(result)
                await self.bus.ack(task.get("_redis_id", ""))

    def stop(self) -> None:
        self._running = False


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    worker = Worker()
    await worker.run_forever()


if __name__ == "__main__":
    asyncio.run(main())
