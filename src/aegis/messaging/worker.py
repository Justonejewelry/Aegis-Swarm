"""AEGIS worker loop — consumes task bus and dispatches to agents."""
from __future__ import annotations

import asyncio
import logging
from typing import Any
from uuid import UUID

from aegis.core.models import (
    AgentMessage,
    Engagement,
    EngagementMode,
    EngagementStatus,
    Finding,
    MsgType,
    Scope,
)
from aegis.core.orchestrator import Orchestrator
from aegis.core.registry import build_default_agents
from aegis.core.settings import get_settings
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
        self.processed = 0
        self.failed = 0

    async def _load_engagement_from_db(self, engagement_id: UUID) -> Engagement | None:
        try:
            from aegis.storage.repositories import EngagementRepository
            from aegis.storage.session import get_session

            async with get_session() as session:
                repo = EngagementRepository(session)
                row = await repo.get(engagement_id)
                if row is None:
                    return None
                eng = EngagementRepository.to_engagement(row)
                if eng.engagement_id not in self.orch.engagements:
                    try:
                        self.orch.register_engagement(eng)
                    except ValueError:
                        self.orch.engagements[eng.engagement_id] = eng
                return eng
        except Exception as e:
            logger.debug("worker load engagement from DB skipped: %s", e)
            return None

    async def ensure_engagement(
        self, engagement_id: str | UUID, payload: dict[str, Any]
    ) -> Engagement:
        eid = UUID(str(engagement_id))
        if eid in self.orch.engagements:
            return self.orch.engagements[eid]

        loaded = await self._load_engagement_from_db(eid)
        if loaded is not None:
            return loaded

        mode_raw = payload.get("mode", "assess")
        try:
            mode = (
                EngagementMode(mode_raw)
                if not isinstance(mode_raw, EngagementMode)
                else mode_raw
            )
        except (ValueError, TypeError):
            mode = EngagementMode.ASSESS
        scope_raw = payload.get("scope")
        if isinstance(scope_raw, dict):
            try:
                scope = Scope(**scope_raw)
            except Exception:
                scope = Scope()
        else:
            scope = Scope()
        eng = Engagement(
            engagement_id=eid,
            name=payload.get("engagement_name", "worker-engagement"),
            mode=mode,
            scope=scope,
            status=EngagementStatus.ACTIVE,
        )
        self.orch.register_engagement(eng)
        try:
            from aegis.storage.repositories import EngagementRepository
            from aegis.storage.session import get_session

            async with get_session() as session:
                repo = EngagementRepository(session)
                await repo.upsert(eng)
        except Exception as e:
            logger.debug("worker persist synthetic engagement skipped: %s", e)
        return eng

    async def _persist_findings(self, engagement_id: UUID, findings: list[Finding]) -> None:
        settings = get_settings()
        if not settings.persist_findings or not findings:
            return
        try:
            from aegis.storage.repositories import FindingRepository
            from aegis.storage.session import get_session

            async with get_session() as session:
                repo = FindingRepository(session)
                for f in findings:
                    await repo.create(f)
            logger.info("persisted %d findings for engagement %s", len(findings), engagement_id)
        except Exception as e:
            logger.warning("worker persist findings failed (dev OK): %s", e)

    async def process_task(self, task: dict[str, Any]) -> dict[str, Any]:
        engagement_id = task.get("engagement_id")
        recipient = task.get("recipient") or task.get("agent_id")
        if not engagement_id or not recipient:
            return {"ok": False, "error": "engagement_id and recipient required"}
        eid = UUID(str(engagement_id))
        await self.ensure_engagement(eid, task)
        try:
            msg_type = MsgType(task.get("msg_type", "task"))
        except (ValueError, TypeError):
            msg_type = MsgType.TASK
        msg = AgentMessage(
            engagement_id=eid,
            sender=task.get("sender", "worker"),
            recipient=recipient,
            msg_type=msg_type,
            priority=int(task.get("priority", 3)),
            payload=task.get("payload") or {},
        )
        try:
            result = await self.orch.dispatch(msg)
            findings: list[Finding] = []
            if isinstance(result, list) and result and isinstance(result[0], Finding):
                findings = result
                await self._persist_findings(eid, findings)
            if hasattr(result, "model_dump"):
                data: Any = result.model_dump(mode="json")
            elif isinstance(result, list):
                data = [
                    r.model_dump(mode="json") if hasattr(r, "model_dump") else r for r in result
                ]
            else:
                data = result
            self.processed += 1
            return {
                "ok": True,
                "task_id": task.get("task_id"),
                "result": data,
                "findings_persisted": len(findings),
            }
        except Exception as e:
            logger.exception("task failed")
            self.failed += 1
            return {"ok": False, "task_id": task.get("task_id"), "error": str(e)}

    async def run_forever(self, poll_interval: float = 0.1) -> None:
        await self.bus.connect()
        self._running = True
        logger.info(
            "worker %s started (%d agents) — Redis=%s",
            self.consumer_name,
            len(self.orch.agents),
            "yes" if self.bus._client else "in-memory",
        )
        while self._running:
            tasks = await self.bus.dequeue(self.consumer_name, count=5, block_ms=2000)
            if not tasks:
                await asyncio.sleep(poll_interval)
                continue
            for task in tasks:
                result = await self.process_task(task)
                await self.bus.publish_result(result)
                if result.get("ok"):
                    await self.bus.ack(task.get("_redis_id", ""))
                else:
                    await self.bus.dead_letter(task, result.get("error", "unknown"))
                    await self.bus.ack(task.get("_redis_id", ""))

    def stop(self) -> None:
        self._running = False


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    worker = Worker()
    await worker.run_forever()


if __name__ == "__main__":
    asyncio.run(main())
