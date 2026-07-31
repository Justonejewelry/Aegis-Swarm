"""Ingestion fan-in → normalize → optional task-bus enqueue."""
from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

logger = logging.getLogger(__name__)

DEFAULT_ROUTING: dict[str, str] = {
    "critical": "threat-hunter",
    "high": "siem-correlator",
    "medium": "siem-correlator",
    "low": "network-traffic-analyst",
    "info": "siem-correlator",
}


class IngestionPipeline:
    def __init__(self, connectors: list[Any] | None = None) -> None:
        self.connectors: list[Any] = list(connectors or [])

    async def collect(self, limit_per_connector: int = 100, since: str | None = None) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for conn in self.connectors:
            try:
                batch = await conn.fetch(since=since, limit=limit_per_connector)
                events.extend(batch)
            except Exception:
                logger.exception("connector %s failed", getattr(conn, "name", conn))
        return events

    def route_recipient(self, event: dict[str, Any]) -> str:
        sev = str(event.get("severity") or "info").lower()
        return DEFAULT_ROUTING.get(sev, "siem-correlator")

    async def collect_and_enqueue(
        self,
        *,
        engagement_id: UUID | str,
        bus: Any,
        limit_per_connector: int = 100,
        since: str | None = None,
        domain: str | None = None,
        default_recipient: str | None = None,
    ) -> dict[str, Any]:
        events = await self.collect(limit_per_connector=limit_per_connector, since=since)
        task_ids: list[str] = []
        for event in events:
            recipient = default_recipient or self.route_recipient(event)
            payload = {
                "engagement_id": str(engagement_id),
                "recipient": recipient,
                "payload": {"event": event, "source": event.get("source")},
                "priority": 2 if str(event.get("severity", "")).lower() in {"critical", "high"} else 3,
                "sender": "ingestion",
                "msg_type": "task",
            }
            if domain:
                payload["domain"] = domain
            tid = await bus.enqueue(payload, domain=domain)
            task_ids.append(tid)
        logger.info(
            "ingestion enqueued %d tasks for engagement %s domain=%s",
            len(task_ids),
            engagement_id,
            domain,
        )
        return {"events": len(events), "enqueued": len(task_ids), "task_ids": task_ids}
