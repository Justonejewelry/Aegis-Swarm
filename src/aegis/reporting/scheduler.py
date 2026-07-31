"""Lightweight executive report scheduler."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from uuid import UUID

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ScheduledReport:
    schedule_id: str
    engagement_id: UUID
    interval_hours: int = 24
    last_run: datetime | None = None
    enabled: bool = True
    meta: dict[str, Any] = field(default_factory=dict)


class ReportScheduler:
    def __init__(self) -> None:
        self._jobs: dict[str, ScheduledReport] = {}

    def schedule(self, schedule_id: str, engagement_id: UUID | str, interval_hours: int = 24, **meta: Any) -> ScheduledReport:
        job = ScheduledReport(schedule_id=schedule_id, engagement_id=UUID(str(engagement_id)), interval_hours=interval_hours, meta=meta)
        self._jobs[schedule_id] = job
        return job

    def unschedule(self, schedule_id: str) -> None:
        self._jobs.pop(schedule_id, None)

    def due(self, now: datetime | None = None) -> list[ScheduledReport]:
        now = now or utcnow()
        out: list[ScheduledReport] = []
        for job in self._jobs.values():
            if not job.enabled:
                continue
            if job.last_run is None or (now - job.last_run).total_seconds() / 3600.0 >= job.interval_hours:
                out.append(job)
        return out

    async def tick(self, render: Callable[[UUID], Awaitable[Any]], now: datetime | None = None) -> list[dict[str, Any]]:
        now = now or utcnow()
        results: list[dict[str, Any]] = []
        for job in self.due(now):
            try:
                await render(job.engagement_id)
                job.last_run = now
                results.append({"schedule_id": job.schedule_id, "ok": True, "engagement_id": str(job.engagement_id)})
            except Exception as e:
                logger.exception("scheduled report failed")
                results.append({"schedule_id": job.schedule_id, "ok": False, "error": str(e)})
        return results

    def list_jobs(self) -> list[ScheduledReport]:
        return list(self._jobs.values())


_scheduler: ReportScheduler | None = None


def get_report_scheduler() -> ReportScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = ReportScheduler()
    return _scheduler
