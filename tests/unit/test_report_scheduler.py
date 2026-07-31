from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from aegis.reporting.scheduler import ReportScheduler

@pytest.mark.asyncio
async def test_scheduler_due_and_tick():
    sched = ReportScheduler()
    eid = uuid4()
    sched.schedule("daily", eid, interval_hours=24)
    rendered = []
    async def render(eng_id):
        rendered.append(eng_id)
    results = await sched.tick(render)
    assert results[0]["ok"] is True
    assert rendered == [eid]
