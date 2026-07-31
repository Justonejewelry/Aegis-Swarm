from uuid import uuid4
import pytest
from aegis.core.models import Engagement, EngagementMode, EngagementStatus, Scope
from aegis.messaging.bus import TaskBus
from aegis.storage.cache import Cache

@pytest.mark.asyncio
async def test_bus_works_without_redis():
    bus = TaskBus(url="redis://127.0.0.1:59997/0")
    await bus.connect()
    tid = await bus.enqueue({"engagement_id": str(uuid4()), "recipient": "threat-hunter", "payload": {}})
    tasks = await bus.dequeue("chaos-worker", count=5)
    assert any(t.get("task_id") == tid for t in tasks)

@pytest.mark.asyncio
async def test_cache_memory_fallback_without_redis():
    cache = Cache(url="redis://127.0.0.1:59996/0", enabled=True)
    await cache.connect()
    eng = Engagement(name="chaos", mode=EngagementMode.ASSESS, scope=Scope(), status=EngagementStatus.ACTIVE)
    await cache.set_engagement(eng)
    assert (await cache.get_engagement(eng.engagement_id)).name == "chaos"
