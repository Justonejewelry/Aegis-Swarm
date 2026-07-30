import pytest

from aegis.messaging.bus import TaskBus
from aegis.messaging.worker import Worker


@pytest.mark.asyncio
async def test_memory_bus_enqueue_dequeue():
    bus = TaskBus()
    await bus.connect()
    tid = await bus.enqueue({
        "engagement_id": "00000000-0000-0000-0000-000000000001",
        "recipient": "attack-mapper",
        "payload": {"text": "powershell"},
    })
    assert tid
    tasks = await bus.dequeue("test-consumer", count=5)
    assert len(tasks) == 1
    assert tasks[0]["recipient"] == "attack-mapper"


@pytest.mark.asyncio
async def test_worker_processes_task():
    from uuid import uuid4

    from aegis.core.models import Engagement, EngagementMode, EngagementStatus, Scope

    worker = Worker()
    eng_id = uuid4()
    eng = Engagement(
        engagement_id=eng_id,
        name="t",
        mode=EngagementMode.ASSESS,
        scope=Scope(),
        status=EngagementStatus.ACTIVE,
    )
    worker.orch.register_engagement(eng)
    result = await worker.process_task({
        "engagement_id": str(eng_id),
        "recipient": "attack-mapper",
        "payload": {"text": "ransomware and powershell"},
        "task_id": "t1",
    })
    assert result["ok"] is True
    assert "T1059.001" in str(result["result"]) or "T1486" in str(result["result"])
