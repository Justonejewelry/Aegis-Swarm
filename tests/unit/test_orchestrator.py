import pytest
from uuid import uuid4

from aegis.agents.intel.attack_mapper import AttackMapper
from aegis.core.models import (
    AgentMessage,
    Engagement,
    EngagementMode,
    EngagementStatus,
    MsgType,
    Scope,
)
from aegis.core.orchestrator import Orchestrator


@pytest.mark.asyncio
async def test_dispatch_requires_active_engagement():
    orch = Orchestrator()
    orch.register(AttackMapper())
    eng = Engagement(
        name="test",
        mode=EngagementMode.ASSESS,
        scope=Scope(in_scope_cidrs=["10.0.0.0/8"], in_scope_domains=[], out_of_scope=[]),
        status=EngagementStatus.DRAFT,
    )
    orch.register_engagement(eng)
    msg = AgentMessage(
        engagement_id=eng.engagement_id,
        sender="test",
        recipient="attack-mapper",
        msg_type=MsgType.TASK,
        payload={"text": "powershell beacon"},
    )
    with pytest.raises(PermissionError):
        await orch.dispatch(msg)


@pytest.mark.asyncio
async def test_attack_mapper_maps_techniques():
    orch = Orchestrator()
    orch.register(AttackMapper())
    eng = Engagement(
        name="test",
        mode=EngagementMode.ASSESS,
        scope=Scope(),
        status=EngagementStatus.ACTIVE,
    )
    orch.register_engagement(eng)
    msg = AgentMessage(
        engagement_id=eng.engagement_id,
        sender="test",
        recipient="attack-mapper",
        msg_type=MsgType.TASK,
        payload={"text": "suspicious powershell and ransomware notes"},
    )
    result = await orch.dispatch(msg)
    assert "T1059.001" in result.mitre_techniques
    assert "T1486" in result.mitre_techniques
