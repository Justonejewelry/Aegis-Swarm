import pytest
from uuid import uuid4

from aegis.agents.blue.authentication_analyst import AuthenticationAnalyst
from aegis.core.models import AgentMessage, MsgType


@pytest.mark.asyncio
async def test_brute_force_detection():
    agent = AuthenticationAnalyst()
    events = [{"result": "failure", "user": "alice"} for _ in range(12)]
    msg = AgentMessage(
        engagement_id=uuid4(),
        sender="test",
        recipient=agent.agent_id,
        msg_type=MsgType.TASK,
        payload={"auth_events": events},
    )
    findings = await agent.handle(msg)
    assert any("brute-force" in f.title.lower() for f in findings)
