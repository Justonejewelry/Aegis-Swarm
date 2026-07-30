import pytest
from uuid import uuid4

from aegis.agents.red.attack_path_modeler import AttackPathModeler
from aegis.core.models import AgentMessage, MsgType


@pytest.mark.asyncio
async def test_path_modeler_finds_path():
    agent = AttackPathModeler()
    eng = uuid4()
    msg = AgentMessage(
        engagement_id=eng,
        sender="test",
        recipient=agent.agent_id,
        msg_type=MsgType.TASK,
        payload={
            "edges": [
                {"src": "userA", "dst": "groupHelpdesk", "relation": "member"},
                {"src": "groupHelpdesk", "dst": "serverJump", "relation": "admin"},
                {"src": "serverJump", "dst": "dc01", "relation": "admin"},
            ],
            "entries": ["userA"],
            "targets": ["dc01"],
        },
    )
    findings = await agent.handle(msg)
    assert len(findings) == 1
    assert "dc01" in findings[0].assets
