"""Timeline Builder — merges multi-source events into a coherent incident timeline."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, MsgType


class TimelineBuilder(BaseAgent):
    agent_id = "timeline-builder"
    domain = "dfir"

    async def handle(self, message: AgentMessage) -> AgentMessage:
        events = list(message.payload.get("events", []))
        events.sort(key=lambda e: e.get("ts", ""))
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload={"timeline": events, "event_count": len(events)},
            confidence=0.9 if events else 0.2,
            correlation_id=message.correlation_id,
        )
