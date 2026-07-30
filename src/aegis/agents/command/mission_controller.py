"""Mission Controller — approves scope, starts/stops engagements, enforces kill-switch."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, EngagementStatus, MsgType, utcnow


class MissionController(BaseAgent):
    agent_id = "mission-controller"
    domain = "command"

    async def handle(self, message: AgentMessage) -> AgentMessage | None:
        action = message.payload.get("action")
        await self.audit("mission_control", {"action": action})

        if action == "approve_engagement":
            return AgentMessage(
                engagement_id=message.engagement_id,
                sender=self.agent_id,
                recipient=message.sender,
                msg_type=MsgType.CONTROL,
                payload={
                    "status": EngagementStatus.ACTIVE.value,
                    "approved_at": utcnow().isoformat(),
                    "approver": message.payload.get("approver", "unknown"),
                },
                correlation_id=message.correlation_id,
            )

        if action == "abort":
            return AgentMessage(
                engagement_id=message.engagement_id,
                sender=self.agent_id,
                recipient="*",
                msg_type=MsgType.CONTROL,
                priority=1,
                payload={"status": EngagementStatus.ABORTED.value, "reason": message.payload.get("reason")},
                correlation_id=message.correlation_id,
            )

        return None
