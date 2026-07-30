"""Global orchestrator — routes tasks to domain agents within engagement scope."""
from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Engagement, EngagementStatus, MsgType

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self) -> None:
        self.agents: dict[str, BaseAgent] = {}
        self.engagements: dict[UUID, Engagement] = {}

    def register(self, agent: BaseAgent) -> None:
        self.agents[agent.agent_id] = agent
        logger.info("registered agent %s (%s)", agent.agent_id, agent.domain)

    def register_engagement(self, engagement: Engagement) -> None:
        if engagement.status not in {
            EngagementStatus.ACTIVE,
            EngagementStatus.PENDING_APPROVAL,
            EngagementStatus.DRAFT,
        }:
            raise ValueError(f"Cannot register engagement in status {engagement.status}")
        self.engagements[engagement.engagement_id] = engagement

    async def dispatch(self, message: AgentMessage) -> Any:
        eng = self.engagements.get(message.engagement_id)
        if eng is None:
            raise PermissionError("Unknown engagement_id — refuse task")
        if eng.status != EngagementStatus.ACTIVE and message.msg_type != MsgType.CONTROL:
            raise PermissionError(
                f"Engagement {eng.engagement_id} is {eng.status}; only CONTROL messages allowed"
            )

        agent = self.agents.get(message.recipient)
        if agent is None:
            raise KeyError(f"Unknown agent: {message.recipient}")

        await agent.audit("dispatch", {"message_id": str(message.message_id)})
        return await agent.handle(message)

    def list_agents(self) -> list[dict[str, str]]:
        return [
            {"agent_id": a.agent_id, "domain": a.domain, "version": a.version}
            for a in self.agents.values()
        ]
