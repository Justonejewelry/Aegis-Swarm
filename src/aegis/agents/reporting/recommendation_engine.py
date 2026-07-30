"""Recommendation Engine — turn findings into actionable remediation playbooks."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, MsgType


class RecommendationEngine(BaseAgent):
    agent_id = "recommendation-engine"
    domain = "reporting"

    async def handle(self, message: AgentMessage) -> AgentMessage:
        findings = message.payload.get("findings", [])
        actions = []
        for f in findings:
            for r in (f.get("remediation") or [])[:3]:
                actions.append({
                    "finding": f.get("title", ""),
                    "action": r,
                    "severity": f.get("severity", "info"),
                    "risk_score": f.get("risk_score", 0),
                })
        actions.sort(key=lambda a: a.get("risk_score", 0), reverse=True)
        await self.audit("recommendations", {"count": len(actions)})
        self._tasks_completed += 1
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload={"actions": actions[:50]},
            confidence=0.8,
            correlation_id=message.correlation_id,
        )
