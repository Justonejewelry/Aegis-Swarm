"""Risk Prioritization — rank findings by residual risk for executive backlog."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, MsgType
from aegis.core.risk import prioritize


class RiskPrioritization(BaseAgent):
    agent_id = "risk-prioritization"
    domain = "reporting"

    async def handle(self, message: AgentMessage) -> AgentMessage:
        raw = message.payload.get("findings", [])
        findings = [Finding.model_validate(x) if isinstance(x, dict) else x for x in raw]
        ordered = prioritize(findings)
        bands = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in ordered:
            if f.risk_score >= 80:
                bands["critical"] += 1
            elif f.risk_score >= 60:
                bands["high"] += 1
            elif f.risk_score >= 40:
                bands["medium"] += 1
            elif f.risk_score >= 20:
                bands["low"] += 1
            else:
                bands["info"] += 1
        await self.audit("prioritized", {"total": len(ordered)})
        self._tasks_completed += 1
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload={
                "bands": bands,
                "top": [
                    {"title": f.title, "risk_score": f.risk_score, "severity": f.severity.value}
                    for f in ordered[:10]
                ],
            },
            confidence=0.88,
            correlation_id=message.correlation_id,
        )
