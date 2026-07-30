"""Security Gap Analyst — consolidate gaps into prioritized remediation backlog."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, MsgType
from aegis.core.risk import prioritize


class SecurityGapAnalyst(BaseAgent):
    agent_id = "security-gap-analyst"
    domain = "purple"

    async def handle(self, message: AgentMessage) -> AgentMessage:
        from aegis.core.models import Finding

        raw = message.payload.get("findings", [])
        findings = [Finding.model_validate(x) if isinstance(x, dict) else x for x in raw]
        ordered = prioritize(findings)
        backlog = [
            {
                "finding_id": str(f.finding_id),
                "title": f.title,
                "risk_score": f.risk_score,
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "remediation": f.remediation[:2],
            }
            for f in ordered[:25]
        ]
        await self.audit("gap_backlog", {"items": len(backlog)})
        self._tasks_completed += 1
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload={"backlog": backlog, "total": len(ordered)},
            confidence=0.85,
            correlation_id=message.correlation_id,
        )
