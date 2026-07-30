"""Root Cause Analyst — rank initial-access hypotheses from timeline evidence."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, MsgType


class RootCauseAnalyst(BaseAgent):
    agent_id = "root-cause-analyst"
    domain = "dfir"

    KEYWORDS = {
        "phishing": ("T1566", 0.7),
        "exploit": ("T1190", 0.65),
        "valid accounts": ("T1078", 0.6),
        "remote services": ("T1021", 0.55),
        "supply chain": ("T1195", 0.5),
    }

    async def handle(self, message: AgentMessage) -> AgentMessage:
        timeline = message.payload.get("timeline", [])
        text = " ".join(str(e.get("summary", "")) for e in timeline).lower()
        hypotheses = []
        for kw, (tech, base) in self.KEYWORDS.items():
            if kw in text:
                hypotheses.append({
                    "hypothesis": f"Initial access via {kw}",
                    "technique": tech,
                    "confidence": round(min(0.95, base + 0.05 * text.count(kw)), 2),
                })
        hypotheses.sort(key=lambda h: h["confidence"], reverse=True)
        await self.audit("rca", {"hypotheses": len(hypotheses)})
        self._tasks_completed += 1
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload={"root_cause_hypotheses": hypotheses[:5]},
            confidence=hypotheses[0]["confidence"] if hypotheses else 0.2,
            mitre_techniques=[h["technique"] for h in hypotheses[:5]],
            correlation_id=message.correlation_id,
        )
