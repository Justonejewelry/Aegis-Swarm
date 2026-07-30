"""Executive Reporter — summarizes findings into board-ready risk narrative."""
from __future__ import annotations

from collections import Counter

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, MsgType, Severity


class ExecutiveReporter(BaseAgent):
    agent_id = "executive-reporter"
    domain = "reporting"

    async def handle(self, message: AgentMessage) -> AgentMessage:
        findings = message.payload.get("findings", [])
        by_sev = Counter(f.get("severity", "info") for f in findings)
        top = sorted(findings, key=lambda f: f.get("risk_score", 0), reverse=True)[:5]

        narrative = (
            f"Engagement produced {len(findings)} findings. "
            f"Critical={by_sev.get(Severity.CRITICAL.value, 0)}, "
            f"High={by_sev.get(Severity.HIGH.value, 0)}, "
            f"Medium={by_sev.get(Severity.MEDIUM.value, 0)}. "
            "Prioritize remediation of the top residual-risk items below."
        )
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload={
                "executive_summary": narrative,
                "severity_counts": dict(by_sev),
                "top_findings": top,
                "recommendations": [
                    "Fund closure of critical/high residual risk within 30 days",
                    "Expand detection coverage for techniques observed in paths",
                    "Schedule purple-team retest after remediation",
                ],
            },
            confidence=0.85,
            correlation_id=message.correlation_id,
        )
