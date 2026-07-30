"""Helpers for compact catalog agents with consistent finding emission."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, MsgType, Severity
from aegis.core.risk import score_finding


class AnalyticAgent(BaseAgent):
    """Pattern: read payload key → emit findings from rules."""

    payload_key: str = "events"
    default_category: str = "network"
    default_techniques: list[str] = ["T1071"]
    min_events: int = 1

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        return []

    async def handle(self, message: AgentMessage) -> list[Finding] | AgentMessage:
        events = message.payload.get(self.payload_key, [])
        if isinstance(events, dict):
            events = [events]
        if len(events) < self.min_events:
            await self.audit("insufficient_data", {"count": len(events)})
            self._tasks_completed += 1
            return []
        findings = self.rules(events, message)
        for f in findings:
            if f.risk_score == 0:
                f.risk_score = score_finding(f)
        await self.audit("analysis_complete", {"findings": len(findings)})
        self._tasks_completed += 1
        return findings

    def finding(
        self,
        message: AgentMessage,
        *,
        title: str,
        description: str,
        severity: Severity,
        category: str | None = None,
        techniques: list[str] | None = None,
        assets: list[str] | None = None,
        remediation: list[str] | None = None,
        confidence: float = 0.7,
        cves: list[str] | None = None,
    ) -> Finding:
        f = Finding(
            engagement_id=message.engagement_id,
            title=title,
            description=description,
            severity=severity,
            category=category or self.default_category,
            confidence=confidence,
            mitre_techniques=techniques or list(self.default_techniques),
            assets=assets or [],
            sources=[self.agent_id],
            remediation=remediation or ["Review and remediate per organizational policy"],
            cves=cves or [],
        )
        f.risk_score = score_finding(f)
        return f


class ResultAgent(BaseAgent):
    """Pattern: transform payload → RESULT message."""

    async def handle(self, message: AgentMessage) -> AgentMessage:
        payload = await self.compute(message)
        conf = float(payload.pop("_confidence", 0.8))
        techniques = payload.pop("_techniques", [])
        await self.audit("result", {"keys": list(payload.keys())})
        self._tasks_completed += 1
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload=payload,
            confidence=conf,
            mitre_techniques=techniques,
            correlation_id=message.correlation_id,
        )

    async def compute(self, message: AgentMessage) -> dict:
        return {"status": "ok"}
