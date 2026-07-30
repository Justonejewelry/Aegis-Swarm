"""SIEM Correlator — multi-source alert correlation into candidate findings."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class SIEMCorrelator(BaseAgent):
    agent_id = "siem-correlator"
    domain = "blue"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        events = message.payload.get("events", [])
        if len(events) < 2:
            return []

        hosts = {e.get("host") for e in events if e.get("host")}
        users = {e.get("user") for e in events if e.get("user")}
        techniques = sorted({t for e in events for t in e.get("mitre", [])})

        conf = self.compute_confidence(
            source_quality=0.7,
            corroboration=len(events),
            freshness_hours=float(message.payload.get("age_hours", 1)),
            false_positive_rate=0.15,
        )

        finding = Finding(
            engagement_id=message.engagement_id,
            title="Correlated multi-source authentication anomaly",
            description=f"Correlated {len(events)} events across hosts={hosts} users={users}",
            severity=Severity.MEDIUM if conf < 0.75 else Severity.HIGH,
            category="identity",
            confidence=conf,
            mitre_techniques=techniques or ["T1078"],
            assets=list(hosts),
            sources=["siem-correlator"],
            remediation=[
                "Review authentication logs for the correlated principals",
                "Validate MFA status and conditional access policies",
                "Check for concurrent impossible-travel indicators",
            ],
        )
        finding.risk_score = score_finding(finding, asset_criticality=0.7, exploitability=0.4)
        await self.audit("finding_emitted", {"finding_id": str(finding.finding_id)})
        self._tasks_completed += 1
        return [finding]
