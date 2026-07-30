"""Threat Hunter — hypothesis-driven hunt producing prioritized leads."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class ThreatHunter(BaseAgent):
    agent_id = "threat-hunter"
    domain = "blue"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        hypothesis = message.payload.get("hypothesis", "")
        observables = message.payload.get("observables", [])
        hits = message.payload.get("hits", [])

        if not hits:
            await self.audit("hunt_negative", {"hypothesis": hypothesis})
            self._tasks_completed += 1
            return []

        conf = self.compute_confidence(
            source_quality=0.75,
            corroboration=len(hits),
            freshness_hours=float(message.payload.get("age_hours", 12)),
            false_positive_rate=0.2,
        )
        techniques = sorted({t for h in hits for t in h.get("mitre", [])}) or ["T1047"]
        finding = Finding(
            engagement_id=message.engagement_id,
            title=f"Hunt lead: {hypothesis[:80] or 'unnamed hypothesis'}",
            description=f"{len(hits)} supporting hits across {len(observables)} observables",
            severity=Severity.HIGH if conf >= 0.7 else Severity.MEDIUM,
            category="active_threat",
            confidence=conf,
            mitre_techniques=techniques,
            assets=[h.get("host", "") for h in hits if h.get("host")],
            sources=["threat-hunter"],
            remediation=[
                "Scope containment for implicated hosts",
                "Collect volatile evidence before remediation",
                "Promote detection rule from this hypothesis if validated",
            ],
            evidence_refs=[h.get("event_id", "") for h in hits if h.get("event_id")],
        )
        finding.risk_score = score_finding(finding, asset_criticality=0.75, exploitability=0.55)
        await self.audit("hunt_lead", {"finding_id": str(finding.finding_id)})
        self._tasks_completed += 1
        return [finding]
