"""IOC Correlator — match observables against known indicators."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class IOCCorrelator(BaseAgent):
    agent_id = "ioc-correlator"
    domain = "intel"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        observables = set(message.payload.get("observables", []))
        iocs = message.payload.get("iocs", [])
        findings: list[Finding] = []

        for ioc in iocs:
            val = ioc.get("value")
            if not val or val not in observables:
                continue
            sev = Severity(ioc.get("severity", "medium"))
            conf = self.compute_confidence(
                source_quality=float(ioc.get("source_quality", 0.8)),
                corroboration=1,
                freshness_hours=float(ioc.get("age_hours", 24)),
                false_positive_rate=float(ioc.get("fp_rate", 0.1)),
            )
            f = Finding(
                engagement_id=message.engagement_id,
                title=f"IOC match: {ioc.get('type', 'indicator')}={val}",
                description=f"Matched against intel source {ioc.get('source', 'unknown')}",
                severity=sev,
                category="active_threat",
                confidence=conf,
                mitre_techniques=ioc.get("mitre", ["T1071"]),
                assets=list(message.payload.get("assets", [])),
                sources=["ioc-correlator", ioc.get("source", "intel")],
                remediation=[
                    "Block or monitor the indicator per policy",
                    "Hunt historical presence of the IOC",
                    "Update detection content if coverage is missing",
                ],
            )
            f.risk_score = score_finding(f, asset_criticality=0.7, exploitability=0.7)
            findings.append(f)

        await self.audit("ioc_matches", {"count": len(findings)})
        self._tasks_completed += 1
        return findings
