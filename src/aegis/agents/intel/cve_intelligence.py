"""CVE Intelligence — enrich assets with CVE / EPSS / KEV context."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class CVEIntelligence(BaseAgent):
    agent_id = "cve-intelligence"
    domain = "intel"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        items = message.payload.get("cves", [])
        findings: list[Finding] = []
        for item in items:
            epss = float(item.get("epss", 0))
            kev = bool(item.get("kev", False))
            cvss = float(item.get("cvss", 0))
            if not kev and epss < 0.1 and cvss < 7:
                continue
            severity = Severity.CRITICAL if kev or (epss >= 0.5 and cvss >= 9) else (
                Severity.HIGH if epss >= 0.2 or cvss >= 7 else Severity.MEDIUM
            )
            conf = self.compute_confidence(
                source_quality=0.85,
                corroboration=2 if kev else 1,
                freshness_hours=float(item.get("age_hours", 48)),
            )
            f = Finding(
                engagement_id=message.engagement_id,
                title=f"{item.get('cve_id', 'CVE')} — elevated exploit risk",
                description=f"CVSS={cvss}, EPSS={epss}, KEV={'yes' if kev else 'no'}",
                severity=severity,
                category="vulnerability",
                confidence=conf,
                mitre_techniques=["T1190"],
                cves=[item.get("cve_id", "")],
                assets=item.get("assets", []),
                sources=["cve-intelligence"],
                remediation=[
                    "Patch or mitigate per vendor advisory",
                    "Verify compensating controls if patch delayed",
                    "Prioritize internet-facing assets first",
                ],
            )
            f.risk_score = score_finding(
                f,
                asset_criticality=0.8,
                exploitability=min(1.0, epss + (0.3 if kev else 0)),
                exposure=0.7 if item.get("internet_facing") else 0.4,
            )
            findings.append(f)

        await self.audit("cve_enrichment", {"count": len(findings)})
        self._tasks_completed += 1
        return findings
