"""Rule Coverage Analyst — ATT&CK technique × detection rule matrix gaps."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class RuleCoverageAnalyst(BaseAgent):
    agent_id = "rule-coverage-analyst"
    domain = "purple"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        techniques = message.payload.get("techniques", [])
        findings: list[Finding] = []
        for tech in techniques:
            rules = tech.get("rules") or []
            if rules:
                continue
            priority = tech.get("priority", "medium")
            severity = Severity.HIGH if priority == "high" else Severity.MEDIUM
            conf = 0.9
            f = Finding(
                engagement_id=message.engagement_id,
                title=f"Detection gap for {tech.get('id', 'technique')}",
                description="No detection rules mapped to this ATT&CK technique",
                severity=severity,
                category="detection_gap",
                confidence=conf,
                mitre_techniques=[tech.get("id", "T1059")],
                sources=["rule-coverage-analyst"],
                remediation=[
                    f"Author detection content for {tech.get('id')}",
                    "Confirm required log sources are onboarded",
                    "Schedule purple-team validation after rule deploy",
                ],
            )
            f.risk_score = score_finding(f, asset_criticality=0.7, exploitability=0.5, detection_coverage=0.0)
            findings.append(f)

        await self.audit("coverage_gaps", {"count": len(findings)})
        self._tasks_completed += 1
        return findings
