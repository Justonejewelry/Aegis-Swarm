"""Authentication Analyst — MFA gaps, impossible travel, brute-force patterns."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class AuthenticationAnalyst(BaseAgent):
    agent_id = "authentication-analyst"
    domain = "blue"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        events = message.payload.get("auth_events", [])
        findings: list[Finding] = []

        failures = [e for e in events if e.get("result") == "failure"]
        successes = [e for e in events if e.get("result") == "success"]
        no_mfa = [e for e in successes if e.get("mfa") is False]

        if len(failures) >= 10:
            conf = self.compute_confidence(source_quality=0.8, corroboration=len(failures), freshness_hours=1)
            f = Finding(
                engagement_id=message.engagement_id,
                title="Possible brute-force authentication pattern",
                description=f"{len(failures)} failed auth events in analysis window",
                severity=Severity.HIGH,
                category="identity",
                confidence=conf,
                mitre_techniques=["T1110"],
                assets=sorted({e.get("user", "") for e in failures if e.get("user")}),
                sources=["authentication-analyst"],
                remediation=[
                    "Enable lockout / smart lockout policies",
                    "Block source IPs exceeding failure thresholds",
                    "Require MFA for targeted accounts",
                ],
            )
            f.risk_score = score_finding(f, asset_criticality=0.8, exploitability=0.6)
            findings.append(f)

        if no_mfa:
            conf = self.compute_confidence(source_quality=0.7, corroboration=len(no_mfa), freshness_hours=6)
            f = Finding(
                engagement_id=message.engagement_id,
                title="Successful authentication without MFA",
                description=f"{len(no_mfa)} success events without MFA challenge",
                severity=Severity.MEDIUM,
                category="identity",
                confidence=conf,
                mitre_techniques=["T1078"],
                assets=sorted({e.get("user", "") for e in no_mfa if e.get("user")}),
                sources=["authentication-analyst"],
                remediation=[
                    "Enforce Conditional Access / MFA for all interactive logons",
                    "Review break-glass account controls",
                ],
            )
            f.risk_score = score_finding(f, asset_criticality=0.7, exploitability=0.5, detection_coverage=0.4)
            findings.append(f)

        await self.audit("auth_analysis", {"findings": len(findings)})
        self._tasks_completed += 1
        return findings
