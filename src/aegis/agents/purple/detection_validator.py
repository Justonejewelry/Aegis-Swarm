"""Detection Validator — purple-team check that a detection rule fires on known telemetry."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class DetectionValidator(BaseAgent):
    agent_id = "detection-validator"
    domain = "purple"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        rule_id = message.payload.get("rule_id", "unknown")
        fired = bool(message.payload.get("rule_fired"))
        technique = message.payload.get("technique", "T1059")

        if fired:
            await self.audit("detection_validated", {"rule_id": rule_id, "technique": technique})
            self._tasks_completed += 1
            return []

        finding = Finding(
            engagement_id=message.engagement_id,
            title=f"Detection gap: rule {rule_id} did not fire",
            description=(
                f"Authorized purple-team validation expected rule '{rule_id}' "
                f"to fire for technique {technique}, but no alert was observed."
            ),
            severity=Severity.HIGH,
            category="detection_gap",
            confidence=0.85,
            mitre_techniques=[technique],
            sources=["detection-validator"],
            remediation=[
                f"Review rule logic for {rule_id}",
                "Confirm required telemetry fields are ingested",
                "Add regression test for this technique in CI",
            ],
        )
        finding.risk_score = score_finding(
            finding, asset_criticality=0.8, exploitability=0.6, detection_coverage=0.1
        )
        self._tasks_completed += 1
        return [finding]
