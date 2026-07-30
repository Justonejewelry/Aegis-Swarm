"""Purple team catalog agents."""
from __future__ import annotations

from aegis.core.compact_agent import AnalyticAgent, ResultAgent
from aegis.core.models import AgentMessage, Severity


class LoggingCoverageAnalyst(AnalyticAgent):
    agent_id = "logging-coverage-analyst"
    domain = "purple"
    payload_key = "required_sources"
    default_category = "detection_gap"
    default_techniques = ["T1070"]

    def rules(self, events, message):
        present = set(message.payload.get("present_sources", []))
        missing = [s for s in events if (s if isinstance(s, str) else s.get("name")) not in present]
        if not missing:
            return []
        names = [m if isinstance(m, str) else m.get("name", "?") for m in missing]
        return [self.finding(
            message,
            title=f"Logging coverage gaps ({len(names)})",
            description="Required log sources not present: " + ", ".join(names[:10]),
            severity=Severity.HIGH,
            remediation=["Onboard missing sources", "Verify retention and field completeness"],
            confidence=0.9,
        )]


class ControlValidationAgent(AnalyticAgent):
    agent_id = "control-validation-agent"
    domain = "purple"
    payload_key = "control_tests"
    default_category = "detection_gap"
    default_techniques = ["T1562"]

    def rules(self, events, message):
        failed = [t for t in events if not t.get("passed")]
        if not failed:
            return []
        return [self.finding(
            message,
            title=f"Security control validation failures ({len(failed)})",
            description="Authorized control tests did not meet expected outcomes",
            severity=Severity.HIGH,
            techniques=[t.get("technique", "T1562") for t in failed],
            remediation=["Remediate failed controls", "Retest after change"],
            confidence=0.85,
        )]


class AttackCoverageAgent(ResultAgent):
    agent_id = "attack-coverage-agent"
    domain = "purple"

    async def compute(self, message: AgentMessage) -> dict:
        matrix = message.payload.get("matrix", {})
        scores = []
        gaps = []
        for tech, cells in matrix.items():
            vals = [float(cells.get(k, 0)) for k in ("detect", "prevent", "log", "validate")]
            score = sum(vals) / 4 if vals else 0
            scores.append(score)
            if score < 0.5:
                gaps.append(tech)
        avg = sum(scores) / len(scores) if scores else 0
        return {
            "enterprise_coverage": round(avg, 3),
            "gap_techniques": gaps[:30],
            "_confidence": 0.85,
            "_techniques": gaps[:10],
        }
