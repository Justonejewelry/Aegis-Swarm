"""Reporting catalog agents."""
from __future__ import annotations

from aegis.core.compact_agent import ResultAgent
from aegis.core.models import AgentMessage


class TechnicalReporting(ResultAgent):
    agent_id = "technical-reporting"
    domain = "reporting"

    async def compute(self, message: AgentMessage) -> dict:
        findings = message.payload.get("findings", [])
        return {
            "report_type": "technical",
            "sections": [
                {"name": "Executive summary", "count": min(5, len(findings))},
                {"name": "Findings detail", "count": len(findings)},
                {"name": "Remediation", "count": sum(len(f.get("remediation", [])) for f in findings)},
            ],
            "finding_count": len(findings),
            "_confidence": 0.85,
        }


class DashboardGenerator(ResultAgent):
    agent_id = "dashboard-generator"
    domain = "reporting"

    async def compute(self, message: AgentMessage) -> dict:
        metrics = message.payload.get("metrics", {})
        return {
            "widgets": [
                {"id": "risk_index", "value": metrics.get("risk_index", 0)},
                {"id": "open_findings", "value": metrics.get("open_findings", 0)},
                {"id": "coverage", "value": metrics.get("coverage", 0)},
            ],
            "_confidence": 0.9,
        }


class ComplianceReporting(ResultAgent):
    agent_id = "compliance-reporting"
    domain = "reporting"

    async def compute(self, message: AgentMessage) -> dict:
        framework = message.payload.get("framework", "NIST-CSF")
        controls = message.payload.get("controls", [])
        mapped = sum(1 for c in controls if c.get("status") == "met")
        return {
            "framework": framework,
            "controls_total": len(controls),
            "controls_met": mapped,
            "coverage_pct": round(100 * mapped / len(controls), 1) if controls else 0,
            "_confidence": 0.8,
        }
