"""Privilege Graph Analysis — score dangerous privilege edges (authorized)."""
from __future__ import annotations

from aegis.analytics.graph_store import get_graph_store
from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class PrivilegeGraphAnalysis(BaseAgent):
    agent_id = "privilege-graph-analysis"
    domain = "red"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        edges = message.payload.get("edges", [])
        high_value = list(message.payload.get("high_value_nodes", []))
        store = get_graph_store()
        if edges:
            store.add_edges(message.engagement_id, edges)

        concentrations = store.privilege_concentration(message.engagement_id, high_value)

        findings: list[Finding] = []
        for item in concentrations:
            node = item["node"]
            reachable_hv = item["reachable_hv"]
            f = Finding(
                engagement_id=message.engagement_id,
                title=f"Privilege concentration: {node} reaches {reachable_hv} high-value nodes",
                description="Authorized graph analysis of privilege relationships",
                severity=Severity.HIGH if reachable_hv >= 3 else Severity.MEDIUM,
                category="identity",
                confidence=0.8,
                mitre_techniques=["T1078", "T1021"],
                assets=[node, *high_value[:5]],
                sources=["privilege-graph-analysis"],
                remediation=[
                    "Apply tiered administration / least privilege",
                    "Remove transitive group grants where possible",
                    "Monitor anomalous use of this principal",
                ],
            )
            f.risk_score = score_finding(f, asset_criticality=0.85, exploitability=0.6)
            findings.append(f)

        await self.audit("priv_graph", {"findings": len(findings)})
        self._tasks_completed += 1
        return findings
