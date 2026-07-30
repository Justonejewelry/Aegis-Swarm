"""Privilege Graph Analysis — score dangerous privilege edges (authorized)."""
from __future__ import annotations

import networkx as nx

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class PrivilegeGraphAnalysis(BaseAgent):
    agent_id = "privilege-graph-analysis"
    domain = "red"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        edges = message.payload.get("edges", [])
        high_value = set(message.payload.get("high_value_nodes", []))
        g = nx.DiGraph()
        for e in edges:
            g.add_edge(e["src"], e["dst"], relation=e.get("relation", "priv"))

        findings: list[Finding] = []
        for node in list(g.nodes):
            reachable_hv = 0
            for hv in high_value:
                if node == hv:
                    continue
                if hv in g and nx.has_path(g, node, hv):
                    reachable_hv += 1
            if reachable_hv < 2:
                continue
            f = Finding(
                engagement_id=message.engagement_id,
                title=f"Privilege concentration: {node} reaches {reachable_hv} high-value nodes",
                description="Authorized graph analysis of privilege relationships",
                severity=Severity.HIGH if reachable_hv >= 3 else Severity.MEDIUM,
                category="identity",
                confidence=0.8,
                mitre_techniques=["T1078", "T1021"],
                assets=[node, *list(high_value)[:5]],
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
