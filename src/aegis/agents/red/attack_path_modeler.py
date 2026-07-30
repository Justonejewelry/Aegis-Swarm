"""Attack Path Modeler — builds privilege/asset graphs for authorized path analysis."""
from __future__ import annotations

from aegis.analytics.graph_store import get_graph_store
from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class AttackPathModeler(BaseAgent):
    agent_id = "attack-path-modeler"
    domain = "red"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        """
        Input payload.edges: list of {src, dst, relation}
        Finds shortest paths from entry nodes to high-value targets.
        Uses shared GraphStore so subsequent agents see the same graph.
        """
        edges = message.payload.get("edges", [])
        entries = message.payload.get("entries", [])
        targets = message.payload.get("targets", [])
        store = get_graph_store()
        if edges:
            store.add_edges(message.engagement_id, edges)

        paths = store.shortest_paths(message.engagement_id, entries, targets)

        findings: list[Finding] = []
        for path in paths:
            entry, target = path[0], path[-1]
            finding = Finding(
                engagement_id=message.engagement_id,
                title=f"Attack path: {entry} → {target}",
                description=f"Path length {len(path) - 1}: {' → '.join(path)}",
                severity=Severity.HIGH if len(path) <= 4 else Severity.MEDIUM,
                category="identity",
                confidence=0.75,
                mitre_techniques=["T1078", "T1021"],
                assets=path,
                sources=["attack-path-modeler"],
                remediation=[
                    "Break path with tiered admin model / PAW",
                    "Remove unnecessary group membership edges",
                    "Enable detection for unusual privilege use along the path",
                ],
            )
            finding.risk_score = score_finding(
                finding,
                asset_criticality=0.9,
                exploitability=0.7,
                exposure=0.6,
                detection_coverage=0.3,
            )
            findings.append(finding)

        await self.audit(
            "paths_modeled",
            {
                "count": len(findings),
                "graph_nodes": len(store.get_or_create(message.engagement_id).nodes),
            },
        )
        self._tasks_completed += 1
        return findings
