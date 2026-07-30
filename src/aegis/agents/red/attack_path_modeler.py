"""Attack Path Modeler — builds privilege/asset graphs for authorized path analysis."""
from __future__ import annotations

import networkx as nx

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
        """
        edges = message.payload.get("edges", [])
        entries = message.payload.get("entries", [])
        targets = message.payload.get("targets", [])

        g = nx.DiGraph()
        for e in edges:
            g.add_edge(e["src"], e["dst"], relation=e.get("relation", "related"))

        findings: list[Finding] = []
        for entry in entries:
            for target in targets:
                if entry not in g or target not in g:
                    continue
                try:
                    path = nx.shortest_path(g, entry, target)
                except nx.NetworkXNoPath:
                    continue
                if len(path) < 2:
                    continue
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

        await self.audit("paths_modeled", {"count": len(findings)})
        self._tasks_completed += 1
        return findings
