"""Network Traffic Analyst — beaconing and unusual egress patterns."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, Finding, Severity
from aegis.core.risk import score_finding


class NetworkTrafficAnalyst(BaseAgent):
    agent_id = "network-traffic-analyst"
    domain = "blue"

    async def handle(self, message: AgentMessage) -> list[Finding]:
        flows = message.payload.get("flows", [])
        findings: list[Finding] = []

        by_pair: dict[str, list] = {}
        for fl in flows:
            key = f"{fl.get('src')}->{fl.get('dst')}:{fl.get('dport')}"
            by_pair.setdefault(key, []).append(fl)

        for key, group in by_pair.items():
            if len(group) < 5:
                continue
            intervals = sorted(float(g.get("interval_s", 0)) for g in group if g.get("interval_s"))
            if len(intervals) < 4:
                continue
            mean = sum(intervals) / len(intervals)
            var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
            if mean <= 0 or var > (mean * 0.15) ** 2:
                continue
            conf = self.compute_confidence(
                source_quality=0.7,
                corroboration=len(group),
                freshness_hours=float(message.payload.get("age_hours", 2)),
                false_positive_rate=0.25,
            )
            f = Finding(
                engagement_id=message.engagement_id,
                title=f"Possible C2 beaconing pattern: {key}",
                description=f"{len(group)} flows, mean interval {mean:.1f}s, low variance",
                severity=Severity.HIGH if conf >= 0.65 else Severity.MEDIUM,
                category="network",
                confidence=conf,
                mitre_techniques=["T1071"],
                assets=[group[0].get("src", "")],
                sources=["network-traffic-analyst"],
                remediation=[
                    "Capture full PCAP for the pair if policy allows",
                    "Check EDR process initiating the connection",
                    "Block destination if confirmed malicious and in scope",
                ],
            )
            f.risk_score = score_finding(f, asset_criticality=0.7, exploitability=0.65, exposure=0.7)
            findings.append(f)

        await self.audit("traffic_analysis", {"findings": len(findings)})
        self._tasks_completed += 1
        return findings
