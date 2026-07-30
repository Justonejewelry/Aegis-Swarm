"""Threat intelligence catalog agents."""
from __future__ import annotations

from aegis.core.compact_agent import AnalyticAgent, ResultAgent
from aegis.core.models import AgentMessage, Severity


class CampaignCorrelator(ResultAgent):
    agent_id = "campaign-correlator"
    domain = "intel"

    async def compute(self, message: AgentMessage) -> dict:
        events = message.payload.get("events", [])
        clusters: dict[str, list] = {}
        for e in events:
            tag = e.get("campaign") or e.get("family") or "unknown"
            clusters.setdefault(tag, []).append(e.get("id", ""))
        return {"campaigns": {k: len(v) for k, v in clusters.items()}, "_confidence": 0.7, "_techniques": ["T1583"]}


class ThreatIntelFusion(ResultAgent):
    agent_id = "threat-intel-fusion"
    domain = "intel"

    async def compute(self, message: AgentMessage) -> dict:
        feeds = message.payload.get("feeds", [])
        merged = []
        seen = set()
        for feed in feeds:
            for ioc in feed.get("iocs", []):
                val = ioc.get("value")
                if val and val not in seen:
                    seen.add(val)
                    merged.append(ioc)
        return {"merged_iocs": merged, "sources": len(feeds), "_confidence": 0.75, "_techniques": ["T1583"]}


class TTPClassifier(AnalyticAgent):
    agent_id = "ttp-classifier"
    domain = "intel"
    payload_key = "behaviors"
    default_techniques = ["T1059"]

    MAP = {
        "powershell": "T1059.001",
        "wmi": "T1047",
        "credential dump": "T1003",
        "lateral": "T1021",
        "ransomware": "T1486",
        "phish": "T1566",
    }

    def rules(self, events, message):
        text = " ".join(str(e.get("description", e)) for e in events).lower()
        techniques = sorted({t for k, t in self.MAP.items() if k in text})
        if not techniques:
            return []
        return [self.finding(
            message,
            title="TTP classification from behaviors",
            description=f"Mapped techniques: {', '.join(techniques)}",
            severity=Severity.MEDIUM,
            techniques=techniques,
            confidence=0.7,
        )]
