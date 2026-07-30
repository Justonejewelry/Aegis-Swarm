"""ATT&CK Mapper — maps findings and observables to MITRE ATT&CK techniques."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, MsgType

KEYWORD_MAP = {
    "pass-the-hash": "T1550.002",
    "golden ticket": "T1558.001",
    "powershell": "T1059.001",
    "beacon": "T1071",
    "ransomware": "T1486",
    "phishing": "T1566",
    "brute force": "T1110",
    "lateral movement": "T1021",
    "credential dump": "T1003",
}


class AttackMapper(BaseAgent):
    agent_id = "attack-mapper"
    domain = "intel"

    async def handle(self, message: AgentMessage) -> AgentMessage:
        text = (message.payload.get("text") or "").lower()
        techniques = sorted({tech for kw, tech in KEYWORD_MAP.items() if kw in text})
        conf = self.compute_confidence(
            source_quality=0.8 if techniques else 0.3,
            corroboration=len(techniques),
            freshness_hours=0,
            false_positive_rate=0.2,
        )
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload={"techniques": techniques, "mapped_from": message.payload.get("text", "")},
            confidence=conf,
            mitre_techniques=techniques,
            correlation_id=message.correlation_id,
        )
