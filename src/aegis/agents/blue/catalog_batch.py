"""Blue Team catalog agents (batch expansion)."""
from __future__ import annotations

from aegis.core.compact_agent import AnalyticAgent, ResultAgent
from aegis.core.models import AgentMessage, Finding, Severity


class DetectionEngineer(AnalyticAgent):
    agent_id = "detection-engineer"
    domain = "blue"
    payload_key = "rules"
    default_category = "detection"
    default_techniques = ["T1562"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        out = []
        for r in events[:20]:
            if not isinstance(r, dict):
                continue
            gap = r.get("gap") or r.get("missing_coverage")
            if gap:
                out.append(
                    self.finding(
                        message,
                        title=f"Detection gap: {r.get('name', r.get('id', 'rule'))}",
                        description=str(gap),
                        severity=Severity.MEDIUM,
                        techniques=["T1562", "T1070"],
                        remediation=["Author detection", "Validate in purple mode"],
                    )
                )
        return out


class EndpointTelemetryAnalyst(AnalyticAgent):
    agent_id = "endpoint-telemetry-analyst"
    domain = "blue"
    payload_key = "events"
    default_category = "endpoint"
    default_techniques = ["T1059"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        out = []
        for e in events[:30]:
            if not isinstance(e, dict):
                continue
            if e.get("suspicious") or e.get("severity") in ("high", "critical"):
                out.append(
                    self.finding(
                        message,
                        title=f"Endpoint signal: {e.get('process', e.get('name', 'host'))}",
                        description=str(e.get("description") or e)[:400],
                        severity=Severity.HIGH if e.get("severity") == "critical" else Severity.MEDIUM,
                        assets=[str(e.get("host", e.get("asset", "")))],
                        techniques=list(e.get("mitre") or ["T1059"]),
                    )
                )
        return out


class EmailSecurityAnalyst(AnalyticAgent):
    agent_id = "email-security-analyst"
    domain = "blue"
    payload_key = "messages"
    default_category = "email"
    default_techniques = ["T1566"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        out = []
        for m in events[:20]:
            if not isinstance(m, dict):
                continue
            if m.get("phish") or m.get("malware") or m.get("suspicious"):
                out.append(
                    self.finding(
                        message,
                        title="Suspicious email activity",
                        description=str(m)[:400],
                        severity=Severity.HIGH,
                        techniques=["T1566", "T1598"],
                    )
                )
        return out


class CloudSecurityAnalyst(AnalyticAgent):
    agent_id = "cloud-security-analyst"
    domain = "blue"
    payload_key = "findings"
    default_category = "cloud"
    default_techniques = ["T1078"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        out = []
        for f in events[:25]:
            if not isinstance(f, dict):
                continue
            out.append(
                self.finding(
                    message,
                    title=f"Cloud issue: {f.get('title', f.get('check', 'config'))}",
                    description=str(f.get("description") or f)[:400],
                    severity=Severity.MEDIUM,
                    techniques=list(f.get("mitre") or ["T1078"]),
                    assets=[str(f.get("resource", ""))],
                )
            )
        return out


class ActiveDirectoryAnalyst(AnalyticAgent):
    agent_id = "active-directory-analyst"
    domain = "blue"
    payload_key = "events"
    default_category = "identity"
    default_techniques = ["T1078"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        out = []
        for e in events[:25]:
            if not isinstance(e, dict):
                continue
            if e.get("anomaly") or e.get("privilege") or e.get("suspicious"):
                out.append(
                    self.finding(
                        message,
                        title=f"AD signal: {e.get('event', e.get('name', 'ad'))}",
                        description=str(e)[:400],
                        severity=Severity.HIGH,
                        techniques=["T1078", "T1484"],
                    )
                )
        return out


class EntraIDAnalyst(AnalyticAgent):
    agent_id = "entra-id-analyst"
    domain = "blue"
    payload_key = "events"
    default_category = "identity"
    default_techniques = ["T1078"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        return [
            self.finding(
                message,
                title=f"Entra ID: {e.get('event', 'sign-in anomaly')}",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
                techniques=["T1078", "T1556"],
            )
            for e in events[:20]
            if isinstance(e, dict) and (e.get("risk") or e.get("anomaly") or e.get("suspicious"))
        ]


class DNSAnalyst(AnalyticAgent):
    agent_id = "dns-analyst"
    domain = "blue"
    payload_key = "queries"
    default_category = "network"
    default_techniques = ["T1071"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        out = []
        for q in events[:30]:
            if not isinstance(q, dict):
                continue
            if q.get("dga") or q.get("malicious") or q.get("suspicious"):
                out.append(
                    self.finding(
                        message,
                        title=f"DNS: {q.get('query', q.get('domain', 'name'))}",
                        description=str(q)[:400],
                        severity=Severity.HIGH,
                        techniques=["T1071", "T1568"],
                    )
                )
        return out


class DHCPAnalyst(AnalyticAgent):
    agent_id = "dhcp-analyst"
    domain = "blue"
    payload_key = "events"
    default_category = "network"
    default_techniques = ["T1557"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        return [
            self.finding(
                message,
                title="DHCP anomaly",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
            )
            for e in events[:15]
            if isinstance(e, dict) and (e.get("rogue") or e.get("anomaly"))
        ]


class VPNAnalyst(AnalyticAgent):
    agent_id = "vpn-analyst"
    domain = "blue"
    payload_key = "sessions"
    default_category = "network"
    default_techniques = ["T1133"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        return [
            self.finding(
                message,
                title=f"VPN: {e.get('user', e.get('session', 'session'))}",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
                techniques=["T1133"],
            )
            for e in events[:20]
            if isinstance(e, dict) and (e.get("anomaly") or e.get("geo_impossible") or e.get("suspicious"))
        ]


class FirewallAnalyst(AnalyticAgent):
    agent_id = "firewall-analyst"
    domain = "blue"
    payload_key = "events"
    default_category = "network"
    default_techniques = ["T1048"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        return [
            self.finding(
                message,
                title="Firewall allow/deny pattern of interest",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
            )
            for e in events[:25]
            if isinstance(e, dict) and (e.get("blocked") is False or e.get("suspicious"))
        ]


class IDSAnalyst(AnalyticAgent):
    agent_id = "ids-analyst"
    domain = "blue"
    payload_key = "alerts"
    default_category = "network"
    default_techniques = ["T1071"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        return [
            self.finding(
                message,
                title=f"IDS: {e.get('signature', e.get('name', 'alert'))}",
                description=str(e)[:400],
                severity=Severity.HIGH,
            )
            for e in events[:25]
            if isinstance(e, dict)
        ]


class UEBAAnalyst(AnalyticAgent):
    agent_id = "ueba-analyst"
    domain = "blue"
    payload_key = "anomalies"
    default_category = "identity"
    default_techniques = ["T1078"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        return [
            self.finding(
                message,
                title=f"UEBA: {e.get('user', e.get('entity', 'entity'))}",
                description=str(e)[:400],
                severity=Severity.HIGH,
                confidence=0.65,
            )
            for e in events[:20]
            if isinstance(e, dict)
        ]


class InsiderThreatAnalyst(AnalyticAgent):
    agent_id = "insider-threat-analyst"
    domain = "blue"
    payload_key = "events"
    default_category = "insider"
    default_techniques = ["T1078"]

    def rules(self, events: list, message: AgentMessage) -> list[Finding]:
        return [
            self.finding(
                message,
                title="Insider risk indicator",
                description=str(e)[:400],
                severity=Severity.HIGH,
                techniques=["T1078", "T1530"],
            )
            for e in events[:15]
            if isinstance(e, dict) and (e.get("risk") or e.get("exfil") or e.get("suspicious"))
        ]


class RiskAnalyst(ResultAgent):
    agent_id = "risk-analyst"
    domain = "blue"

    async def compute(self, message: AgentMessage) -> dict:
        findings = message.payload.get("findings") or []
        return {
            "risk_summary": {"input_findings": len(findings) if isinstance(findings, list) else 0},
            "_confidence": 0.7,
            "_techniques": ["T1205"],
        }


class SOCCoordinator(ResultAgent):
    agent_id = "soc-coordinator"
    domain = "blue"

    async def compute(self, message: AgentMessage) -> dict:
        return {"coordination": "queued", "payload_keys": list(message.payload.keys()), "_confidence": 0.8}


class IncidentCommander(ResultAgent):
    agent_id = "incident-commander"
    domain = "blue"

    async def compute(self, message: AgentMessage) -> dict:
        return {
            "incident_status": message.payload.get("status", "assessing"),
            "next_actions": message.payload.get("actions", ["contain", "collect", "eradicate"]),
            "_confidence": 0.75,
        }
