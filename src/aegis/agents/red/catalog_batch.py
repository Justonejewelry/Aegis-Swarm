"""Red team authorized validation catalog agents."""
from __future__ import annotations

from aegis.core.compact_agent import AnalyticAgent, ResultAgent
from aegis.core.models import AgentMessage, Severity


class AttackSurfaceDiscovery(AnalyticAgent):
    agent_id = "attack-surface-discovery"
    domain = "red"
    payload_key = "assets"
    default_category = "exposure"
    default_techniques = ["T1595"]

    def rules(self, events: list, message: AgentMessage) -> list:
        return [
            self.finding(
                message,
                title=f"Exposed asset: {e.get('host', e.get('name', 'asset'))}",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
                assets=[str(e.get("host", e.get("name", "")))],
                remediation=["Confirm authorization", "Reduce exposure", "Monitor"],
            )
            for e in events[:25]
            if isinstance(e, dict)
        ]


class ExternalExposureAssessment(AnalyticAgent):
    agent_id = "external-exposure-assessment"
    domain = "red"
    payload_key = "endpoints"
    default_category = "exposure"
    default_techniques = ["T1595"]

    def rules(self, events: list, message: AgentMessage) -> list:
        return [
            self.finding(
                message,
                title=f"External service: {e.get('url', e.get('port', 'endpoint'))}",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
            )
            for e in events[:20]
            if isinstance(e, dict)
        ]


class IdentityExposureAssessment(AnalyticAgent):
    agent_id = "identity-exposure-assessment"
    domain = "red"
    payload_key = "identities"
    default_category = "identity"
    default_techniques = ["T1078"]

    def rules(self, events: list, message: AgentMessage) -> list:
        return [
            self.finding(
                message,
                title=f"Identity exposure: {e.get('user', e.get('name', 'identity'))}",
                description=str(e)[:400],
                severity=Severity.HIGH,
                techniques=["T1078", "T1110"],
            )
            for e in events[:20]
            if isinstance(e, dict)
        ]


class ActiveDirectoryAssessment(AnalyticAgent):
    agent_id = "active-directory-assessment"
    domain = "red"
    payload_key = "findings"
    default_category = "identity"
    default_techniques = ["T1484"]

    def rules(self, events: list, message: AgentMessage) -> list:
        return [
            self.finding(
                message,
                title=f"AD assessment: {e.get('title', e.get('check', 'finding'))}",
                description=str(e)[:400],
                severity=Severity.HIGH,
                techniques=["T1484", "T1078"],
            )
            for e in events[:20]
            if isinstance(e, dict)
        ]


class CloudConfigurationAssessment(AnalyticAgent):
    agent_id = "cloud-configuration-assessment"
    domain = "red"
    payload_key = "findings"
    default_category = "cloud"
    default_techniques = ["T1078"]

    def rules(self, events: list, message: AgentMessage) -> list:
        return [
            self.finding(
                message,
                title=f"Cloud config: {e.get('title', e.get('control', 'check'))}",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
            )
            for e in events[:25]
            if isinstance(e, dict)
        ]


class ContainerSecurityAssessment(AnalyticAgent):
    agent_id = "container-security-assessment"
    domain = "red"
    payload_key = "findings"
    default_category = "container"
    default_techniques = ["T1610"]

    def rules(self, events: list, message: AgentMessage) -> list:
        return [
            self.finding(
                message,
                title=f"Container: {e.get('title', e.get('image', 'issue'))}",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
            )
            for e in events[:20]
            if isinstance(e, dict)
        ]


class KubernetesAssessment(AnalyticAgent):
    agent_id = "kubernetes-assessment"
    domain = "red"
    payload_key = "findings"
    default_category = "kubernetes"
    default_techniques = ["T1610"]

    def rules(self, events: list, message: AgentMessage) -> list:
        return [
            self.finding(
                message,
                title=f"K8s: {e.get('title', e.get('resource', 'finding'))}",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
            )
            for e in events[:20]
            if isinstance(e, dict)
        ]


class WebApplicationAssessment(AnalyticAgent):
    agent_id = "web-application-assessment"
    domain = "red"
    payload_key = "findings"
    default_category = "web"
    default_techniques = ["T1190"]

    def rules(self, events: list, message: AgentMessage) -> list:
        return [
            self.finding(
                message,
                title=f"Web app: {e.get('title', e.get('vuln', 'finding'))}",
                description=str(e)[:400],
                severity=Severity.HIGH,
                techniques=["T1190"],
            )
            for e in events[:20]
            if isinstance(e, dict)
        ]


class WirelessAssessment(AnalyticAgent):
    agent_id = "wireless-assessment"
    domain = "red"
    payload_key = "networks"
    default_category = "wireless"
    default_techniques = ["T1557"]

    def rules(self, events: list, message: AgentMessage) -> list:
        return [
            self.finding(
                message,
                title=f"Wireless: {e.get('ssid', e.get('name', 'network'))}",
                description=str(e)[:400],
                severity=Severity.MEDIUM,
            )
            for e in events[:15]
            if isinstance(e, dict)
        ]


class SecurityControlValidation(ResultAgent):
    agent_id = "security-control-validation"
    domain = "red"

    async def compute(self, message: AgentMessage) -> dict:
        controls = message.payload.get("controls") or []
        return {
            "validated": len(controls) if isinstance(controls, list) else 0,
            "mode": "authorized_validation_only",
            "_confidence": 0.8,
            "_techniques": ["T1562"],
        }
