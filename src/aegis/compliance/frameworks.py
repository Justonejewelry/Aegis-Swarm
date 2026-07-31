"""Compliance framework mapping packs (NIST CSF / CIS Controls)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ControlMapping:
    framework: str
    control_id: str
    title: str
    aegis_domains: tuple[str, ...]
    example_agents: tuple[str, ...]
    attack_techniques: tuple[str, ...] = ()


NIST_CSF: list[ControlMapping] = [
    ControlMapping("NIST-CSF", "ID.AM", "Asset Management", ("command", "red"), ("attack-surface-discovery", "knowledge-manager")),
    ControlMapping("NIST-CSF", "ID.RA", "Risk Assessment", ("reporting", "blue"), ("risk-prioritization", "risk-analyst"), ("T1486",)),
    ControlMapping("NIST-CSF", "PR.AC", "Identity Management / Access", ("blue", "red"), ("authentication-analyst", "identity-exposure-assessment"), ("T1078", "T1110")),
    ControlMapping("NIST-CSF", "DE.CM", "Security Continuous Monitoring", ("blue", "intel"), ("siem-correlator", "threat-hunter", "ioc-correlator"), ("T1059", "T1071")),
    ControlMapping("NIST-CSF", "RS.AN", "Analysis", ("dfir", "intel"), ("timeline-builder", "root-cause-analyst", "attack-mapper")),
    ControlMapping("NIST-CSF", "RS.MI", "Mitigation", ("reporting", "purple"), ("recommendation-engine", "security-gap-analyst")),
]

CIS_CONTROLS: list[ControlMapping] = [
    ControlMapping("CIS", "CIS-1", "Inventory of Enterprise Assets", ("red", "command"), ("attack-surface-discovery",)),
    ControlMapping("CIS", "CIS-5", "Account Management", ("blue",), ("authentication-analyst", "entra-id-analyst"), ("T1078",)),
    ControlMapping("CIS", "CIS-8", "Audit Log Management", ("blue", "dfir"), ("siem-correlator", "timeline-builder")),
    ControlMapping("CIS", "CIS-13", "Network Monitoring", ("blue",), ("network-traffic-analyst", "ids-analyst"), ("T1048",)),
    ControlMapping("CIS", "CIS-18", "Penetration Testing", ("purple", "red"), ("adversary-emulation-planner", "control-validation-agent")),
]


def all_mappings() -> list[ControlMapping]:
    return list(NIST_CSF) + list(CIS_CONTROLS)


def map_findings_to_controls(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tech_to_controls: dict[str, list[ControlMapping]] = {}
    for m in all_mappings():
        for t in m.attack_techniques:
            tech_to_controls.setdefault(t, []).append(m)
    out = []
    for f in findings:
        techniques = f.get("mitre_techniques") or f.get("mitre") or []
        controls = []
        for t in techniques:
            for m in tech_to_controls.get(t, []):
                controls.append({"framework": m.framework, "control_id": m.control_id, "title": m.title})
        out.append({"finding": f.get("title") or f.get("finding_id"), "controls": controls})
    return out


def coverage_matrix() -> list[dict[str, Any]]:
    return [
        {
            "framework": m.framework,
            "control_id": m.control_id,
            "title": m.title,
            "domains": list(m.aegis_domains),
            "agents": list(m.example_agents),
            "techniques": list(m.attack_techniques),
        }
        for m in all_mappings()
    ]
