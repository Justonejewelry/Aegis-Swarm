"""MITRE ATT&CK coverage matrix from findings and agent catalog."""
from __future__ import annotations

import csv
import io
from collections import defaultdict
from typing import Any

TECHNIQUE_CATALOG: dict[str, dict[str, str]] = {
    "T1566": {"name": "Phishing", "tactic": "initial-access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "initial-access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "initial-access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "T1133": {"name": "External Remote Services", "tactic": "initial-access"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial-access"},
    "T1078.004": {"name": "Cloud Accounts", "tactic": "initial-access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "execution"},
    "T1059.006": {"name": "Python", "tactic": "execution"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "execution"},
    "T1204": {"name": "User Execution", "tactic": "execution"},
    "T1204.002": {"name": "Malicious File", "tactic": "execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "persistence"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "persistence"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "persistence"},
    "T1136": {"name": "Create Account", "tactic": "persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "persistence"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege-escalation"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege-escalation"},
    "T1548.002": {"name": "Bypass User Account Control", "tactic": "privilege-escalation"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
    "T1027.010": {"name": "Command Obfuscation", "tactic": "defense-evasion"},
    "T1036": {"name": "Masquerading", "tactic": "defense-evasion"},
    "T1070": {"name": "Indicator Removal", "tactic": "defense-evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "defense-evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "defense-evasion"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "defense-evasion"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "defense-evasion"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "credential-access"},
    "T1003.003": {"name": "NTDS", "tactic": "credential-access"},
    "T1110": {"name": "Brute Force", "tactic": "credential-access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "credential-access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "credential-access"},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "credential-access"},
    "T1558.003": {"name": "Kerberoasting", "tactic": "credential-access"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "credential-access"},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "discovery"},
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery"},
    "T1087": {"name": "Account Discovery", "tactic": "discovery"},
    "T1069": {"name": "Permission Groups Discovery", "tactic": "discovery"},
    "T1482": {"name": "Domain Trust Discovery", "tactic": "discovery"},
    "T1021": {"name": "Remote Services", "tactic": "lateral-movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "lateral-movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "lateral-movement"},
    "T1021.004": {"name": "SSH", "tactic": "lateral-movement"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "lateral-movement"},
    "T1550.002": {"name": "Pass the Hash", "tactic": "lateral-movement"},
    "T1550.003": {"name": "Pass the Ticket", "tactic": "lateral-movement"},
    "T1074": {"name": "Data Staged", "tactic": "collection"},
    "T1005": {"name": "Data from Local System", "tactic": "collection"},
    "T1114": {"name": "Email Collection", "tactic": "collection"},
    "T1113": {"name": "Screen Capture", "tactic": "collection"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "command-and-control"},
    "T1071.004": {"name": "DNS", "tactic": "command-and-control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "command-and-control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "command-and-control"},
    "T1090": {"name": "Proxy", "tactic": "command-and-control"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
    "T1489": {"name": "Service Stop", "tactic": "impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact"},
    "T1498": {"name": "Network Denial of Service", "tactic": "impact"},
}

AGENT_TECHNIQUE_COVERAGE: dict[str, list[str]] = {
    "authentication-analyst": ["T1110", "T1110.001", "T1110.003", "T1078", "T1078.004"],
    "siem-correlator": ["T1078", "T1059", "T1071", "T1566", "T1027"],
    "threat-hunter": ["T1047", "T1059", "T1059.001", "T1027", "T1003", "T1003.001"],
    "network-traffic-analyst": ["T1071", "T1071.001", "T1071.004", "T1048", "T1046", "T1090"],
    "ioc-correlator": ["T1071", "T1105", "T1573"],
    "attack-mapper": list(TECHNIQUE_CATALOG.keys()),
    "cve-intelligence": ["T1190", "T1068"],
    "detection-validator": ["T1110", "T1021.002", "T1059.001", "T1071.004"],
    "endpoint-telemetry-analyst": ["T1059", "T1059.001", "T1027", "T1218", "T1547.001"],
    "root-cause-analyst": ["T1190", "T1566", "T1566.001", "T1078"],
    "ids-analyst": ["T1046", "T1071", "T1498"],
    "firewall-analyst": ["T1048", "T1071", "T1090"],
    "ueba-analyst": ["T1078", "T1087", "T1021"],
    "identity-exposure-assessment": ["T1078", "T1558", "T1558.003", "T1552"],
    "artifact-collector": ["T1005", "T1074", "T1083"],
    "timeline-builder": ["T1070", "T1070.001", "T1082"],
    "privilege-graph-analyst": ["T1069", "T1482", "T1087"],
    "attack-path-modeler": ["T1021", "T1021.002", "T1550.002", "T1078"],
}


def techniques_from_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        techs = f.get("mitre_techniques") or f.get("mitre") or f.get("techniques") or []
        for t in techs:
            tid = str(t).upper().strip()
            if not tid:
                continue
            counts[tid] += 1
            if "." in tid:
                counts[tid.split(".", 1)[0]] += 1
    return dict(counts)


def build_coverage_matrix(
    findings: list[dict[str, Any]] | None = None,
    active_agents: list[str] | None = None,
) -> dict[str, Any]:
    observed = techniques_from_findings(findings or [])
    agents = set(active_agents or AGENT_TECHNIQUE_COVERAGE.keys())
    planned: dict[str, set[str]] = defaultdict(set)
    for agent_id, techs in AGENT_TECHNIQUE_COVERAGE.items():
        if agent_id in agents or not active_agents:
            for t in techs:
                planned[t].add(agent_id)
    rows = []
    covered = 0
    by_tactic: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "covered": 0, "observed": 0})
    for tid, meta in sorted(TECHNIQUE_CATALOG.items()):
        obs = observed.get(tid, 0)
        agent_list = sorted(planned.get(tid, set()))
        status = "observed" if obs else ("planned" if agent_list else "gap")
        if status != "gap":
            covered += 1
        tactic = meta["tactic"]
        by_tactic[tactic]["total"] += 1
        if status != "gap":
            by_tactic[tactic]["covered"] += 1
        if obs:
            by_tactic[tactic]["observed"] += 1
        rows.append({
            "technique_id": tid,
            "name": meta["name"],
            "tactic": tactic,
            "observed_count": obs,
            "covering_agents": agent_list,
            "status": status,
        })
    total = len(TECHNIQUE_CATALOG)
    return {
        "total_techniques": total,
        "covered": covered,
        "gaps": total - covered,
        "coverage_pct": round(100.0 * covered / total, 1) if total else 0.0,
        "observed_unique": len([k for k, v in observed.items() if v > 0]),
        "by_tactic": dict(by_tactic),
        "matrix": rows,
        "findings_hydrated": len(findings or []),
    }


def matrix_to_csv(matrix: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["technique_id", "name", "tactic", "status", "observed_count", "covering_agents"])
    writer.writeheader()
    for row in matrix.get("matrix", []):
        writer.writerow({
            "technique_id": row["technique_id"],
            "name": row["name"],
            "tactic": row["tactic"],
            "status": row["status"],
            "observed_count": row["observed_count"],
            "covering_agents": "|".join(row.get("covering_agents") or []),
        })
    return buf.getvalue()
