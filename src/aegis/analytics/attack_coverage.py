"""MITRE ATT&CK coverage matrix from findings and agent catalog."""
from __future__ import annotations

import csv
import io
from collections import defaultdict
from typing import Any

TECHNIQUE_CATALOG: dict[str, dict[str, str]] = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution"},
    "T1078": {"name": "Valid Accounts", "tactic": "defense-evasion"},
    "T1110": {"name": "Brute Force", "tactic": "credential-access"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "lateral-movement"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control"},
    "T1071.004": {"name": "DNS", "tactic": "command-and-control"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "execution"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
    "T1550.002": {"name": "Pass the Hash", "tactic": "lateral-movement"},
    "T1074": {"name": "Data Staged", "tactic": "collection"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
    "T1036": {"name": "Masquerading", "tactic": "defense-evasion"},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "discovery"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "command-and-control"},
    "T1566": {"name": "Phishing", "tactic": "initial-access"},
}

AGENT_TECHNIQUE_COVERAGE: dict[str, list[str]] = {
    "authentication-analyst": ["T1110", "T1078"],
    "siem-correlator": ["T1078", "T1059", "T1071"],
    "threat-hunter": ["T1047", "T1059", "T1027"],
    "network-traffic-analyst": ["T1071", "T1048", "T1071.004"],
    "ioc-correlator": ["T1071", "T1105"],
    "attack-mapper": list(TECHNIQUE_CATALOG.keys()),
    "cve-intelligence": ["T1190"],
    "detection-validator": ["T1110", "T1021.002", "T1059.001", "T1071.004"],
    "endpoint-telemetry-analyst": ["T1059", "T1059.001", "T1027"],
    "root-cause-analyst": ["T1190", "T1566", "T1078"],
}


def techniques_from_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        techs = f.get("mitre_techniques") or f.get("mitre") or f.get("techniques") or []
        for t in techs:
            tid = str(t).upper().strip()
            if tid:
                counts[tid] += 1
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
    for tid, meta in sorted(TECHNIQUE_CATALOG.items()):
        obs = observed.get(tid, 0)
        agent_list = sorted(planned.get(tid, set()))
        status = "observed" if obs else ("planned" if agent_list else "gap")
        if status != "gap":
            covered += 1
        rows.append({
            "technique_id": tid,
            "name": meta["name"],
            "tactic": meta["tactic"],
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
        "observed_unique": len(observed),
        "matrix": rows,
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
