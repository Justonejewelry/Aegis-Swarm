"""Purple-team detection validation fixture harness."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ValidationFixture:
    fixture_id: str
    technique: str
    description: str
    expected_rule_ids: list[str]
    sample_event: dict[str, Any]
    severity: str = "medium"


@dataclass
class ValidationResult:
    fixture_id: str
    technique: str
    passed: bool
    matched_rules: list[str]
    missing_rules: list[str]
    notes: str = ""


@dataclass
class ValidationReport:
    total: int = 0
    passed: int = 0
    failed: int = 0
    coverage_pct: float = 0.0
    results: list[ValidationResult] = field(default_factory=list)
    by_technique: dict[str, bool] = field(default_factory=dict)


DEFAULT_FIXTURES: list[ValidationFixture] = [
    ValidationFixture("auth-bruteforce-1", "T1110", "Repeated failed logons", ["auth_bruteforce", "siem_failed_logon_spike"], {"message": "Failed password"}, "high"),
    ValidationFixture("lateral-smb-1", "T1021.002", "SMB lateral movement", ["lateral_smb", "network_east_west_anomaly"], {"proto": "smb", "dst_port": 445}, "high"),
    ValidationFixture("ps-encoded-1", "T1059.001", "Encoded PowerShell", ["proc_powershell_encoded", "endpoint_suspicious_cli"], {"process": "powershell.exe"}, "medium"),
    ValidationFixture("dns-tunnel-1", "T1071.004", "High-entropy DNS", ["dns_tunneling", "dns_high_entropy"], {"qtype": "TXT"}, "medium"),
]


class DetectionValidationHarness:
    def __init__(self, fixtures: list[ValidationFixture] | None = None) -> None:
        self.fixtures = fixtures or list(DEFAULT_FIXTURES)

    def run(self, active_rule_ids: list[str] | set[str]) -> ValidationReport:
        active = set(active_rule_ids)
        report = ValidationReport()
        for fx in self.fixtures:
            matched = [r for r in fx.expected_rule_ids if r in active]
            missing = [r for r in fx.expected_rule_ids if r not in active]
            passed = len(missing) == 0
            report.results.append(ValidationResult(fx.fixture_id, fx.technique, passed, matched, missing, fx.description))
            report.by_technique[fx.technique] = report.by_technique.get(fx.technique, False) or passed
            report.total += 1
            report.passed += int(passed)
            report.failed += int(not passed)
        report.coverage_pct = (100.0 * report.passed / report.total) if report.total else 0.0
        return report
