"""Risk scoring model for AEGIS findings and assets."""
from __future__ import annotations

from aegis.core.models import Finding, Severity

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.05,
}

DEFAULT_ASSET_CRITICALITY = 0.5


def score_finding(
    finding: Finding,
    *,
    asset_criticality: float = DEFAULT_ASSET_CRITICALITY,
    exploitability: float = 0.5,
    exposure: float = 0.5,
    detection_coverage: float = 0.5,
) -> float:
    """
    risk = 100 * severity * asset_criticality * exploitability * exposure * (1 - detection_coverage * 0.5)

    All factors in [0, 1]. Higher detection coverage reduces residual risk.
    """
    sev = SEVERITY_WEIGHT.get(finding.severity, 0.5)
    residual = 1.0 - (max(0.0, min(1.0, detection_coverage)) * 0.5)
    raw = (
        100.0
        * sev
        * max(0.0, min(1.0, asset_criticality))
        * max(0.0, min(1.0, exploitability))
        * max(0.0, min(1.0, exposure))
        * residual
        * max(0.1, finding.confidence)
    )
    return round(max(0.0, min(100.0, raw)), 2)


def prioritize(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.risk_score, reverse=True)
