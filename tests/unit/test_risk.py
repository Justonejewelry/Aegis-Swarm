from uuid import uuid4

from aegis.core.models import Finding, Severity
from aegis.core.risk import prioritize, score_finding


def test_score_finding_bounds():
    f = Finding(
        engagement_id=uuid4(),
        title="test",
        severity=Severity.HIGH,
        category="network",
        confidence=0.9,
        sources=["test"],
    )
    score = score_finding(f, asset_criticality=1.0, exploitability=1.0, exposure=1.0, detection_coverage=0.0)
    assert 0 <= score <= 100
    assert score > 50


def test_prioritize_orders_by_risk():
    eng = uuid4()
    a = Finding(engagement_id=eng, title="a", severity=Severity.LOW, category="network", confidence=0.5, sources=["t"], risk_score=10)
    b = Finding(engagement_id=eng, title="b", severity=Severity.CRITICAL, category="network", confidence=0.9, sources=["t"], risk_score=90)
    ordered = prioritize([a, b])
    assert ordered[0].title == "b"
