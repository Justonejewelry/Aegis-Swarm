"""Storage layer unit tests (no live DB required)."""
from __future__ import annotations

from uuid import uuid4

from aegis.core.models import (
    Engagement,
    EngagementMode,
    EngagementStatus,
    Finding,
    Scope,
    Severity,
)
from aegis.storage.models import AuditLogRow, EngagementRow, FindingRow
from aegis.storage.repositories import (
    AuditRepository,
    EngagementRepository,
    FindingRepository,
)


def test_imports():
    assert EngagementRow is not None
    assert FindingRow is not None
    assert AuditLogRow is not None


def test_to_engagement_roundtrip():
    eng = Engagement(
        engagement_id=uuid4(),
        name="test-eng",
        mode=EngagementMode.ASSESS,
        scope=Scope(in_scope_cidrs=["10.0.0.0/8"]),
        status=EngagementStatus.ACTIVE,
        approver="soc-lead",
    )
    row = EngagementRow(
        engagement_id=eng.engagement_id,
        name=eng.name,
        mode=eng.mode.value,
        status=eng.status.value,
        scope=eng.scope.model_dump(),
        approver=eng.approver,
        start_at=None,
        end_at=None,
        created_at=eng.created_at,
    )
    hydrated = EngagementRepository.to_engagement(row)
    assert hydrated.engagement_id == eng.engagement_id
    assert hydrated.name == "test-eng"
    assert hydrated.mode == EngagementMode.ASSESS
    assert hydrated.status == EngagementStatus.ACTIVE
    assert hydrated.approver == "soc-lead"
    assert "10.0.0.0/8" in hydrated.scope.in_scope_cidrs


def test_to_finding_roundtrip():
    fid = uuid4()
    eid = uuid4()
    finding = Finding(
        finding_id=fid,
        engagement_id=eid,
        title="Suspicious login",
        description="MFA bypass attempt",
        severity=Severity.HIGH,
        category="authentication",
        confidence=0.9,
        risk_score=72.5,
        mitre_techniques=["T1078"],
        sources=["auth-analyst"],
        remediation=["Enforce MFA"],
    )
    row = FindingRow(
        finding_id=finding.finding_id,
        engagement_id=finding.engagement_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        category=finding.category,
        confidence=finding.confidence,
        risk_score=finding.risk_score,
        mitre_techniques=finding.mitre_techniques,
        cves=[],
        assets=[],
        sources=finding.sources,
        remediation=finding.remediation,
        evidence_refs=[],
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )
    hydrated = FindingRepository.to_finding(row)
    assert hydrated.finding_id == fid
    assert hydrated.severity == Severity.HIGH
    assert hydrated.risk_score == 72.5
    assert "T1078" in hydrated.mitre_techniques


def test_repo_method_surface():
    assert hasattr(EngagementRepository, "create")
    assert hasattr(EngagementRepository, "get")
    assert hasattr(EngagementRepository, "upsert")
    assert hasattr(EngagementRepository, "update_status")
    assert hasattr(EngagementRepository, "to_engagement")
    assert hasattr(FindingRepository, "create")
    assert hasattr(FindingRepository, "list_for_engagement")
    assert hasattr(AuditRepository, "log")
    assert hasattr(AuditRepository, "record")
