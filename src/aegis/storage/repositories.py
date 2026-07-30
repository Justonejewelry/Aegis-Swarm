"""Repository helpers for durable AEGIS state (engagements, findings, audit)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.models import (
    Engagement,
    EngagementMode,
    EngagementStatus,
    Finding,
    Scope,
    Severity,
)
from aegis.storage.models import (
    AgentRegistryRow,
    AuditLogRow,
    EngagementRow,
    FindingRow,
)


def _enum_val(v: Any) -> str:
    return v.value if hasattr(v, "value") else str(v)


class EngagementRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, eng: Engagement) -> EngagementRow:
        row = EngagementRow(
            engagement_id=eng.engagement_id,
            name=eng.name,
            mode=_enum_val(eng.mode),
            status=_enum_val(eng.status),
            scope=eng.scope.model_dump() if hasattr(eng.scope, "model_dump") else dict(eng.scope),
            approver=getattr(eng, "approver", None),
            start_at=getattr(eng, "start_at", None),
            end_at=getattr(eng, "end_at", None),
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def get(self, engagement_id: UUID | str) -> EngagementRow | None:
        eid = UUID(str(engagement_id))
        result = await self.session.execute(
            select(EngagementRow).where(EngagementRow.engagement_id == eid)
        )
        return result.scalar_one_or_none()

    async def update_status(
        self,
        engagement_id: UUID | str,
        status: str,
        *,
        approver: str | None = None,
    ) -> None:
        eid = UUID(str(engagement_id))
        values: dict[str, Any] = {"status": status}
        if approver is not None:
            values["approver"] = approver
        await self.session.execute(
            update(EngagementRow).where(EngagementRow.engagement_id == eid).values(**values)
        )

    async def upsert(self, eng: Engagement) -> EngagementRow:
        existing = await self.get(eng.engagement_id)
        if existing is None:
            return await self.create(eng)
        existing.name = eng.name
        existing.mode = _enum_val(eng.mode)
        existing.status = _enum_val(eng.status)
        existing.scope = eng.scope.model_dump() if hasattr(eng.scope, "model_dump") else dict(eng.scope)
        existing.approver = getattr(eng, "approver", None)
        existing.start_at = getattr(eng, "start_at", None)
        existing.end_at = getattr(eng, "end_at", None)
        await self.session.flush()
        return existing

    async def list_active(self, limit: int = 50) -> list[EngagementRow]:
        result = await self.session.execute(
            select(EngagementRow)
            .where(EngagementRow.status == EngagementStatus.ACTIVE.value)
            .order_by(EngagementRow.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def list_recent(self, limit: int = 50) -> list[EngagementRow]:
        result = await self.session.execute(
            select(EngagementRow).order_by(EngagementRow.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    @staticmethod
    def to_engagement(row: EngagementRow) -> Engagement:
        try:
            mode = EngagementMode(row.mode)
        except (ValueError, TypeError):
            mode = EngagementMode.ASSESS
        try:
            status = EngagementStatus(row.status)
        except (ValueError, TypeError):
            status = EngagementStatus.DRAFT
        scope_raw = row.scope if isinstance(row.scope, dict) else {}
        try:
            scope = Scope(**scope_raw)
        except Exception:
            scope = Scope()
        return Engagement(
            engagement_id=row.engagement_id,
            name=row.name,
            mode=mode,
            scope=scope,
            status=status,
            approver=row.approver,
            start_at=row.start_at,
            end_at=row.end_at,
            created_at=row.created_at,
        )


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, finding: Finding) -> FindingRow:
        return await self.create_from_model(finding)

    async def create_from_model(self, finding: Finding) -> FindingRow:
        row = FindingRow(
            finding_id=finding.finding_id,
            engagement_id=finding.engagement_id,
            title=finding.title,
            description=finding.description or "",
            severity=_enum_val(finding.severity),
            category=finding.category,
            confidence=finding.confidence,
            risk_score=getattr(finding, "risk_score", 0.0) or 0.0,
            mitre_techniques=list(finding.mitre_techniques or []),
            cves=list(getattr(finding, "cves", None) or []),
            assets=list(getattr(finding, "assets", None) or []),
            sources=list(finding.sources or []),
            remediation=list(getattr(finding, "remediation", None) or []),
            evidence_refs=list(getattr(finding, "evidence_refs", None) or []),
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def list_for_engagement(
        self, engagement_id: UUID | str, limit: int = 200
    ) -> list[FindingRow]:
        eid = UUID(str(engagement_id))
        result = await self.session.execute(
            select(FindingRow)
            .where(FindingRow.engagement_id == eid)
            .order_by(FindingRow.risk_score.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def top_risk(self, limit: int = 25) -> list[FindingRow]:
        result = await self.session.execute(
            select(FindingRow).order_by(FindingRow.risk_score.desc()).limit(limit)
        )
        return list(result.scalars().all())

    @staticmethod
    def to_finding(row: FindingRow) -> Finding:
        try:
            sev = Severity(row.severity)
        except (ValueError, TypeError):
            sev = Severity.INFO
        return Finding(
            finding_id=row.finding_id,
            engagement_id=row.engagement_id,
            title=row.title,
            description=row.description or "",
            severity=sev,
            category=row.category,
            confidence=row.confidence,
            risk_score=row.risk_score or 0.0,
            mitre_techniques=list(row.mitre_techniques or []),
            cves=list(row.cves or []),
            assets=list(row.assets or []),
            sources=list(row.sources or []),
            remediation=list(row.remediation or []),
            evidence_refs=list(row.evidence_refs or []),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def log(
        self,
        engagement_id: UUID | str | None,
        agent_id: str,
        event: str,
        details: dict[str, Any] | None = None,
    ) -> AuditLogRow:
        return await self.record(
            agent_id=agent_id,
            event=event,
            details=details,
            engagement_id=engagement_id,
        )

    async def record(
        self,
        agent_id: str,
        event: str,
        details: dict[str, Any] | None = None,
        engagement_id: UUID | str | None = None,
    ) -> AuditLogRow:
        row = AuditLogRow(
            agent_id=agent_id,
            event=event,
            details=details or {},
            engagement_id=UUID(str(engagement_id)) if engagement_id else None,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def recent(self, limit: int = 100) -> list[AuditLogRow]:
        result = await self.session.execute(
            select(AuditLogRow).order_by(AuditLogRow.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def for_engagement(
        self, engagement_id: UUID | str, limit: int = 100
    ) -> list[AuditLogRow]:
        eid = UUID(str(engagement_id))
        result = await self.session.execute(
            select(AuditLogRow)
            .where(AuditLogRow.engagement_id == eid)
            .order_by(AuditLogRow.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())


class AgentRegistryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert(
        self,
        agent_id: str,
        domain: str,
        version: str = "0.2.1",
        status: str = "registered",
        meta: dict[str, Any] | None = None,
    ) -> AgentRegistryRow:
        result = await self.session.execute(
            select(AgentRegistryRow).where(AgentRegistryRow.agent_id == agent_id)
        )
        row = result.scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if row is None:
            row = AgentRegistryRow(
                agent_id=agent_id,
                domain=domain,
                version=version,
                status=status,
                last_heartbeat=now,
                meta=meta or {},
            )
            self.session.add(row)
        else:
            row.domain = domain
            row.version = version
            row.status = status
            row.last_heartbeat = now
            if meta:
                row.meta = {**(row.meta or {}), **meta}
        await self.session.flush()
        return row

    async def heartbeat(self, agent_id: str) -> None:
        await self.session.execute(
            update(AgentRegistryRow)
            .where(AgentRegistryRow.agent_id == agent_id)
            .values(last_heartbeat=datetime.now(timezone.utc))
        )
