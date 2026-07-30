"""Repository helpers for durable AEGIS state."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.core.models import Engagement, Finding, Severity
from aegis.storage.models import (
    AgentRegistryRow,
    AuditLogRow,
    EngagementRow,
    FindingRow,
)


class EngagementRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, eng: Engagement) -> EngagementRow:
        row = EngagementRow(
            engagement_id=eng.engagement_id,
            name=eng.name,
            mode=eng.mode.value if hasattr(eng.mode, "value") else str(eng.mode),
            status=eng.status.value if hasattr(eng.status, "value") else str(eng.status),
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

    async def update_status(self, engagement_id: UUID | str, status: str) -> None:
        eid = UUID(str(engagement_id))
        await self.session.execute(
            update(EngagementRow)
            .where(EngagementRow.engagement_id == eid)
            .values(status=status)
        )

    async def list_recent(self, limit: int = 50) -> list[EngagementRow]:
        result = await self.session.execute(
            select(EngagementRow).order_by(EngagementRow.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, finding: Finding) -> FindingRow:
        row = FindingRow(
            finding_id=finding.finding_id,
            engagement_id=finding.engagement_id,
            title=finding.title,
            description=finding.description or "",
            severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            category=finding.category,
            confidence=finding.confidence,
            risk_score=finding.risk_score,
            mitre_techniques=list(finding.mitre_techniques or []),
            cves=list(finding.cves or []),
            assets=list(finding.assets or []),
            sources=list(finding.sources or []),
            remediation=list(finding.remediation or []),
            evidence_refs=list(finding.evidence_refs or []),
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
        row = AuditLogRow(
            engagement_id=UUID(str(engagement_id)) if engagement_id else None,
            agent_id=agent_id,
            event=event,
            details=details or {},
        )
        self.session.add(row)
        await self.session.flush()
        return row


class AgentRegistryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert(
        self, agent_id: str, domain: str, version: str = "0.1.0", meta: dict | None = None
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
                status="registered",
                last_heartbeat=now,
                meta=meta or {},
            )
            self.session.add(row)
        else:
            row.version = version
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
