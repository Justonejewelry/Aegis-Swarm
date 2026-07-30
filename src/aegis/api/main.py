"""AEGIS Swarm FastAPI control plane."""
from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from aegis.analytics.graph_store import get_graph_store
from aegis.core.models import (
    AgentMessage,
    Engagement,
    EngagementMode,
    EngagementStatus,
    Finding,
    MsgType,
    Scope,
)
from aegis.core.orchestrator import Orchestrator
from aegis.core.registry import build_default_agents
from aegis.core.settings import get_settings

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AEGIS Swarm API",
    version="0.2.1",
    description="Autonomous Enterprise Guard & Intelligence System — control plane",
)

orch = Orchestrator()
for agent in build_default_agents():
    orch.register(agent)

_findings_by_eng: dict[UUID, list[Finding]] = {}


class CreateEngagementRequest(BaseModel):
    name: str
    mode: EngagementMode = EngagementMode.ASSESS
    scope: Scope
    approver: str | None = None


class DispatchRequest(BaseModel):
    engagement_id: UUID
    recipient: str
    payload: dict = Field(default_factory=dict)
    msg_type: MsgType = MsgType.TASK
    priority: int = 3


class EnqueueRequest(BaseModel):
    engagement_id: UUID
    recipient: str
    payload: dict = Field(default_factory=dict)
    priority: int = 3


async def _persist_engagement(eng: Engagement) -> None:
    settings = get_settings()
    try:
        from aegis.storage.cache import get_cache

        cache = await get_cache()
        await cache.set_engagement(eng)
    except Exception as e:
        logger.debug("cache set engagement skipped: %s", e)
    if not settings.persist_findings:
        return
    try:
        from aegis.storage.repositories import EngagementRepository
        from aegis.storage.session import get_session

        async with get_session() as session:
            repo = EngagementRepository(session)
            await repo.upsert(eng)
    except Exception as e:
        logger.warning("persist engagement failed (dev OK): %s", e)


async def _load_engagement_from_db(engagement_id: UUID) -> Engagement | None:
    try:
        from aegis.storage.repositories import EngagementRepository
        from aegis.storage.session import get_session

        async with get_session() as session:
            repo = EngagementRepository(session)
            row = await repo.get(engagement_id)
            if row is None:
                return None
            eng = EngagementRepository.to_engagement(row)
            if eng.engagement_id not in orch.engagements:
                try:
                    orch.register_engagement(eng)
                except ValueError:
                    orch.engagements[eng.engagement_id] = eng
            return eng
    except Exception as e:
        logger.debug("load engagement from DB skipped: %s", e)
        return None


async def _load_findings_from_db(engagement_id: UUID) -> list[Finding]:
    if engagement_id in _findings_by_eng and _findings_by_eng[engagement_id]:
        return _findings_by_eng[engagement_id]
    try:
        from aegis.storage.cache import get_cache

        cache = await get_cache()
        cached = await cache.get_findings(engagement_id)
        if cached is not None:
            _findings_by_eng[engagement_id] = cached
            return cached
    except Exception as e:
        logger.debug("cache get findings skipped: %s", e)
    try:
        from aegis.storage.repositories import FindingRepository
        from aegis.storage.session import get_session

        async with get_session() as session:
            repo = FindingRepository(session)
            rows = await repo.list_for_engagement(engagement_id)
            findings = [FindingRepository.to_finding(r) for r in rows]
            if findings:
                _findings_by_eng[engagement_id] = findings
                try:
                    from aegis.storage.cache import get_cache

                    cache = await get_cache()
                    await cache.set_findings(engagement_id, findings)
                except Exception as e:
                    logger.debug("cache set findings skipped: %s", e)
            return findings
    except Exception as e:
        logger.debug("load findings from DB skipped: %s", e)
        return _findings_by_eng.get(engagement_id, [])


async def _persist_findings(engagement_id: UUID, findings: list[Finding]) -> None:
    if not findings:
        return
    settings = get_settings()
    _findings_by_eng.setdefault(engagement_id, []).extend(findings)
    try:
        from aegis.storage.cache import get_cache

        cache = await get_cache()
        await cache.set_findings(engagement_id, _findings_by_eng[engagement_id])
    except Exception as e:
        logger.debug("cache set findings on persist skipped: %s", e)
    if not settings.persist_findings:
        return
    try:
        from aegis.storage.repositories import FindingRepository
        from aegis.storage.session import get_session

        async with get_session() as session:
            repo = FindingRepository(session)
            for f in findings:
                await repo.create(f)
    except Exception as e:
        logger.warning("persist findings failed (dev OK): %s", e)


async def _audit(
    engagement_id: UUID | None, agent_id: str, event: str, details: dict
) -> None:
    settings = get_settings()
    if not settings.persist_audit:
        return
    try:
        from aegis.storage.repositories import AuditRepository
        from aegis.storage.session import get_session

        async with get_session() as session:
            repo = AuditRepository(session)
            await repo.log(engagement_id, agent_id, event, details)
    except Exception as e:
        logger.debug("audit persist skipped: %s", e)


async def _resolve_engagement(engagement_id: UUID) -> Engagement | None:
    """Memory → Redis cache → Postgres hydration."""
    eng = orch.engagements.get(engagement_id)
    if eng is not None:
        return eng
    try:
        from aegis.storage.cache import get_cache

        cache = await get_cache()
        cached = await cache.get_engagement(engagement_id)
        if cached is not None:
            if cached.engagement_id not in orch.engagements:
                try:
                    orch.register_engagement(cached)
                except ValueError:
                    orch.engagements[cached.engagement_id] = cached
            return cached
    except Exception as e:
        logger.debug("cache get engagement skipped: %s", e)
    eng = await _load_engagement_from_db(engagement_id)
    if eng is not None:
        try:
            from aegis.storage.cache import get_cache

            cache = await get_cache()
            await cache.set_engagement(eng)
        except Exception as e:
            logger.debug("cache set after DB load skipped: %s", e)
    return eng


@app.get("/health")
async def health() -> dict:
    settings = get_settings()
    cache_stats: dict = {}
    try:
        from aegis.storage.cache import get_cache

        cache = await get_cache()
        cache_stats = cache.stats()
    except Exception:
        cache_stats = {"backend": "unavailable"}
    return {
        "status": "ok",
        "agents": len(orch.agents),
        "version": "0.2.1",
        "env": settings.env,
        "persist": settings.persist_findings,
        "engagements_in_memory": len(orch.engagements),
        "cache": cache_stats,
    }


@app.get("/agents")
async def list_agents() -> list[dict]:
    return orch.list_agents()


@app.post("/engagements")
async def create_engagement(body: CreateEngagementRequest) -> Engagement:
    eng = Engagement(
        name=body.name,
        mode=body.mode,
        scope=body.scope,
        status=EngagementStatus.DRAFT,
        approver=body.approver,
    )
    orch.register_engagement(eng)
    await _persist_engagement(eng)
    await _audit(eng.engagement_id, "api", "engagement_created", {"name": eng.name})
    return eng


@app.get("/engagements")
async def list_engagements(limit: int = 50) -> list[dict]:
    seen: set[UUID] = set()
    out: list[dict] = []
    for eng in orch.engagements.values():
        seen.add(eng.engagement_id)
        out.append(
            {
                "engagement_id": str(eng.engagement_id),
                "name": eng.name,
                "mode": eng.mode.value,
                "status": eng.status.value,
                "approver": eng.approver,
                "created_at": eng.created_at.isoformat() if eng.created_at else None,
                "source": "memory",
            }
        )
    try:
        from aegis.storage.repositories import EngagementRepository
        from aegis.storage.session import get_session

        async with get_session() as session:
            repo = EngagementRepository(session)
            for row in await repo.list_recent(limit=limit):
                if row.engagement_id in seen:
                    continue
                out.append(
                    {
                        "engagement_id": str(row.engagement_id),
                        "name": row.name,
                        "mode": row.mode,
                        "status": row.status,
                        "approver": row.approver,
                        "created_at": row.created_at.isoformat() if row.created_at else None,
                        "source": "db",
                    }
                )
                seen.add(row.engagement_id)
    except Exception as e:
        logger.debug("list engagements from DB skipped: %s", e)
    return out[:limit]


@app.post("/engagements/{engagement_id}/approve")
async def approve_engagement(engagement_id: UUID, approver: str = "soc-lead") -> dict:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    msg = AgentMessage(
        engagement_id=engagement_id,
        sender="api",
        recipient="mission-controller",
        msg_type=MsgType.CONTROL,
        payload={"action": "approve_engagement", "approver": approver},
    )
    result = await orch.dispatch(msg)
    eng.status = EngagementStatus.ACTIVE
    eng.approver = approver
    await _persist_engagement(eng)
    await _audit(engagement_id, "api", "engagement_approved", {"approver": approver})
    return {"engagement": eng, "control": result}


@app.get("/engagements/{engagement_id}")
async def get_engagement(engagement_id: UUID) -> dict:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    findings = await _load_findings_from_db(engagement_id)
    return {
        "engagement": eng,
        "finding_count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings[:50]],
    }


@app.get("/engagements/{engagement_id}/findings")
async def list_findings(engagement_id: UUID) -> list[dict]:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    findings = await _load_findings_from_db(engagement_id)
    return [f.model_dump(mode="json") for f in findings]


@app.get("/engagements/{engagement_id}/graph")
async def get_graph(engagement_id: UUID) -> dict:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    store = get_graph_store()
    return store.to_dict(engagement_id)


@app.post("/dispatch")
async def dispatch(body: DispatchRequest):
    eng = await _resolve_engagement(body.engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    if eng.status != EngagementStatus.ACTIVE:
        raise HTTPException(403, f"engagement status is {eng.status}; approve first")
    msg = AgentMessage(
        engagement_id=body.engagement_id,
        sender="api",
        recipient=body.recipient,
        msg_type=body.msg_type,
        priority=body.priority,
        payload=body.payload,
    )
    try:
        result = await orch.dispatch(msg)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from e
    except KeyError as e:
        raise HTTPException(404, str(e)) from e

    findings: list[Finding] = []
    if isinstance(result, list) and result and isinstance(result[0], Finding):
        findings = result
        await _persist_findings(body.engagement_id, findings)
    await _audit(
        body.engagement_id, body.recipient, "dispatch", {"msg_type": body.msg_type.value}
    )

    if hasattr(result, "model_dump"):
        data: Any = result.model_dump(mode="json")
    elif isinstance(result, list):
        data = [r.model_dump(mode="json") if hasattr(r, "model_dump") else r for r in result]
    else:
        data = result
    return {"result": data, "findings_persisted": len(findings)}


_bus = None


async def get_bus():
    global _bus
    if _bus is None:
        from aegis.messaging.bus import TaskBus

        _bus = TaskBus()
        await _bus.connect()
    return _bus


@app.post("/tasks")
async def enqueue_task(body: EnqueueRequest):
    eng = await _resolve_engagement(body.engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    if eng.status != EngagementStatus.ACTIVE:
        raise HTTPException(403, f"engagement status is {eng.status}")
    bus = await get_bus()
    task_id = await bus.enqueue(
        {
            "engagement_id": str(body.engagement_id),
            "recipient": body.recipient,
            "payload": body.payload,
            "priority": body.priority,
            "sender": "api",
            "msg_type": "task",
            "mode": eng.mode.value,
            "engagement_name": eng.name,
            "scope": eng.scope.model_dump(),
        }
    )
    return {"task_id": task_id, "queued": True}


@app.get("/engagements/{engagement_id}/report", response_class=HTMLResponse)
async def executive_report_html(engagement_id: UUID) -> str:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    findings = await _load_findings_from_db(engagement_id)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    top = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:8]
    rows = "".join(
        f"<tr><td>{f.severity.value}</td><td>{f.risk_score:.1f}</td><td>{f.title}</td>"
        f"<td>{', '.join(f.mitre_techniques[:3])}</td></tr>"
        for f in top
    )
    return f"""<!DOCTYPE html>
<html><head><title>AEGIS Report — {eng.name}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0f1419; color: #e7e9ea; }}
h1 {{ color: #1d9bf0; }} table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #38444d; padding: 8px; text-align: left; }}
th {{ background: #192734; }} .crit {{ color: #f4212e; }} .high {{ color: #ff7a00; }}
</style></head><body>
<h1>AEGIS Executive Report</h1>
<p><strong>Engagement:</strong> {eng.name} &nbsp;|&nbsp; <strong>Mode:</strong> {eng.mode.value}
&nbsp;|&nbsp; <strong>Status:</strong> {eng.status.value}</p>
<p>Total findings: <strong>{len(findings)}</strong>
&nbsp; Critical={by_sev.get('critical',0)} High={by_sev.get('high',0)}
Medium={by_sev.get('medium',0)} Low={by_sev.get('low',0)}</p>
<table><thead><tr><th>Severity</th><th>Risk</th><th>Title</th><th>ATT&CK</th></tr></thead>
<tbody>{rows or '<tr><td colspan=4>No findings yet</td></tr>'}</tbody></table>
<p style="margin-top:2rem;opacity:.6">Generated by AEGIS Swarm · Authorized defensive use only</p>
</body></html>"""


def run() -> None:
    import uvicorn

    uvicorn.run("aegis.api.main:app", host="0.0.0.0", port=8080, reload=False)


if __name__ == "__main__":
    run()
