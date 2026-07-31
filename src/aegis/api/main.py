"""AEGIS Swarm FastAPI control plane."""
from __future__ import annotations

import logging
import uuid as _uuid
from typing import Any
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
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
from aegis.auth.api_key import require_api_key  # noqa: F401
from aegis.auth.deps import require_approver_role, require_auth
from aegis.core.settings import get_settings

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AEGIS Swarm API",
    version="0.4.2",
    description="Autonomous Enterprise Guard & Intelligence System — control plane",
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(_uuid.uuid4())
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response

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
            await EngagementRepository(session).upsert(eng)
    except Exception as e:
        logger.warning("persist engagement failed (dev OK): %s", e)


async def _load_engagement_from_db(engagement_id: UUID) -> Engagement | None:
    try:
        from aegis.storage.repositories import EngagementRepository
        from aegis.storage.session import get_session
        async with get_session() as session:
            row = await EngagementRepository(session).get(engagement_id)
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
            rows = await FindingRepository(session).list_for_engagement(engagement_id)
            findings = [FindingRepository.to_finding(r) for r in rows]
            if findings:
                _findings_by_eng[engagement_id] = findings
                try:
                    from aegis.storage.cache import get_cache
                    await (await get_cache()).set_findings(engagement_id, findings)
                except Exception:
                    pass
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
        await (await get_cache()).set_findings(engagement_id, _findings_by_eng[engagement_id])
    except Exception:
        pass
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


async def _audit(engagement_id: UUID | None, agent_id: str, event: str, details: dict) -> None:
    settings = get_settings()
    if not settings.persist_audit:
        return
    try:
        from aegis.storage.repositories import AuditRepository
        from aegis.storage.session import get_session
        async with get_session() as session:
            await AuditRepository(session).log(engagement_id, agent_id, event, details)
    except Exception as e:
        logger.debug("audit persist skipped: %s", e)


async def _resolve_engagement(engagement_id: UUID) -> Engagement | None:
    eng = orch.engagements.get(engagement_id)
    if eng is not None:
        return eng
    try:
        from aegis.storage.cache import get_cache
        cached = await (await get_cache()).get_engagement(engagement_id)
        if cached is not None:
            if cached.engagement_id not in orch.engagements:
                try:
                    orch.register_engagement(cached)
                except ValueError:
                    orch.engagements[cached.engagement_id] = cached
            return cached
    except Exception:
        pass
    eng = await _load_engagement_from_db(engagement_id)
    if eng is not None:
        try:
            from aegis.storage.cache import get_cache
            await (await get_cache()).set_engagement(eng)
        except Exception:
            pass
    return eng


@app.get("/health")
async def health() -> dict:
    settings = get_settings()
    cache_stats: dict = {}
    try:
        from aegis.storage.cache import get_cache
        cache_stats = (await get_cache()).stats()
    except Exception:
        cache_stats = {"backend": "unavailable"}
    return {
        "status": "ok",
        "agents": len(orch.agents),
        "version": "0.4.2",
        "env": settings.env,
        "persist": settings.persist_findings,
        "engagements_in_memory": len(orch.engagements),
        "cache": cache_stats,
    }


@app.get("/metrics")
async def metrics():
    settings = get_settings()
    if not settings.enable_metrics:
        raise HTTPException(404, "metrics disabled")
    from fastapi.responses import PlainTextResponse, Response
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest
        registry = CollectorRegistry()
        Gauge("aegis_agents_registered", "Registered agents", registry=registry).set(len(orch.agents))
        Gauge("aegis_engagements_in_memory", "Engagements in process memory", registry=registry).set(len(orch.engagements))
        try:
            from aegis.storage.cache import get_cache
            cache = await get_cache()
            Gauge("aegis_cache_hits", "Cache hits", registry=registry).set(getattr(cache, "hits", 0))
            Gauge("aegis_cache_misses", "Cache misses", registry=registry).set(getattr(cache, "misses", 0))
        except Exception:
            pass
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
    except Exception as e:
        text = f"aegis_agents_registered {len(orch.agents)}\naegis_engagements_in_memory {len(orch.engagements)}\n# error_fallback {type(e).__name__}\n"
        return PlainTextResponse(text, media_type="text/plain; version=0.0.4")


@app.get("/agents")
async def list_agents() -> list[dict]:
    return orch.list_agents()


@app.get("/audit")
async def list_audit(engagement_id: UUID | None = None, limit: int = 100) -> list[dict]:
    try:
        from aegis.storage.repositories import AuditRepository
        from aegis.storage.session import get_session
        async with get_session() as session:
            repo = AuditRepository(session)
            rows = await (repo.for_engagement(engagement_id, limit=limit) if engagement_id else repo.recent(limit=limit))
            return [{
                "audit_id": r.audit_id,
                "engagement_id": str(r.engagement_id) if r.engagement_id else None,
                "agent_id": r.agent_id,
                "event": r.event,
                "details": r.details,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            } for r in rows]
    except Exception as e:
        raise HTTPException(503, f"audit store unavailable: {e}") from e


class IngestRequest(BaseModel):
    engagement_id: UUID
    domain: str | None = None
    since: str | None = None
    limit_per_connector: int = 50
    use_syslog_buffer: bool = True
    syslog_lines: list[str] = Field(default_factory=list)


@app.post("/ingest")
async def run_ingestion(body: IngestRequest, _: None = Depends(require_auth)) -> dict:
    eng = await _resolve_engagement(body.engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    if eng.status != EngagementStatus.ACTIVE:
        raise HTTPException(403, f"engagement status is {eng.status}")
    from aegis.ingestion.connectors import ElasticConnector, SentinelConnector, SyslogConnector
    from aegis.ingestion.pipeline import IngestionPipeline
    connectors: list = [ElasticConnector(), SentinelConnector()]
    if body.use_syslog_buffer or body.syslog_lines:
        syslog = SyslogConnector()
        for line in body.syslog_lines:
            syslog.ingest_line(line)
        connectors.insert(0, syslog)
    result = await IngestionPipeline(connectors).collect_and_enqueue(
        engagement_id=body.engagement_id, bus=await get_bus(),
        limit_per_connector=body.limit_per_connector, since=body.since, domain=body.domain,
    )
    await _audit(body.engagement_id, "ingestion", "ingest_run", {"enqueued": result.get("enqueued"), "domain": body.domain})
    return result


@app.post("/engagements")
async def create_engagement(body: CreateEngagementRequest, _: None = Depends(require_auth)) -> Engagement:
    eng = Engagement(name=body.name, mode=body.mode, scope=body.scope, status=EngagementStatus.DRAFT, approver=body.approver)
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
        out.append({"engagement_id": str(eng.engagement_id), "name": eng.name, "mode": eng.mode.value, "status": eng.status.value, "approver": eng.approver, "created_at": eng.created_at.isoformat() if eng.created_at else None, "source": "memory"})
    try:
        from aegis.storage.repositories import EngagementRepository
        from aegis.storage.session import get_session
        async with get_session() as session:
            for row in await EngagementRepository(session).list_recent(limit=limit):
                if row.engagement_id in seen:
                    continue
                out.append({"engagement_id": str(row.engagement_id), "name": row.name, "mode": row.mode, "status": row.status, "approver": row.approver, "created_at": row.created_at.isoformat() if row.created_at else None, "source": "db"})
                seen.add(row.engagement_id)
    except Exception as e:
        logger.debug("list engagements from DB skipped: %s", e)
    return out[:limit]


@app.post("/engagements/{engagement_id}/abort")
async def abort_engagement(engagement_id: UUID, reason: str = "operator_kill_switch", _: None = Depends(require_approver_role)) -> dict:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    eng.status = EngagementStatus.ABORTED
    await _persist_engagement(eng)
    try:
        from aegis.storage.cache import get_cache
        await (await get_cache()).invalidate_engagement(engagement_id)
    except Exception:
        pass
    await _audit(engagement_id, "api", "engagement_aborted", {"reason": reason})
    return {"engagement": eng, "aborted": True, "reason": reason}


@app.post("/engagements/{engagement_id}/approve")
async def approve_engagement(engagement_id: UUID, approver: str = "soc-lead", _: None = Depends(require_approver_role)) -> dict:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    msg = AgentMessage(engagement_id=engagement_id, sender="api", recipient="mission-controller", msg_type=MsgType.CONTROL, payload={"action": "approve_engagement", "approver": approver})
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
    return {"engagement": eng, "finding_count": len(findings), "findings": [f.model_dump(mode="json") for f in findings[:50]]}


@app.get("/engagements/{engagement_id}/findings")
async def list_findings(engagement_id: UUID) -> list[dict]:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    return [f.model_dump(mode="json") for f in await _load_findings_from_db(engagement_id)]


@app.get("/engagements/{engagement_id}/graph")
async def get_graph(engagement_id: UUID) -> dict:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    return get_graph_store().to_dict(engagement_id)


@app.post("/dispatch")
async def dispatch(body: DispatchRequest, _: None = Depends(require_auth)):
    eng = await _resolve_engagement(body.engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    if eng.status != EngagementStatus.ACTIVE:
        raise HTTPException(403, f"engagement status is {eng.status}; approve first")
    msg = AgentMessage(engagement_id=body.engagement_id, sender="api", recipient=body.recipient, msg_type=body.msg_type, priority=body.priority, payload=body.payload)
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
    await _audit(body.engagement_id, body.recipient, "dispatch", {"msg_type": body.msg_type.value})
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
async def enqueue_task(body: EnqueueRequest, _: None = Depends(require_auth)):
    eng = await _resolve_engagement(body.engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    if eng.status != EngagementStatus.ACTIVE:
        raise HTTPException(403, f"engagement status is {eng.status}")
    bus = await get_bus()
    task_id = await bus.enqueue({"engagement_id": str(body.engagement_id), "recipient": body.recipient, "payload": body.payload, "priority": body.priority, "sender": "api", "msg_type": "task", "mode": eng.mode.value, "engagement_name": eng.name, "scope": eng.scope.model_dump()})
    return {"task_id": task_id, "queued": True}


@app.get("/engagements/{engagement_id}/report", response_class=HTMLResponse)
async def executive_report(engagement_id: UUID) -> str:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    findings = await _load_findings_from_db(engagement_id)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    top = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:8]
    rows = "".join(f"<tr><td>{f.severity.value}</td><td>{f.risk_score:.1f}</td><td>{f.title}</td><td>{', '.join(f.mitre_techniques[:3])}</td></tr>" for f in top)
    return f"""<!DOCTYPE html><html><head><title>AEGIS Report — {eng.name}</title></head><body>
<h1>AEGIS Executive Report</h1><p>{eng.name} | {eng.mode.value} | {eng.status.value}</p>
<p>Findings: {len(findings)} C={by_sev.get('critical',0)} H={by_sev.get('high',0)}</p>
<table><tr><th>Sev</th><th>Risk</th><th>Title</th><th>ATT&CK</th></tr>{rows}</table></body></html>"""


class PurpleValidateRequest(BaseModel):
    active_rule_ids: list[str] = Field(default_factory=list)


@app.post("/purple/validate")
async def purple_validate(body: PurpleValidateRequest, _: None = Depends(require_auth)) -> dict:
    from aegis.purple.validation_harness import DetectionValidationHarness
    report = DetectionValidationHarness().run(body.active_rule_ids)
    return {"total": report.total, "passed": report.passed, "failed": report.failed, "coverage_pct": report.coverage_pct, "by_technique": report.by_technique, "results": [{"fixture_id": r.fixture_id, "technique": r.technique, "passed": r.passed, "matched_rules": r.matched_rules, "missing_rules": r.missing_rules, "notes": r.notes} for r in report.results]}


@app.get("/compliance/matrix")
async def compliance_matrix() -> list[dict]:
    from aegis.compliance.frameworks import coverage_matrix
    return coverage_matrix()


class ScheduleReportRequest(BaseModel):
    schedule_id: str
    engagement_id: UUID
    interval_hours: int = 24


@app.post("/reports/schedule")
async def schedule_report(body: ScheduleReportRequest, _: None = Depends(require_auth)) -> dict:
    from aegis.reporting.scheduler import get_report_scheduler
    job = get_report_scheduler().schedule(body.schedule_id, body.engagement_id, interval_hours=body.interval_hours)
    return {"schedule_id": job.schedule_id, "engagement_id": str(job.engagement_id), "interval_hours": job.interval_hours}


@app.post("/reports/tick")
async def tick_reports(_: None = Depends(require_auth)) -> dict:
    from aegis.reporting.scheduler import get_report_scheduler
    async def render(eid: UUID):
        eng = await _resolve_engagement(eid)
        if not eng:
            raise ValueError("engagement not found")
        return {"engagement": eng.name, "finding_count": len(await _load_findings_from_db(eid))}
    results = await get_report_scheduler().tick(render)
    return {"ran": len(results), "results": results}


@app.post("/engagements/{engagement_id}/graph/persist")
async def persist_graph(engagement_id: UUID, _: None = Depends(require_auth)) -> dict:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    try:
        from aegis.storage.session import get_session
        async with get_session() as session:
            n = await get_graph_store().persist(session, engagement_id)
        return {"persisted_edges": n}
    except Exception as e:
        raise HTTPException(503, f"graph persist unavailable: {e}") from e


@app.post("/engagements/{engagement_id}/graph/load")
async def load_graph(engagement_id: UUID, _: None = Depends(require_auth)) -> dict:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    try:
        from aegis.storage.session import get_session
        async with get_session() as session:
            n = await get_graph_store().load_from_db(session, engagement_id)
        return {"loaded_edges": n, "graph": get_graph_store().to_dict(engagement_id)}
    except Exception as e:
        raise HTTPException(503, f"graph load unavailable: {e}") from e


class EvidenceRegisterRequest(BaseModel):
    engagement_id: UUID
    label: str
    content_text: str | None = None
    content_hash: str | None = None
    source: str | None = None
    media_type: str | None = None
    collected_by: str | None = None
    meta: dict = Field(default_factory=dict)


@app.post("/evidence")
async def register_evidence(body: EvidenceRegisterRequest, _: None = Depends(require_auth)) -> dict:
    eng = await _resolve_engagement(body.engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    from aegis.dfir.evidence_chain import get_evidence_chain
    rec = get_evidence_chain().register(body.engagement_id, label=body.label, content=body.content_text, content_hash=body.content_hash, source=body.source, media_type=body.media_type, collected_by=body.collected_by, meta=body.meta)
    persisted = False
    try:
        from aegis.storage.repositories import EvidenceRepository
        from aegis.storage.session import get_session
        async with get_session() as session:
            await EvidenceRepository(session).upsert_record(rec)
            await session.commit()
            persisted = True
    except Exception as e:
        logger.warning("evidence persist skipped: %s", e)
    await _audit(body.engagement_id, "dfir", "evidence_registered", {"evidence_id": rec.evidence_id, "persisted": persisted})
    return {"evidence_id": rec.evidence_id, "content_hash": rec.content_hash, "chain_hash": rec.chain_hash, "prev_hash": rec.prev_hash, "persisted": persisted}


@app.get("/evidence/{engagement_id}")
async def list_evidence(engagement_id: UUID) -> dict:
    from aegis.dfir.evidence_chain import get_evidence_chain
    chain = get_evidence_chain()
    items = chain.export(engagement_id)
    source = "memory"
    if not items:
        try:
            from aegis.storage.repositories import EvidenceRepository
            from aegis.storage.session import get_session
            async with get_session() as session:
                rows = await EvidenceRepository(session).list_for_engagement(engagement_id)
            for row in rows:
                chain.register(engagement_id, label=row["label"], content_hash=row["content_hash"], source=row.get("source"), media_type=row.get("media_type"), collected_by=row.get("collected_by"), meta=row.get("meta") or {})
            items = chain.export(engagement_id)
            source = "db"
        except Exception as e:
            logger.debug("evidence load from DB skipped: %s", e)
    return {"engagement_id": str(engagement_id), "source": source, "items": items, "verify": chain.verify(engagement_id)}


@app.get("/evidence/{engagement_id}/verify")
async def verify_evidence_chain(engagement_id: UUID) -> dict:
    from aegis.dfir.evidence_chain import get_evidence_chain
    return get_evidence_chain().verify(engagement_id)


@app.get("/attack/coverage")
async def attack_coverage(engagement_id: UUID | None = None, format: str = "json"):
    from fastapi.responses import PlainTextResponse
    from aegis.analytics.attack_coverage import build_coverage_matrix, matrix_to_csv
    findings: list[dict] = []
    if engagement_id:
        try:
            loaded = await _load_findings_from_db(engagement_id)
            findings = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in loaded]
        except Exception:
            findings = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in _findings_by_eng.get(engagement_id, [])]
    else:
        try:
            from aegis.storage.repositories import FindingRepository
            from aegis.storage.session import get_session
            async with get_session() as session:
                rows = await FindingRepository(session).top_risk(limit=500)
                findings = [FindingRepository.to_finding(r).model_dump() for r in rows]
        except Exception:
            pass
        for eng_findings in _findings_by_eng.values():
            for f in eng_findings:
                findings.append(f.model_dump() if hasattr(f, "model_dump") else dict(f))
    active = [a.get("agent_id") for a in orch.list_agents() if a.get("agent_id")]
    matrix = build_coverage_matrix(findings=findings, active_agents=active or None)
    if format.lower() == "csv":
        return PlainTextResponse(matrix_to_csv(matrix), media_type="text/csv")
    return matrix


@app.get("/audit/export")
async def export_audit(engagement_id: UUID | None = None, limit: int = 500, _: None = Depends(require_auth)) -> dict:
    from aegis.audit.signed_export import build_signed_export
    rows: list[dict] = []
    try:
        from aegis.storage.repositories import AuditRepository
        from aegis.storage.session import get_session
        async with get_session() as session:
            repo = AuditRepository(session)
            db_rows = await (repo.for_engagement(engagement_id, limit=limit) if engagement_id else repo.recent(limit=limit))
            rows = [{"audit_id": r.audit_id, "engagement_id": str(r.engagement_id) if r.engagement_id else None, "agent_id": r.agent_id, "event": r.event, "details": r.details, "created_at": r.created_at.isoformat() if r.created_at else None} for r in db_rows]
    except Exception as e:
        raise HTTPException(503, f"audit store unavailable: {e}") from e
    return build_signed_export(rows, secret=get_settings().audit_signing_key, engagement_id=str(engagement_id) if engagement_id else None)


@app.get("/engagements/{engagement_id}/report.html")
async def executive_report_html(engagement_id: UUID):
    from fastapi.responses import HTMLResponse
    from aegis.analytics.attack_coverage import build_coverage_matrix
    from aegis.audit.signed_export import render_executive_html
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    findings = await _load_findings_from_db(engagement_id)
    finding_dicts = []
    sev_counts: dict[str, int] = {}
    for f in findings:
        d = f.model_dump() if hasattr(f, "model_dump") else dict(f)
        finding_dicts.append(d)
        sev = str(d.get("severity", "info"))
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    top = sorted(finding_dicts, key=lambda x: x.get("risk_score") or 0, reverse=True)[:10]
    coverage = build_coverage_matrix(findings=finding_dicts)
    html = render_executive_html(engagement_name=eng.name, engagement_id=str(engagement_id), summary=f"Engagement produced {len(finding_dicts)} findings.", severity_counts=sev_counts, top_findings=top, coverage=coverage)
    return HTMLResponse(html)


@app.get("/engagements/{engagement_id}/timeline")
async def engagement_timeline(engagement_id: UUID) -> dict:
    eng = await _resolve_engagement(engagement_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    events: list[dict] = []
    for f in await _load_findings_from_db(engagement_id):
        d = f.model_dump(mode="json") if hasattr(f, "model_dump") else dict(f)
        events.append({"ts": d.get("created_at"), "kind": "finding", "severity": d.get("severity"), "title": d.get("title"), "mitre": d.get("mitre_techniques") or [], "id": str(d.get("finding_id"))})
    try:
        from aegis.storage.repositories import AuditRepository
        from aegis.storage.session import get_session
        async with get_session() as session:
            rows = await AuditRepository(session).for_engagement(engagement_id, limit=200)
        for r in rows:
            events.append({"ts": r.created_at.isoformat() if r.created_at else None, "kind": "audit", "agent_id": r.agent_id, "event": r.event, "details": r.details, "id": str(r.audit_id)})
    except Exception as e:
        logger.debug("timeline audit load skipped: %s", e)
    events.sort(key=lambda e: e.get("ts") or "")
    return {"engagement_id": str(engagement_id), "count": len(events), "events": events}


def run() -> None:
    import uvicorn
    uvicorn.run("aegis.api.main:app", host="0.0.0.0", port=8080, reload=False)


if __name__ == "__main__":
    run()
