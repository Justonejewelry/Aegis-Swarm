"""AEGIS Swarm FastAPI control plane."""
from __future__ import annotations

from uuid import UUID

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from aegis.agents.blue.siem_correlator import SIEMCorrelator
from aegis.agents.command.mission_controller import MissionController
from aegis.agents.dfir.timeline_builder import TimelineBuilder
from aegis.agents.intel.attack_mapper import AttackMapper
from aegis.agents.purple.detection_validator import DetectionValidator
from aegis.agents.red.attack_path_modeler import AttackPathModeler
from aegis.agents.reporting.executive_reporter import ExecutiveReporter
from aegis.core.models import (
    AgentMessage,
    Engagement,
    EngagementMode,
    EngagementStatus,
    MsgType,
    Scope,
)
from aegis.core.orchestrator import Orchestrator

app = FastAPI(
    title="AEGIS Swarm API",
    version="0.1.0",
    description="Autonomous Enterprise Guard & Intelligence System — control plane",
)

orch = Orchestrator()
for agent in (
    MissionController(),
    SIEMCorrelator(),
    AttackMapper(),
    DetectionValidator(),
    AttackPathModeler(),
    TimelineBuilder(),
    ExecutiveReporter(),
):
    orch.register(agent)


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


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "agents": len(orch.agents)}


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
    return eng


@app.post("/engagements/{engagement_id}/approve")
async def approve_engagement(engagement_id: UUID, approver: str = "soc-lead") -> dict:
    eng = orch.engagements.get(engagement_id)
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
    return {"engagement": eng, "control": result}


@app.post("/dispatch")
async def dispatch(body: DispatchRequest):
    eng = orch.engagements.get(body.engagement_id)
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
    return {"result": result}


def run() -> None:
    import uvicorn

    uvicorn.run("aegis.api.main:app", host="0.0.0.0", port=8080, reload=False)


if __name__ == "__main__":
    run()
