"""Shared domain models for AEGIS Swarm."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngagementMode(str, Enum):
    MONITOR = "monitor"
    ASSESS = "assess"
    HUNT = "hunt"
    PURPLE_VALIDATE = "purple_validate"
    INCIDENT = "incident"
    TABLETOP = "tabletop"


class EngagementStatus(str, Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"


class MsgType(str, Enum):
    TASK = "task"
    RESULT = "result"
    FINDING = "finding"
    ALERT = "alert"
    HEARTBEAT = "heartbeat"
    CONSENSUS = "consensus"
    AUDIT = "audit"
    CONTROL = "control"


class Scope(BaseModel):
    in_scope_cidrs: list[str] = Field(default_factory=list)
    in_scope_domains: list[str] = Field(default_factory=list)
    in_scope_assets: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    allowed_validation_actions: list[str] = Field(
        default_factory=lambda: ["passive_recon", "config_review", "detection_test"]
    )


class Engagement(BaseModel):
    engagement_id: UUID = Field(default_factory=uuid4)
    name: str
    mode: EngagementMode
    scope: Scope
    status: EngagementStatus = EngagementStatus.DRAFT
    approver: str | None = None
    start_at: datetime | None = None
    end_at: datetime | None = None
    created_at: datetime = Field(default_factory=utcnow)


class Finding(BaseModel):
    finding_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    title: str
    description: str = ""
    severity: Severity
    category: str
    confidence: float = Field(ge=0, le=1)
    risk_score: float = Field(default=0, ge=0, le=100)
    mitre_techniques: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)
    sources: list[str]
    remediation: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


class AgentMessage(BaseModel):
    message_id: UUID = Field(default_factory=uuid4)
    correlation_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    sender: str
    recipient: str
    msg_type: MsgType
    priority: int = Field(default=3, ge=1, le=5)
    payload: dict[str, Any] = Field(default_factory=dict)
    confidence: float | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utcnow)
    signature: str = ""


class AgentHealth(BaseModel):
    agent_id: str
    status: str  # healthy | degraded | failed | offline
    last_heartbeat: datetime
    tasks_completed: int = 0
    tasks_failed: int = 0
    avg_latency_ms: float = 0.0
