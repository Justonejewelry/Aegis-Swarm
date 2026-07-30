"""Health Monitor — aggregate agent liveness and SLA signals."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, MsgType, utcnow


class HealthMonitor(BaseAgent):
    agent_id = "health-monitor"
    domain = "command"

    async def handle(self, message: AgentMessage) -> AgentMessage:
        reports = message.payload.get("agent_reports", [])
        healthy = sum(1 for r in reports if r.get("status") == "healthy")
        degraded = sum(1 for r in reports if r.get("status") == "degraded")
        failed = sum(1 for r in reports if r.get("status") in {"failed", "offline"})
        total = max(len(reports), 1)
        fleet_status = "healthy"
        if failed:
            fleet_status = "critical"
        elif degraded:
            fleet_status = "degraded"

        await self.audit("fleet_health", {"status": fleet_status, "total": len(reports)})
        self._tasks_completed += 1
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload={
                "fleet_status": fleet_status,
                "healthy": healthy,
                "degraded": degraded,
                "failed": failed,
                "health_ratio": round(healthy / total, 3),
                "checked_at": utcnow().isoformat(),
            },
            confidence=0.95,
            correlation_id=message.correlation_id,
        )
