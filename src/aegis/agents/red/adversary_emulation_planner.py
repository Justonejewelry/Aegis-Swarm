"""Adversary Emulation Planner — produce authorized ATT&CK test plans (no exploit execution)."""
from __future__ import annotations

from aegis.core.agent_base import BaseAgent
from aegis.core.models import AgentMessage, MsgType


class AdversaryEmulationPlanner(BaseAgent):
    agent_id = "adversary-emulation-planner"
    domain = "red"

    async def handle(self, message: AgentMessage) -> AgentMessage:
        techniques = message.payload.get("techniques", ["T1059.001", "T1003", "T1021"])
        allowed = set(message.payload.get("allowed_actions", ["detection_test", "emulation_plan"]))
        if "emulation_plan" not in allowed and "detection_test" not in allowed:
            await self.audit("emulation_refused", {"reason": "not in allowed_actions"})
            return AgentMessage(
                engagement_id=message.engagement_id,
                sender=self.agent_id,
                recipient=message.sender,
                msg_type=MsgType.RESULT,
                payload={"error": "emulation_plan not permitted in engagement scope"},
                confidence=1.0,
                correlation_id=message.correlation_id,
            )

        plan = []
        for tech in techniques:
            plan.append({
                "technique": tech,
                "objective": f"Validate detection and logging for {tech}",
                "steps": [
                    "Confirm scope and approval",
                    "Generate synthetic telemetry or atomic test reference",
                    "Observe SIEM/EDR alerts and log presence",
                    "Record pass/fail and open remediation if gap",
                ],
                "safety": "No destructive actions; detection_test only unless further approved",
            })

        await self.audit("emulation_plan", {"techniques": len(plan)})
        self._tasks_completed += 1
        return AgentMessage(
            engagement_id=message.engagement_id,
            sender=self.agent_id,
            recipient=message.sender,
            msg_type=MsgType.RESULT,
            payload={"plan": plan, "requires_approval": True},
            confidence=0.9,
            mitre_techniques=list(techniques),
            correlation_id=message.correlation_id,
        )
