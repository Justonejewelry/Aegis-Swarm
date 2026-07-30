"""Command domain catalog agents."""
from __future__ import annotations

from aegis.core.compact_agent import ResultAgent
from aegis.core.models import AgentMessage


class Scheduler(ResultAgent):
    agent_id = "scheduler"
    domain = "command"

    async def compute(self, message: AgentMessage) -> dict:
        jobs = message.payload.get("jobs", [])
        due = [j for j in jobs if j.get("due")]
        return {"scheduled": len(jobs), "due_now": due, "_confidence": 0.9}


class TaskPlanner(ResultAgent):
    agent_id = "task-planner"
    domain = "command"

    async def compute(self, message: AgentMessage) -> dict:
        mission = message.payload.get("mission", "")
        steps = message.payload.get("steps") or [
            {"agent": "siem-correlator", "task": "correlate recent alerts"},
            {"agent": "threat-hunter", "task": "hunt from top hypothesis"},
            {"agent": "risk-prioritization", "task": "rank residual risk"},
        ]
        return {"mission": mission, "plan": steps, "_confidence": 0.85}


class ResourceManager(ResultAgent):
    agent_id = "resource-manager"
    domain = "command"

    async def compute(self, message: AgentMessage) -> dict:
        budget = message.payload.get("budget", {})
        used = message.payload.get("used", {})
        return {
            "budget": budget,
            "used": used,
            "within_budget": all(used.get(k, 0) <= budget.get(k, 1e9) for k in budget),
            "_confidence": 0.9,
        }


class KnowledgeManager(ResultAgent):
    agent_id = "knowledge-manager"
    domain = "command"

    async def compute(self, message: AgentMessage) -> dict:
        entries = message.payload.get("entries", [])
        return {
            "indexed": len(entries),
            "stale": [e for e in entries if e.get("stale")],
            "_confidence": 0.8,
        }
