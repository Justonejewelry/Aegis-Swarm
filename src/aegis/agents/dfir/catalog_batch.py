"""DFIR catalog agents."""
from __future__ import annotations

from aegis.core.compact_agent import ResultAgent
from aegis.core.models import AgentMessage


class ArtifactCollector(ResultAgent):
    agent_id = "artifact-collector"
    domain = "dfir"

    async def compute(self, message: AgentMessage) -> dict:
        targets = message.payload.get("targets", [])
        requested = message.payload.get("artifact_types", ["logs", "memory", "disk"])
        return {
            "targets": targets,
            "requested": requested,
            "collection_plan": [{"host": t, "artifacts": requested} for t in targets],
            "chain_of_custody": True,
            "_confidence": 0.85,
        }


class MemoryAnalysisCoordinator(ResultAgent):
    agent_id = "memory-analysis-coordinator"
    domain = "dfir"

    async def compute(self, message: AgentMessage) -> dict:
        dumps = message.payload.get("memory_dumps", [])
        return {
            "dumps": len(dumps),
            "priority": sorted(dumps, key=lambda d: d.get("priority", 5)),
            "notes": "Coordinate offline memory triage — do not execute untrusted code",
            "_confidence": 0.8,
            "_techniques": ["T1055"],
        }


class EvidenceCorrelator(ResultAgent):
    agent_id = "evidence-correlator"
    domain = "dfir"

    async def compute(self, message: AgentMessage) -> dict:
        items = message.payload.get("evidence", [])
        by_host: dict[str, list] = {}
        for e in items:
            by_host.setdefault(e.get("host", "unknown"), []).append(e.get("id", ""))
        links = [{"host": h, "evidence_ids": ids} for h, ids in by_host.items() if len(ids) > 1]
        return {"cross_host_links": links, "total_evidence": len(items), "_confidence": 0.75, "_techniques": ["T1074"]}


class IncidentReconstruction(ResultAgent):
    agent_id = "incident-reconstruction"
    domain = "dfir"

    async def compute(self, message: AgentMessage) -> dict:
        timeline = message.payload.get("timeline", [])
        narrative = message.payload.get("narrative") or (
            f"Reconstructed {len(timeline)} events from first to last observed activity."
        )
        return {
            "narrative": narrative,
            "event_count": len(timeline),
            "first_ts": timeline[0].get("ts") if timeline else None,
            "last_ts": timeline[-1].get("ts") if timeline else None,
            "_confidence": 0.7 if timeline else 0.3,
            "_techniques": ["T1078"],
        }
