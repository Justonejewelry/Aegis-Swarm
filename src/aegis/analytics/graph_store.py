"""NetworkX-backed privilege / attack-path graph store with optional Postgres persistence."""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID, uuid4

import networkx as nx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class GraphStore:
    """
    In-memory NetworkX DiGraph keyed by engagement_id.
    Optionally serializes edges to Postgres `graph_edges` table.
    """

    def __init__(self) -> None:
        self._graphs: dict[UUID, nx.DiGraph] = {}

    def get_or_create(self, engagement_id: UUID | str) -> nx.DiGraph:
        eid = UUID(str(engagement_id))
        if eid not in self._graphs:
            self._graphs[eid] = nx.DiGraph()
        return self._graphs[eid]

    def add_edges(self, engagement_id: UUID | str, edges: list[dict[str, Any]]) -> int:
        g = self.get_or_create(engagement_id)
        count = 0
        for e in edges:
            src, dst = e.get("src"), e.get("dst")
            if not src or not dst:
                continue
            g.add_edge(src, dst, **{k: v for k, v in e.items() if k not in ("src", "dst")})
            count += 1
        return count

    def shortest_paths(
        self,
        engagement_id: UUID | str,
        entries: list[str],
        targets: list[str],
        cutoff: int = 8,
    ) -> list[list[str]]:
        g = self.get_or_create(engagement_id)
        paths: list[list[str]] = []
        for entry in entries:
            for target in targets:
                if entry not in g or target not in g:
                    continue
                try:
                    path = nx.shortest_path(g, entry, target)
                    if 2 <= len(path) <= cutoff + 1:
                        paths.append(path)
                except nx.NetworkXNoPath:
                    continue
        return paths

    def privilege_concentration(
        self, engagement_id: UUID | str, high_value: list[str]
    ) -> list[dict[str, Any]]:
        g = self.get_or_create(engagement_id)
        results = []
        hv = set(high_value)
        for node in list(g.nodes):
            reachable = sum(1 for t in hv if t != node and t in g and nx.has_path(g, node, t))
            if reachable >= 2:
                results.append({"node": node, "reachable_hv": reachable})
        return sorted(results, key=lambda x: -x["reachable_hv"])

    def to_dict(self, engagement_id: UUID | str) -> dict[str, Any]:
        g = self.get_or_create(engagement_id)
        return {
            "nodes": list(g.nodes),
            "edges": [{"src": u, "dst": v, **d} for u, v, d in g.edges(data=True)],
        }

    def load_dict(self, engagement_id: UUID | str, data: dict[str, Any]) -> None:
        g = self.get_or_create(engagement_id)
        g.clear()
        for e in data.get("edges", []):
            g.add_edge(e["src"], e["dst"], **{k: v for k, v in e.items() if k not in ("src", "dst")})

    async def persist(self, session: AsyncSession, engagement_id: UUID | str) -> int:
        """Write current edges to graph_edges table (idempotent insert)."""
        eid = UUID(str(engagement_id))
        g = self.get_or_create(eid)
        await session.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS graph_edges (
                    edge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    engagement_id UUID NOT NULL,
                    src TEXT NOT NULL,
                    dst TEXT NOT NULL,
                    relation TEXT DEFAULT 'related',
                    meta JSONB DEFAULT '{}',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
                """
            )
        )
        count = 0
        for u, v, d in g.edges(data=True):
            relation = d.get("relation", "related")
            meta = {k: v for k, v in d.items() if k != "relation"}
            await session.execute(
                text(
                    """
                    INSERT INTO graph_edges (edge_id, engagement_id, src, dst, relation, meta)
                    VALUES (:eid, :eng, :src, :dst, :rel, :meta::jsonb)
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "eid": str(uuid4()),
                    "eng": str(eid),
                    "src": u,
                    "dst": v,
                    "rel": relation,
                    "meta": json.dumps(meta),
                },
            )
            count += 1
        await session.commit()
        return count


_store: GraphStore | None = None


def get_graph_store() -> GraphStore:
    global _store
    if _store is None:
        _store = GraphStore()
    return _store
