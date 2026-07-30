"""Base agent contract for all AEGIS swarm members."""
from __future__ import annotations

import abc
import logging
from typing import Any

from aegis.core.models import AgentHealth, AgentMessage, Finding, utcnow

logger = logging.getLogger(__name__)


class BaseAgent(abc.ABC):
    """
    Every agent implements this contract.

    Security invariants:
    - Must receive a valid engagement_id on every task
    - Must refuse out-of-scope targets
    - Must emit audit events for every decision
    - Must never execute unauthorized destructive actions
    """

    agent_id: str = "base"
    domain: str = "command"
    version: str = "0.1.0"

    def __init__(self, bus: Any | None = None, memory: Any | None = None) -> None:
        self.bus = bus
        self.memory = memory
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._last_heartbeat = utcnow()

    @abc.abstractmethod
    async def handle(self, message: AgentMessage) -> AgentMessage | list[Finding] | None:
        """Process an inbound message and optionally emit findings."""

    async def heartbeat(self) -> AgentHealth:
        self._last_heartbeat = utcnow()
        return AgentHealth(
            agent_id=self.agent_id,
            status="healthy",
            last_heartbeat=self._last_heartbeat,
            tasks_completed=self._tasks_completed,
            tasks_failed=self._tasks_failed,
        )

    def compute_confidence(
        self,
        *,
        source_quality: float,
        corroboration: int,
        freshness_hours: float,
        false_positive_rate: float = 0.1,
    ) -> float:
        """
        Shared confidence model (0..1).

        confidence = clamp(
            0.4 * source_quality
          + 0.3 * min(1, corroboration / 3)
          + 0.2 * max(0, 1 - freshness_hours / 168)
          + 0.1 * (1 - false_positive_rate)
        )
        """
        raw = (
            0.4 * source_quality
            + 0.3 * min(1.0, corroboration / 3.0)
            + 0.2 * max(0.0, 1.0 - freshness_hours / 168.0)
            + 0.1 * (1.0 - false_positive_rate)
        )
        return max(0.0, min(1.0, raw))

    def assert_in_scope(self, target: str, scope_targets: set[str]) -> None:
        if scope_targets and target not in scope_targets:
            raise PermissionError(
                f"Agent {self.agent_id} refused out-of-scope target: {target}"
            )

    async def audit(self, event: str, details: dict[str, Any]) -> None:
        logger.info(
            "audit",
            extra={"agent": self.agent_id, "event": event, "details": details},
        )
