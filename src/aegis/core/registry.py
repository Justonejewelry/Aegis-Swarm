"""Agent registry — single place to list implemented agents."""
from __future__ import annotations

from aegis.agents.blue.authentication_analyst import AuthenticationAnalyst
from aegis.agents.blue.network_traffic_analyst import NetworkTrafficAnalyst
from aegis.agents.blue.siem_correlator import SIEMCorrelator
from aegis.agents.blue.threat_hunter import ThreatHunter
from aegis.agents.command.health_monitor import HealthMonitor
from aegis.agents.command.mission_controller import MissionController
from aegis.agents.dfir.root_cause_analyst import RootCauseAnalyst
from aegis.agents.dfir.timeline_builder import TimelineBuilder
from aegis.agents.intel.attack_mapper import AttackMapper
from aegis.agents.intel.cve_intelligence import CVEIntelligence
from aegis.agents.intel.ioc_correlator import IOCCorrelator
from aegis.agents.purple.detection_validator import DetectionValidator
from aegis.agents.purple.rule_coverage_analyst import RuleCoverageAnalyst
from aegis.agents.purple.security_gap_analyst import SecurityGapAnalyst
from aegis.agents.red.adversary_emulation_planner import AdversaryEmulationPlanner
from aegis.agents.red.attack_path_modeler import AttackPathModeler
from aegis.agents.red.privilege_graph_analysis import PrivilegeGraphAnalysis
from aegis.agents.reporting.executive_reporter import ExecutiveReporter
from aegis.agents.reporting.recommendation_engine import RecommendationEngine
from aegis.agents.reporting.risk_prioritization import RiskPrioritization
from aegis.core.agent_base import BaseAgent


def build_default_agents() -> list[BaseAgent]:
    """Return all currently implemented agents (v0.1.x set)."""
    return [
        # Command
        MissionController(),
        HealthMonitor(),
        # Blue
        SIEMCorrelator(),
        ThreatHunter(),
        AuthenticationAnalyst(),
        NetworkTrafficAnalyst(),
        # Intel
        AttackMapper(),
        IOCCorrelator(),
        CVEIntelligence(),
        # Purple
        DetectionValidator(),
        RuleCoverageAnalyst(),
        SecurityGapAnalyst(),
        # Red (authorized validation)
        AttackPathModeler(),
        PrivilegeGraphAnalysis(),
        AdversaryEmulationPlanner(),
        # DFIR
        TimelineBuilder(),
        RootCauseAnalyst(),
        # Reporting
        ExecutiveReporter(),
        RecommendationEngine(),
        RiskPrioritization(),
    ]
