"""Agent registry — all implemented catalog agents."""
from __future__ import annotations

from aegis.agents.blue.authentication_analyst import AuthenticationAnalyst
from aegis.agents.blue.catalog_batch import (
    ActiveDirectoryAnalyst,
    CloudSecurityAnalyst,
    DetectionEngineer,
    DHCPAnalyst,
    DNSAnalyst,
    EmailSecurityAnalyst,
    EndpointTelemetryAnalyst,
    EntraIDAnalyst,
    FirewallAnalyst,
    IDSAnalyst,
    IncidentCommander,
    InsiderThreatAnalyst,
    RiskAnalyst,
    SOCCoordinator,
    UEBAAnalyst,
    VPNAnalyst,
)
from aegis.agents.blue.network_traffic_analyst import NetworkTrafficAnalyst
from aegis.agents.blue.siem_correlator import SIEMCorrelator
from aegis.agents.blue.threat_hunter import ThreatHunter
from aegis.agents.command.catalog_batch import (
    KnowledgeManager,
    ResourceManager,
    Scheduler,
    TaskPlanner,
)
from aegis.agents.command.health_monitor import HealthMonitor
from aegis.agents.command.mission_controller import MissionController
from aegis.agents.dfir.catalog_batch import (
    ArtifactCollector,
    EvidenceCorrelator,
    IncidentReconstruction,
    MemoryAnalysisCoordinator,
)
from aegis.agents.dfir.root_cause_analyst import RootCauseAnalyst
from aegis.agents.dfir.timeline_builder import TimelineBuilder
from aegis.agents.intel.attack_mapper import AttackMapper
from aegis.agents.intel.catalog_batch import CampaignCorrelator, ThreatIntelFusion, TTPClassifier
from aegis.agents.intel.cve_intelligence import CVEIntelligence
from aegis.agents.intel.ioc_correlator import IOCCorrelator
from aegis.agents.purple.catalog_batch import (
    AttackCoverageAgent,
    ControlValidationAgent,
    LoggingCoverageAnalyst,
)
from aegis.agents.purple.detection_validator import DetectionValidator
from aegis.agents.purple.rule_coverage_analyst import RuleCoverageAnalyst
from aegis.agents.purple.security_gap_analyst import SecurityGapAnalyst
from aegis.agents.red.adversary_emulation_planner import AdversaryEmulationPlanner
from aegis.agents.red.attack_path_modeler import AttackPathModeler
from aegis.agents.red.catalog_batch import (
    ActiveDirectoryAssessment,
    AttackSurfaceDiscovery,
    CloudConfigurationAssessment,
    ContainerSecurityAssessment,
    ExternalExposureAssessment,
    IdentityExposureAssessment,
    KubernetesAssessment,
    SecurityControlValidation,
    WebApplicationAssessment,
    WirelessAssessment,
)
from aegis.agents.red.privilege_graph_analysis import PrivilegeGraphAnalysis
from aegis.agents.reporting.catalog_batch import (
    ComplianceReporting,
    DashboardGenerator,
    TechnicalReporting,
)
from aegis.agents.reporting.executive_reporter import ExecutiveReporter
from aegis.agents.reporting.recommendation_engine import RecommendationEngine
from aegis.agents.reporting.risk_prioritization import RiskPrioritization
from aegis.core.agent_base import BaseAgent


def build_default_agents() -> list[BaseAgent]:
    """Return the full implemented agent set (catalog coverage)."""
    return [
        MissionController(),
        HealthMonitor(),
        Scheduler(),
        TaskPlanner(),
        ResourceManager(),
        KnowledgeManager(),
        SIEMCorrelator(),
        ThreatHunter(),
        AuthenticationAnalyst(),
        NetworkTrafficAnalyst(),
        SOCCoordinator(),
        DetectionEngineer(),
        IDSAnalyst(),
        FirewallAnalyst(),
        EndpointTelemetryAnalyst(),
        ActiveDirectoryAnalyst(),
        EntraIDAnalyst(),
        EmailSecurityAnalyst(),
        DNSAnalyst(),
        DHCPAnalyst(),
        VPNAnalyst(),
        CloudSecurityAnalyst(),
        UEBAAnalyst(),
        InsiderThreatAnalyst(),
        RiskAnalyst(),
        IncidentCommander(),
        AttackMapper(),
        IOCCorrelator(),
        CVEIntelligence(),
        CampaignCorrelator(),
        ThreatIntelFusion(),
        TTPClassifier(),
        DetectionValidator(),
        RuleCoverageAnalyst(),
        SecurityGapAnalyst(),
        LoggingCoverageAnalyst(),
        ControlValidationAgent(),
        AttackCoverageAgent(),
        AttackPathModeler(),
        PrivilegeGraphAnalysis(),
        AdversaryEmulationPlanner(),
        AttackSurfaceDiscovery(),
        ExternalExposureAssessment(),
        IdentityExposureAssessment(),
        CloudConfigurationAssessment(),
        ContainerSecurityAssessment(),
        KubernetesAssessment(),
        WebApplicationAssessment(),
        WirelessAssessment(),
        ActiveDirectoryAssessment(),
        SecurityControlValidation(),
        TimelineBuilder(),
        RootCauseAnalyst(),
        ArtifactCollector(),
        MemoryAnalysisCoordinator(),
        EvidenceCorrelator(),
        IncidentReconstruction(),
        ExecutiveReporter(),
        RecommendationEngine(),
        RiskPrioritization(),
        TechnicalReporting(),
        DashboardGenerator(),
        ComplianceReporting(),
    ]
