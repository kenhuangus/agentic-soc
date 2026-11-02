"""End-to-End Agentic SOC Orchestration Pipeline."""

from __future__ import annotations
from typing import Dict, List, Optional
from .models.ocsf import FindingEvent, OCSFEvent
from .models.incident import IncidentDossier, AlertStatus, ContainmentAction
from .models.graph import AttackGraph
from .engine.telemetry_bus import TelemetryBus
from .engine.baseline import EntityBaselineStore
from .engine.soar_gateway import SOARGateway
from .agents.triage import TriageAgent
from .agents.forensic import ForensicAgent
from .agents.hunter import HunterAgent
from .agents.supervisor import SOCSupervisor


class SOCPipeline:
    """Orchestrates multi-tier security investigation and containment across Tier 1-4 agents."""

    def __init__(
        self,
        telemetry_bus: Optional[TelemetryBus] = None,
        baseline_store: Optional[EntityBaselineStore] = None,
        soar_gateway: Optional[SOARGateway] = None
    ) -> None:
        self.telemetry_bus = telemetry_bus or TelemetryBus()
        self.baseline_store = baseline_store or EntityBaselineStore()
        self.soar_gateway = soar_gateway or SOARGateway()

        # Instantiate tiered agents
        self.triage_agent = TriageAgent(baseline_store=self.baseline_store)
        self.forensic_agent = ForensicAgent()
        self.hunter_agent = HunterAgent()
        self.supervisor_agent = SOCSupervisor(soar_gateway=self.soar_gateway)

    def process_incident(
        self,
        finding: FindingEvent,
        human_approver: Optional[str] = None,
        auto_approve_hitl: bool = False
    ) -> IncidentDossier:
        """Executes full multi-tier SOC investigation cycle."""
        # Step 1: Tier 1 Triage
        dossier = self.triage_agent.process(finding, self.telemetry_bus)

        # False positive early termination gate
        if dossier.status == AlertStatus.FALSE_POSITIVE:
            return dossier

        # Step 2: Tier 2 Forensic Investigation
        attack_graph = self.forensic_agent.process(dossier, self.telemetry_bus)

        # Step 3: Tier 3 Threat Hunting & Containment Formulation
        self.hunter_agent.process(dossier, attack_graph)

        # Step 4: Tier 4 Governance & SOAR Execution Gate
        self.supervisor_agent.process(
            dossier,
            human_approver=human_approver,
            auto_approve_hitl=auto_approve_hitl
        )

        return dossier
