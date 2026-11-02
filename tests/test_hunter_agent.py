import pytest
from agentic_soc.agents.triage import TriageAgent
from agentic_soc.agents.forensic import ForensicAgent
from agentic_soc.agents.hunter import HunterAgent
from agentic_soc.scenarios.attack_chains import generate_apt_attack_chain
from agentic_soc.engine.telemetry_bus import TelemetryBus
from agentic_soc.models.incident import AlertStatus


def test_hunter_containment_formulation():
    finding, events, baseline_store = generate_apt_attack_chain()
    bus = TelemetryBus()
    bus.publish_batch(events)

    triage = TriageAgent(baseline_store=baseline_store)
    dossier = triage.process(finding, bus)

    forensic = ForensicAgent()
    graph = forensic.process(dossier, bus)

    hunter = HunterAgent()
    actions = hunter.process(dossier, graph)

    assert dossier.status == AlertStatus.CONTAINMENT_PROPOSED
    assert len(actions) > 0

    # Ensure actions distinguish between automated and HITL-required
    has_hitl = any(a.requires_hitl for a in actions)
    has_automated = any(not a.requires_hitl for a in actions)
    assert has_hitl is True
    assert has_automated is True
