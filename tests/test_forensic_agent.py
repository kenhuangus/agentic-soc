import pytest
from agentic_soc.agents.triage import TriageAgent
from agentic_soc.agents.forensic import ForensicAgent
from agentic_soc.scenarios.attack_chains import generate_apt_attack_chain
from agentic_soc.engine.telemetry_bus import TelemetryBus
from agentic_soc.models.incident import AlertStatus


def test_forensic_investigation_and_mitre_mapping():
    finding, events, baseline_store = generate_apt_attack_chain()
    bus = TelemetryBus()
    bus.publish_batch(events)

    triage = TriageAgent(baseline_store=baseline_store)
    dossier = triage.process(finding, bus)

    forensic = ForensicAgent()
    graph = forensic.process(dossier, bus)

    assert dossier.status == AlertStatus.INVESTIGATING
    assert dossier.blast_radius_score > 0.0
    assert len(graph.nodes) >= 4
    # Check that MITRE techniques were identified
    assert any("T1059" in t or "T1003" in t or "T1071" in t for t in dossier.mitre_techniques)
