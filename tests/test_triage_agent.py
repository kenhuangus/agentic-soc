import pytest
from agentic_soc.agents.triage import TriageAgent
from agentic_soc.scenarios.attack_chains import generate_false_positive_scenario, generate_apt_attack_chain
from agentic_soc.engine.telemetry_bus import TelemetryBus
from agentic_soc.models.incident import AlertStatus


def test_triage_false_positive():
    finding, events, baseline_store = generate_false_positive_scenario()
    bus = TelemetryBus()
    bus.publish_batch(events)

    triage = TriageAgent(baseline_store=baseline_store)
    dossier = triage.process(finding, bus)

    assert dossier.status == AlertStatus.FALSE_POSITIVE
    assert dossier.anomaly_score < 0.35


def test_triage_escalate_apt():
    finding, events, baseline_store = generate_apt_attack_chain()
    bus = TelemetryBus()
    bus.publish_batch(events)

    triage = TriageAgent(baseline_store=baseline_store)
    dossier = triage.process(finding, bus)

    assert dossier.status == AlertStatus.TRIAGED_ESCALATED
    assert dossier.anomaly_score >= 0.50
    assert len(dossier.baseline_deviations) > 0
