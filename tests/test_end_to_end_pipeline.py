import pytest
from agentic_soc.pipeline import SOCPipeline
from agentic_soc.scenarios.attack_chains import generate_false_positive_scenario, generate_apt_attack_chain
from agentic_soc.models.incident import AlertStatus


def test_pipeline_false_positive_short_circuit():
    finding, events, baseline_store = generate_false_positive_scenario()
    pipeline = SOCPipeline(baseline_store=baseline_store)
    pipeline.telemetry_bus.publish_batch(events)

    dossier = pipeline.process_incident(finding)
    assert dossier.status == AlertStatus.FALSE_POSITIVE
    assert len(dossier.containment_actions) == 0


def test_pipeline_full_apt_containment():
    finding, events, baseline_store = generate_apt_attack_chain()
    pipeline = SOCPipeline(baseline_store=baseline_store)
    pipeline.telemetry_bus.publish_batch(events)

    dossier = pipeline.process_incident(
        finding,
        human_approver="Ken_Huang",
        auto_approve_hitl=True
    )
    assert dossier.status == AlertStatus.CONTAINED
    assert dossier.blast_radius_score > 0
    assert len(dossier.containment_actions) >= 3
    assert len(pipeline.soar_gateway.execution_audit_log) >= 3
