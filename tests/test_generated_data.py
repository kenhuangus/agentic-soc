import pytest
from agentic_soc.engine.data_generator import SyntheticTelemetryGenerator
from agentic_soc.pipeline import SOCPipeline
from agentic_soc.models.incident import AlertStatus


def test_synthetic_data_generation_volume():
    generator = SyntheticTelemetryGenerator(seed=123)
    findings, events, baseline_store = generator.generate_attack_dataset(
        num_benign=100,
        include_apt=True
    )

    assert len(findings) == 1
    assert len(events) >= 103
    assert len(baseline_store.user_baselines) >= 5


def test_pipeline_on_synthetic_generated_telemetry():
    generator = SyntheticTelemetryGenerator(seed=456)
    findings, events, baseline_store = generator.generate_attack_dataset(
        num_benign=80,
        include_apt=True,
        inject_prompt_injection=True
    )

    pipeline = SOCPipeline(baseline_store=baseline_store)
    pipeline.telemetry_bus.publish_batch(events)

    # Process finding through Tiers 1-4
    finding = findings[0]
    dossier = pipeline.process_incident(
        finding=finding,
        human_approver="Ken_Huang_SOC_Lead",
        auto_approve_hitl=True
    )

    # Verify complete containment and forensic graph reconstruction
    assert dossier.status == AlertStatus.CONTAINED
    assert dossier.anomaly_score >= 0.70
    assert dossier.blast_radius_score > 0
    assert len(dossier.containment_actions) >= 3

    # Verify tool calls are serialized in supervisor transcript
    transcript = pipeline.supervisor_agent.get_transcript(
        user_input=finding.description,
        agent_output=dossier.summary
    )
    assert len(transcript["tool_calls"]) >= 3
    assert transcript["canary_leak_detected"] is False
