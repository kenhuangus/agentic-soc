import pytest
from agentic_soc.agents.triage import TriageAgent
from agentic_soc.agents.forensic import ForensicAgent
from agentic_soc.agents.hunter import HunterAgent
from agentic_soc.agents.supervisor import SOCSupervisor
from agentic_soc.scenarios.attack_chains import generate_apt_attack_chain
from agentic_soc.engine.telemetry_bus import TelemetryBus
from agentic_soc.engine.soar_gateway import SOARGateway
from agentic_soc.models.incident import ApprovalStatus, AlertStatus


def test_supervisor_governance_hitl_blocking():
    finding, events, baseline_store = generate_apt_attack_chain()
    bus = TelemetryBus()
    bus.publish_batch(events)

    triage = TriageAgent(baseline_store=baseline_store)
    dossier = triage.process(finding, bus)

    forensic = ForensicAgent()
    graph = forensic.process(dossier, bus)

    hunter = HunterAgent()
    hunter.process(dossier, graph)

    soar = SOARGateway()
    supervisor = SOCSupervisor(soar_gateway=soar)

    # Execute WITHOUT human dual-key authorization
    supervisor.process(dossier, auto_approve_hitl=False)

    # Critical actions must remain PENDING
    pending_actions = [a for a in dossier.containment_actions if a.requires_hitl]
    for action in pending_actions:
        assert action.approval_status == ApprovalStatus.PENDING
        assert action.executed is False

    # Low-risk actions must be automatically approved and executed
    auto_actions = [a for a in dossier.containment_actions if not a.requires_hitl]
    for action in auto_actions:
        assert action.approval_status == ApprovalStatus.AUTOMATICALLY_APPROVED
        assert action.executed is True
        assert action.audit_hash is not None


def test_supervisor_governance_hitl_granted():
    finding, events, baseline_store = generate_apt_attack_chain()
    bus = TelemetryBus()
    bus.publish_batch(events)

    triage = TriageAgent(baseline_store=baseline_store)
    dossier = triage.process(finding, bus)

    forensic = ForensicAgent()
    graph = forensic.process(dossier, bus)

    hunter = HunterAgent()
    hunter.process(dossier, graph)

    soar = SOARGateway()
    supervisor = SOCSupervisor(soar_gateway=soar)

    # Execute WITH human dual-key authorization
    supervisor.process(dossier, human_approver="Ken_Huang", auto_approve_hitl=True)

    assert dossier.status == AlertStatus.CONTAINED
    for action in dossier.containment_actions:
        assert action.executed is True
        assert action.audit_hash is not None
