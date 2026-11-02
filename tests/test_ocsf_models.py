import pytest
from agentic_soc.models.ocsf import (
    AuthenticationEvent,
    NetworkActivityEvent,
    FileActivityEvent,
    FindingEvent,
    OCSFEventCategory,
    OCSFSeverity,
)
from agentic_soc.models.graph import AttackGraph, NodeType, EdgeType


def test_authentication_event_creation():
    event = AuthenticationEvent(
        event_id="EVT-01",
        principal="alice",
        src_ip="10.0.0.1",
        status="success"
    )
    assert event.category == OCSFEventCategory.AUTHENTICATION
    assert event.principal == "alice"
    assert event.status == "success"


def test_attack_graph_blast_radius():
    graph = AttackGraph(incident_id="INC-TEST-01")
    graph.add_node("user_1", NodeType.PRINCIPAL, "Alice", risk_weight=2.0, compromised=True)
    graph.add_node("host_1", NodeType.HOST, "WORKSTATION", risk_weight=3.0, compromised=True)
    graph.add_edge("user_1", "host_1", EdgeType.AUTHENTICATED_TO, "2026-11-01T20:00:00Z")

    blast = graph.calculate_blast_radius()
    assert blast > 0.0
    assert len(graph.get_compromised_nodes()) == 2
