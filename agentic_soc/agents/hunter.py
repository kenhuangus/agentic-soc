"""Tier 3: Threat Hunting & Containment Agent (HunterAgent)."""

from __future__ import annotations
import uuid
from typing import List
from .base import SOCAgent
from ..models.incident import IncidentDossier, ContainmentAction, ActionSeverity, AlertStatus
from ..models.graph import AttackGraph, NodeType


class HunterAgent(SOCAgent):
    """Tier 3 Threat Hunter: Synthesizes threat vectors into surgical SOAR containment plans."""

    def __init__(self) -> None:
        super().__init__(name="HunterAgent", tier=3, role="Threat Hunting & Containment Formulation")

    def process(self, dossier: IncidentDossier, attack_graph: AttackGraph) -> List[ContainmentAction]:
        """Formulates targeted containment actions based on attack graph evidence."""
        self.logger.info(f"Formulating containment playbooks for incident {dossier.incident_id}")

        actions: List[ContainmentAction] = []

        # 1. Inspect compromised nodes in the attack graph
        for node in attack_graph.get_compromised_nodes():
            action_id = f"ACT-{uuid.uuid4().hex[:6].upper()}"

            if node.node_type == NodeType.PRINCIPAL:
                # Identity containment
                actions.append(ContainmentAction(
                    action_id=action_id,
                    target_entity=node.id,
                    target_type="user",
                    action_type="credential_revocation",
                    reason=f"Compromised credential identified in attack chain with {len(dossier.mitre_techniques)} MITRE techniques.",
                    severity=ActionSeverity.HIGH,
                    requires_hitl=True  # Identity revocation requires human oversight
                ))

            elif node.node_type == NodeType.HOST:
                # Endpoint isolation
                actions.append(ContainmentAction(
                    action_id=action_id,
                    target_entity=node.id,
                    target_type="host",
                    action_type="host_isolation",
                    reason=f"Host identified as active pivot or execution base in incident {dossier.incident_id}.",
                    severity=ActionSeverity.CRITICAL,
                    requires_hitl=True  # Production host isolation requires human dual-key authorization
                ))

            elif node.node_type == NodeType.IP_ENDPOINT:
                # Perimeter network block
                actions.append(ContainmentAction(
                    action_id=action_id,
                    target_entity=node.id,
                    target_type="ip",
                    action_type="firewall_block_ip",
                    reason=f"Active Command & Control (C2) destination detected in network flow telemetry.",
                    severity=ActionSeverity.MEDIUM,
                    requires_hitl=False  # Perimeter IP blocking is automated for high-confidence C2
                ))

            elif node.node_type == NodeType.PROCESS:
                # Local process termination
                actions.append(ContainmentAction(
                    action_id=action_id,
                    target_entity=node.label,
                    target_type="process",
                    action_type="process_kill",
                    reason=f"Malicious process active on host.",
                    severity=ActionSeverity.MEDIUM,
                    requires_hitl=False
                ))

        dossier.containment_actions = actions
        dossier.update_status(AlertStatus.CONTAINMENT_PROPOSED)

        self.logger.info(f"Formulated {len(actions)} containment actions ({sum(1 for a in actions if a.requires_hitl)} require HITL dual-key approval)")
        for a in actions:
            self.logger.info(f"  -> [{a.action_type}] on {a.target_entity} (Severity: {a.severity.value}, HITL: {a.requires_hitl})")

        return actions
