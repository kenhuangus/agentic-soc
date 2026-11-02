"""Tier 4: Governance and Policy Enforcement Supervisor (SOCSupervisor)."""

from __future__ import annotations
from typing import Dict, List, Optional
from .base import SOCAgent
from ..models.incident import IncidentDossier, ContainmentAction, ApprovalStatus, AlertStatus, ActionSeverity
from ..engine.soar_gateway import SOARGateway


class SOCSupervisor(SOCAgent):
    """Tier 4 Supervisor: Evaluates proposed containment actions against OWASP AIVSS governance policies and enforces HITL dual-key approval gates."""

    def __init__(self, soar_gateway: Optional[SOARGateway] = None) -> None:
        super().__init__(name="SOCSupervisor", tier=4, role="Policy Governance & Dual-Key Approval Gateway")
        self.soar_gateway = soar_gateway or SOARGateway()

    def process(
        self,
        dossier: IncidentDossier,
        human_approver: Optional[str] = None,
        auto_approve_hitl: bool = False
    ) -> List[ContainmentAction]:
        """Applies policy gates to proposed actions and coordinates execution through SOAR."""
        self.logger.info(f"Enforcing governance policy and approval gates for incident {dossier.incident_id}")

        executed_actions: List[ContainmentAction] = []

        for action in dossier.containment_actions:
            # Policy Rule 1: Automated Low/Medium Severity Actions
            if not action.requires_hitl:
                action.approval_status = ApprovalStatus.AUTOMATICALLY_APPROVED
                action.approver = "SOC_POLICY_AUTOMATION"
                self.logger.info(f"Auto-approved low-risk action {action.action_id} ({action.action_type} on {action.target_entity})")
                self.soar_gateway.execute_action(action)
                executed_actions.append(action)

            # Policy Rule 2: High/Critical Severity Actions Requiring Dual-Key HITL
            else:
                if auto_approve_hitl or human_approver:
                    action.approval_status = ApprovalStatus.MANUALLY_APPROVED
                    action.approver = human_approver or "HUMAN_SOC_LEAD"
                    self.logger.warning(f"Dual-key authorization GRANTED by {action.approver} for action {action.action_id} ({action.action_type} on {action.target_entity})")
                    self.soar_gateway.execute_action(action)
                    executed_actions.append(action)
                else:
                    action.approval_status = ApprovalStatus.PENDING
                    self.logger.warning(f"ACTION PAUSED: Action {action.action_id} ({action.action_type} on {action.target_entity}) REQUIRES HUMAN APPROVAL.")

        # Update dossier status
        all_executed = all(a.executed for a in dossier.containment_actions)
        any_executed = any(a.executed for a in dossier.containment_actions)

        if all_executed:
            dossier.update_status(AlertStatus.CONTAINED)
        elif any_executed:
            dossier.update_status(AlertStatus.CONTAINMENT_PROPOSED)

        return dossier.containment_actions
