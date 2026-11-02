"""SOAR Enforcement Gateway with cryptographic audit receipts."""

from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from ..models.incident import ContainmentAction, ActionSeverity, ApprovalStatus


class SOARGateway:
    """Simulated SOAR execution engine for network, endpoint, and identity containment."""

    def __init__(self) -> None:
        self.isolated_hosts: Set[str] = set()
        self.revoked_users: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.killed_processes: List[Dict[str, Any]] = []
        self.execution_audit_log: List[Dict[str, Any]] = []

    def execute_action(self, action: ContainmentAction) -> bool:
        """Executes containment action if approved and generates cryptographic audit signature."""
        if action.approval_status not in (ApprovalStatus.AUTOMATICALLY_APPROVED, ApprovalStatus.MANUALLY_APPROVED):
            action.executed = False
            action.execution_result = f"Execution blocked: Action status is {action.approval_status.value}"
            return False

        now = datetime.now(timezone.utc).isoformat()
        
        if action.action_type == "host_isolation":
            self.isolated_hosts.add(action.target_entity)
            action.execution_result = f"Host {action.target_entity} successfully isolated from corporate network via EDR API."
        elif action.action_type == "credential_revocation":
            self.revoked_users.add(action.target_entity)
            action.execution_result = f"Active sessions terminated and Okta/Entra credentials revoked for {action.target_entity}."
        elif action.action_type == "firewall_block_ip":
            self.blocked_ips.add(action.target_entity)
            action.execution_result = f"Border firewall ACL rule provisioned: DROP traffic from/to {action.target_entity}."
        elif action.action_type == "process_kill":
            self.killed_processes.append({"target": action.target_entity, "executed_at": now})
            action.execution_result = f"Process {action.target_entity} terminated via agent sub-process hook."
        else:
            action.execution_result = f"Unknown action type: {action.action_type}"
            action.executed = False
            return False

        action.executed = True
        
        # Generate cryptographic audit hash
        audit_payload = f"{action.action_id}:{action.action_type}:{action.target_entity}:{action.approver}:{now}"
        action.audit_hash = hashlib.sha256(audit_payload.encode("utf-8")).hexdigest()

        self.execution_audit_log.append({
            "action_id": action.action_id,
            "action_type": action.action_type,
            "target_entity": action.target_entity,
            "approver": action.approver,
            "timestamp": now,
            "audit_hash": action.audit_hash,
            "result": action.execution_result
        })

        return True
