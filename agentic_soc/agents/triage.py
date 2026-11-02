"""Tier 1: Triage and Correlation Agent (TriageAgent)."""

from __future__ import annotations
import uuid
from typing import List, Optional, Tuple
from .base import SOCAgent
from ..models.ocsf import FindingEvent, AuthenticationEvent, FileActivityEvent, NetworkActivityEvent, OCSFEvent
from ..models.incident import IncidentDossier, AlertStatus
from ..engine.telemetry_bus import TelemetryBus
from ..engine.baseline import EntityBaselineStore


class TriageAgent(SOCAgent):
    """Tier 1 Analyst: Evaluates incoming alerts against behavioral baselines, filters false positives, and escalates true anomalies."""

    def __init__(self, baseline_store: Optional[EntityBaselineStore] = None) -> None:
        super().__init__(name="TriageAgent", tier=1, role="Alert Triage & Correlation")
        self.baseline_store = baseline_store or EntityBaselineStore()

    def process(self, finding: FindingEvent, telemetry_bus: TelemetryBus) -> IncidentDossier:
        """Processes a security finding event."""
        self.logger.info(f"Ingesting finding {finding.finding_id}: '{finding.rule_name}' for entity '{finding.entity_id}'")

        # Query surrounding telemetry
        related_events = telemetry_bus.query_entity_events(finding.entity_id)

        # Baseline evaluation
        deviations: List[str] = []
        anomaly_scores: List[float] = [finding.confidence_score * 0.5]

        for ev in related_events:
            if isinstance(ev, AuthenticationEvent):
                score, dev = self.baseline_store.evaluate_auth_deviation(ev)
                anomaly_scores.append(score)
                deviations.extend(dev)
            elif isinstance(ev, FileActivityEvent):
                score, dev = self.baseline_store.evaluate_host_deviation(ev)
                anomaly_scores.append(score)
                deviations.extend(dev)

        aggregate_anomaly = min(round(sum(anomaly_scores) / max(len(anomaly_scores), 1) + (len(deviations) * 0.15), 2), 1.0)

        # Triage Decision Gate: False Positive vs Escalation
        dossier_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        
        if aggregate_anomaly < 0.35 and len(deviations) == 0:
            self.logger.info(f"Auto-resolving finding {finding.finding_id} as FALSE_POSITIVE (Score: {aggregate_anomaly})")
            dossier = IncidentDossier(
                incident_id=dossier_id,
                title=f"False Positive: {finding.rule_name} on {finding.entity_id}",
                summary=f"Automated baseline evaluation detected zero high-confidence deviations. Activity matches known patterns.",
                initial_finding=finding,
                entity_id=finding.entity_id,
                entity_type=finding.entity_type,
                anomaly_score=aggregate_anomaly,
                baseline_deviations=["Activity within standard baseline bounds"],
                evidence_events=related_events,
                status=AlertStatus.FALSE_POSITIVE
            )
        else:
            self.logger.warning(f"ESCALATING finding {finding.finding_id} to Tier 2 (Score: {aggregate_anomaly}, Deviations: {len(deviations)})")
            dossier = IncidentDossier(
                incident_id=dossier_id,
                title=f"Security Incident: {finding.rule_name} involving {finding.entity_id}",
                summary=f"Confirmed anomalous activity with {len(deviations)} baseline violations.",
                initial_finding=finding,
                entity_id=finding.entity_id,
                entity_type=finding.entity_type,
                anomaly_score=aggregate_anomaly,
                baseline_deviations=deviations,
                evidence_events=related_events,
                mitre_techniques=[finding.mitre_technique_id] if finding.mitre_technique_id else [],
                status=AlertStatus.TRIAGED_ESCALATED
            )

        return dossier
