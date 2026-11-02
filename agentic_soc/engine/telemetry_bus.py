"""OCSF Telemetry Bus for streaming ingestion and temporal queries."""

from __future__ import annotations
from typing import Dict, List, Optional
from ..models.ocsf import OCSFEvent, AuthenticationEvent, NetworkActivityEvent, FileActivityEvent, FindingEvent


class TelemetryBus:
    """Central event fabric ingesting normalized security events."""

    def __init__(self) -> None:
        self.events: List[OCSFEvent] = []
        self.findings: List[FindingEvent] = []

    def publish(self, event: OCSFEvent) -> None:
        self.events.append(event)
        if isinstance(event, FindingEvent):
            self.findings.append(event)

    def publish_batch(self, events: List[OCSFEvent]) -> None:
        for ev in events:
            self.publish(ev)

    def query_entity_events(self, entity_id: str) -> List[OCSFEvent]:
        """Queries all telemetry associated with a user, host, or IP."""
        matched: List[OCSFEvent] = []
        for ev in self.events:
            if isinstance(ev, AuthenticationEvent):
                if ev.principal == entity_id or ev.src_ip == entity_id or ev.src_hostname == entity_id:
                    matched.append(ev)
            elif isinstance(ev, NetworkActivityEvent):
                if ev.src_ip == entity_id or ev.dst_ip == entity_id:
                    matched.append(ev)
            elif isinstance(ev, FileActivityEvent):
                if ev.actor_user == entity_id or ev.actor_process_name == entity_id or entity_id in ev.file_path:
                    matched.append(ev)
            elif isinstance(ev, FindingEvent):
                if ev.entity_id == entity_id:
                    matched.append(ev)
        return matched

    def get_pending_findings(self) -> List[FindingEvent]:
        return list(self.findings)
