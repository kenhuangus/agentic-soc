"""Tier 2: Forensic Investigation Agent (ForensicAgent)."""

from __future__ import annotations
from typing import Dict, List, Set, Tuple
from .base import SOCAgent
from ..models.ocsf import AuthenticationEvent, FileActivityEvent, NetworkActivityEvent, OCSFEvent
from ..models.incident import IncidentDossier, AlertStatus
from ..models.graph import AttackGraph, NodeType, EdgeType
from ..engine.telemetry_bus import TelemetryBus


class ForensicAgent(SOCAgent):
    """Tier 2 Forensic Investigator: Constructs causal attack graphs, maps MITRE ATT&CK tactics, and evaluates blast radius."""

    def __init__(self) -> None:
        super().__init__(name="ForensicAgent", tier=2, role="Forensic Investigation & Attack Graph Synthesis")

    def process(self, dossier: IncidentDossier, telemetry_bus: TelemetryBus) -> AttackGraph:
        """Constructs an attack provenance graph from dossier evidence and surrounding telemetry."""
        self.logger.info(f"Initiating forensic investigation for incident {dossier.incident_id} (Entity: {dossier.entity_id})")

        graph = AttackGraph(incident_id=dossier.incident_id)
        mitre_detected: Set[str] = set(dossier.mitre_techniques)

        # 1. Add primary compromised entity node
        primary_node_type = NodeType.PRINCIPAL if dossier.entity_type == "user" else NodeType.HOST
        graph.add_node(
            node_id=dossier.entity_id,
            node_type=primary_node_type,
            label=f"Initial Target ({dossier.entity_id})",
            risk_weight=2.5,
            compromised=True
        )

        # 2. Iterate through telemetry to discover lateral movement, process lineage, and C2 channels
        all_related_events = telemetry_bus.query_entity_events(dossier.entity_id)
        # Also query events for any connected hosts discovered during traversal
        expanded_events: List[OCSFEvent] = list(all_related_events)

        for ev in all_related_events:
            if isinstance(ev, AuthenticationEvent):
                # Map source IP/host and destination host
                src_id = ev.src_hostname or ev.src_ip
                dst_id = ev.dst_endpoint

                graph.add_node(node_id=src_id, node_type=NodeType.HOST if not ev.src_ip else NodeType.IP_ENDPOINT, label=src_id, risk_weight=1.5, compromised=True)
                graph.add_node(node_id=dst_id, node_type=NodeType.HOST, label=dst_id, risk_weight=2.0, compromised=(ev.status == "success"))

                graph.add_edge(
                    source_id=ev.principal,
                    target_id=dst_id,
                    edge_type=EdgeType.AUTHENTICATED_TO,
                    timestamp=ev.timestamp,
                    evidence_event_id=ev.event_id,
                    description=f"Logon via {ev.auth_protocol} ({ev.status})"
                )

                if ev.status == "success" and ev.src_geo_country and ev.src_geo_country not in ["US", "CA"]:
                    mitre_detected.add("T1078")  # Valid Accounts

            elif isinstance(ev, NetworkActivityEvent):
                c2_ip = ev.dst_ip
                graph.add_node(node_id=c2_ip, node_type=NodeType.IP_ENDPOINT, label=f"External Endpoint ({c2_ip})", risk_weight=3.0, compromised=True)
                graph.add_edge(
                    source_id=ev.src_ip,
                    target_id=c2_ip,
                    edge_type=EdgeType.CONNECTED_TO,
                    timestamp=ev.timestamp,
                    evidence_event_id=ev.event_id,
                    description=f"Outbound {ev.protocol} connection to {c2_ip}:{ev.dst_port} ({ev.bytes_sent} bytes)"
                )
                mitre_detected.add("T1071.001")  # Application Layer Protocol: Web Protocols

            elif isinstance(ev, FileActivityEvent):
                proc_id = f"proc-{ev.actor_pid}-{ev.actor_process_name}"
                file_id = f"file-{ev.file_name}"

                graph.add_node(node_id=proc_id, node_type=NodeType.PROCESS, label=ev.actor_process_name, risk_weight=2.0, compromised=True)
                graph.add_node(node_id=file_id, node_type=NodeType.FILE, label=ev.file_name, risk_weight=1.8, compromised=True)

                graph.add_edge(
                    source_id=proc_id,
                    target_id=file_id,
                    edge_type=EdgeType.WROTE_FILE if ev.action in ("create", "modify") else EdgeType.SPAWNED_PROCESS,
                    timestamp=ev.timestamp,
                    evidence_event_id=ev.event_id,
                    description=f"{ev.action.upper()} {ev.file_path}"
                )

                # MITRE detection
                cmd = ev.actor_command_line.lower()
                if "powershell" in ev.actor_process_name.lower():
                    mitre_detected.add("T1059.001")  # PowerShell
                if "mimikatz" in cmd or "sekurlsa" in cmd or "lsass" in cmd:
                    mitre_detected.add("T1003.001")  # OS Credential Dumping: LSASS
                if "vssadmin" in cmd or "delete shadows" in cmd:
                    mitre_detected.add("T1490")      # Inhibit System Recovery

        # 3. Compute blast radius
        blast_score = graph.calculate_blast_radius()
        dossier.blast_radius_score = blast_score
        dossier.mitre_techniques = sorted(list(mitre_detected))
        dossier.update_status(AlertStatus.INVESTIGATING)

        self.logger.info(f"Reconstructed Attack Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges. Blast Radius: {blast_score}/10.0")
        self.logger.info(f"Mapped MITRE ATT&CK Techniques: {', '.join(dossier.mitre_techniques)}")

        return graph
