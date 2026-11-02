"""Forensic attack graph representation and blast-radius analysis."""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    PRINCIPAL = "PRINCIPAL"
    HOST = "HOST"
    PROCESS = "PROCESS"
    FILE = "FILE"
    IP_ENDPOINT = "IP_ENDPOINT"
    CREDENTIAL = "CREDENTIAL"


class EdgeType(str, Enum):
    AUTHENTICATED_TO = "AUTHENTICATED_TO"
    SPAWNED_PROCESS = "SPAWNED_PROCESS"
    WROTE_FILE = "WROTE_FILE"
    CONNECTED_TO = "CONNECTED_TO"
    ACCESSED_CREDENTIAL = "ACCESSED_CREDENTIAL"
    LATERAL_PIVOT = "LATERAL_PIVOT"


class GraphNode(BaseModel):
    id: str
    node_type: NodeType
    label: str
    risk_weight: float = 1.0
    attributes: Dict[str, Any] = Field(default_factory=dict)
    compromised: bool = False


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    edge_type: EdgeType
    timestamp: str
    evidence_event_id: Optional[str] = None
    description: str = ""


class AttackGraph(BaseModel):
    """Dynamic provenance graph reconstructed by ForensicAgent."""
    incident_id: str
    nodes: Dict[str, GraphNode] = Field(default_factory=dict)
    edges: List[GraphEdge] = Field(default_factory=list)

    def add_node(self, node_id: str, node_type: NodeType, label: str, risk_weight: float = 1.0, attributes: Optional[Dict[str, Any]] = None, compromised: bool = False) -> GraphNode:
        if node_id not in self.nodes:
            node = GraphNode(
                id=node_id,
                node_type=node_type,
                label=label,
                risk_weight=risk_weight,
                attributes=attributes or {},
                compromised=compromised
            )
            self.nodes[node_id] = node
        else:
            if compromised:
                self.nodes[node_id].compromised = True
        return self.nodes[node_id]

    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType, timestamp: str, evidence_event_id: Optional[str] = None, description: str = "") -> GraphEdge:
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            timestamp=timestamp,
            evidence_event_id=evidence_event_id,
            description=description
        )
        self.edges.append(edge)
        return edge

    def get_neighbors(self, node_id: str) -> List[str]:
        neighbors: Set[str] = set()
        for edge in self.edges:
            if edge.source_id == node_id:
                neighbors.add(edge.target_id)
            elif edge.target_id == node_id:
                neighbors.add(edge.source_id)
        return list(neighbors)

    def calculate_blast_radius(self) -> float:
        """Calculates normalized blast radius score (0.0 to 10.0)."""
        if not self.nodes:
            return 0.0
        
        compromised_count = sum(1 for n in self.nodes.values() if n.compromised)
        total_risk = sum(n.risk_weight for n in self.nodes.values() if n.compromised)
        edge_multiplier = 1.0 + (len(self.edges) * 0.1)
        
        score = (compromised_count * 1.5 + total_risk) * edge_multiplier
        return min(round(score, 2), 10.0)

    def get_compromised_nodes(self) -> List[GraphNode]:
        return [n for n in self.nodes.values() if n.compromised]

    def render_summary(self) -> str:
        lines = [
            f"Attack Graph Summary for Incident {self.incident_id}:",
            f"- Total Nodes: {len(self.nodes)} ({sum(1 for n in self.nodes.values() if n.compromised)} Compromised)",
            f"- Total Edges: {len(self.edges)}",
            f"- Blast Radius Score: {self.calculate_blast_radius()}/10.0",
            "Compromised Entities:"
        ]
        for node in self.get_compromised_nodes():
            lines.append(f"  * [{node.node_type.value}] {node.label} (ID: {node.id}, Risk: {node.risk_weight})")
        lines.append("Attack Path Transitions:")
        for edge in self.edges:
            lines.append(f"  * {edge.source_id} --[{edge.edge_type.value}]--> {edge.target_id} ({edge.description})")
        return "\n".join(lines)
