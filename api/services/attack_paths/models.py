"""Data models for attack path analysis."""

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    """Types of nodes in attack graph."""
    ENTRY_POINT = "entry_point"
    VULNERABILITY = "vulnerability"
    CAPABILITY = "capability"
    TARGET = "target"


class Exploitability(str, Enum):
    """Exploitability levels for attack paths."""
    CONFIRMED = "confirmed"         # PoC available, easily reproducible
    EASY = "easy"                   # Low skill required
    MODERATE = "moderate"           # Some skill/tools required
    DIFFICULT = "difficult"         # High skill/specific conditions
    THEORETICAL = "theoretical"     # Possible but not demonstrated


@dataclass
class AttackNode:
    """A node in the attack graph representing a finding or capability."""

    node_id: str
    node_type: NodeType
    title: str
    severity: str
    category: str
    finding_id: str | None = None
    description: str | None = None
    in_edges: list["AttackEdge"] = field(default_factory=list)
    out_edges: list["AttackEdge"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "finding_id": self.finding_id,
            "description": self.description,
        }


@dataclass
class AttackEdge:
    """An edge in the attack graph connecting nodes."""

    edge_id: str
    source_id: str
    target_id: str
    edge_type: str
    exploitability: Exploitability
    confidence: float  # 0.0 - 1.0
    requires_physical: bool = False
    requires_network: bool = False
    poc_command: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "exploitability": self.exploitability.value,
            "confidence": self.confidence,
            "requires_physical": self.requires_physical,
            "requires_network": self.requires_network,
            "poc_command": self.poc_command,
            "mitre_techniques": self.mitre_techniques,
            "description": self.description,
        }


@dataclass
class AttackPath:
    """A complete attack path from entry point to target."""

    path_id: str
    name: str
    description: str
    attack_vector: str
    nodes: list[AttackNode]
    edges: list[AttackEdge]

    # Risk assessment
    combined_risk_score: Decimal
    exploitability: Exploitability
    confidence: float  # Combined path confidence

    # Impact scores (0-100)
    impact_confidentiality: int
    impact_integrity: int
    impact_availability: int

    # Requirements
    requires_physical_access: bool
    requires_network_position: bool
    skill_level_required: str  # novice, intermediate, advanced, expert

    # MITRE ATT&CK mapping
    mitre_techniques: list[str] = field(default_factory=list)

    # Exploitation guide
    exploitation_steps: list[dict[str, Any]] = field(default_factory=list)
    poc_commands: list[dict[str, Any]] = field(default_factory=list)

    # Finding chain for backward compatibility
    finding_chain: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "path_id": self.path_id,
            "name": self.name,
            "description": self.description,
            "attack_vector": self.attack_vector,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "combined_risk_score": float(self.combined_risk_score),
            "exploitability": self.exploitability.value,
            "confidence": self.confidence,
            "impact_confidentiality": self.impact_confidentiality,
            "impact_integrity": self.impact_integrity,
            "impact_availability": self.impact_availability,
            "requires_physical_access": self.requires_physical_access,
            "requires_network_position": self.requires_network_position,
            "skill_level_required": self.skill_level_required,
            "mitre_techniques": self.mitre_techniques,
            "exploitation_steps": self.exploitation_steps,
            "poc_commands": self.poc_commands,
            "finding_chain": self.finding_chain,
        }
