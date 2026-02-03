"""Attack path generator - main orchestrator."""

import hashlib
import logging
from decimal import Decimal
from typing import Any
from uuid import uuid4

from api.models.database import Finding
from api.services.attack_paths.graph_builder import AttackGraphBuilder
from api.services.attack_paths.pathfinder import AttackPathfinder
from api.services.attack_paths.impact_assessor import ImpactAssessor
from api.services.attack_paths.models import (
    AttackPath,
    AttackNode,
    AttackEdge,
    Exploitability,
    NodeType,
)

logger = logging.getLogger(__name__)


class AttackPathGenerator:
    """Generates attack paths from findings.

    This is the main class that orchestrates the attack path generation process:
    1. Build graph from findings
    2. Find paths from entry points to targets
    3. Assess impact and risk
    4. Generate exploitation guides
    """

    def __init__(self, findings: list[Finding]):
        """Initialize with findings.

        Args:
            findings: List of Finding objects from a scan
        """
        self.findings = findings
        self.graph_builder = AttackGraphBuilder(findings)
        self.impact_assessor = ImpactAssessor()

        # Will be set after build
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []
        self.pathfinder: AttackPathfinder | None = None

    def generate_paths(
        self,
        max_paths: int = 20,
        max_depth: int = 10,
        min_confidence: float = 0.3,
        package_name: str = "com.example.app",
    ) -> list[AttackPath]:
        """Generate attack paths from findings.

        Args:
            max_paths: Maximum number of paths to return
            max_depth: Maximum path length
            min_confidence: Minimum path confidence threshold
            package_name: Target app package name for PoC commands

        Returns:
            List of AttackPath objects sorted by risk
        """
        # Build the graph
        self.nodes, self.edges = self.graph_builder.build()
        self.pathfinder = AttackPathfinder(self.nodes, self.edges)

        # Get entry points and targets
        entry_points = self.graph_builder.get_entry_points()
        targets = self.graph_builder.get_targets()

        if not entry_points:
            logger.info("No entry points found - no attack paths possible")
            return []

        # Find all paths
        raw_paths = self.pathfinder.find_all_paths(
            entry_points,
            targets,
            max_depth=max_depth,
            min_confidence=min_confidence,
        )

        # Convert to AttackPath objects
        attack_paths: list[AttackPath] = []
        for raw_path in raw_paths:
            attack_path = self._create_attack_path(raw_path, package_name)
            if attack_path:
                attack_paths.append(attack_path)

        # Sort by risk score (descending)
        attack_paths.sort(key=lambda p: p.combined_risk_score, reverse=True)

        # Deduplicate similar paths
        unique_paths = self._deduplicate_paths(attack_paths)

        # Limit to max_paths
        result = unique_paths[:max_paths]

        logger.info(f"Generated {len(result)} attack paths")
        return result

    def _create_attack_path(
        self,
        raw_path: list[tuple[AttackNode, AttackEdge | None]],
        package_name: str,
    ) -> AttackPath | None:
        """Create an AttackPath from a raw path.

        Args:
            raw_path: List of (node, edge_to_next) tuples
            package_name: Target app package name

        Returns:
            AttackPath object or None if invalid
        """
        if len(raw_path) < 2:
            return None

        # Extract nodes and edges
        nodes = [node for node, _ in raw_path]
        edges = [edge for _, edge in raw_path if edge]

        # Calculate path metrics
        confidence = self.pathfinder.calculate_path_confidence(raw_path) if self.pathfinder else 0.5
        exploitability = self.pathfinder.determine_path_exploitability(raw_path) if self.pathfinder else Exploitability.MODERATE
        requirements = self.pathfinder.get_path_requirements(raw_path) if self.pathfinder else {}
        mitre_techniques = self.pathfinder.get_path_mitre_techniques(raw_path) if self.pathfinder else []

        # Calculate impact
        impact = self.impact_assessor.assess_path_impact(raw_path)
        risk_score = self.impact_assessor.calculate_risk_score(raw_path, confidence, impact)
        skill_level = self.impact_assessor.determine_skill_level(raw_path)

        # Generate exploitation guide
        exploitation_steps = self.impact_assessor.generate_exploitation_steps(raw_path, package_name)
        poc_commands = self.impact_assessor.collect_poc_commands(raw_path, package_name)

        # Generate path name and description
        entry_node = nodes[0]
        target_node = nodes[-1]
        path_name = f"{entry_node.title} to {target_node.title}"
        path_description = self._generate_path_description(nodes, edges)

        # Determine attack vector
        attack_vector = self._determine_attack_vector(entry_node, requirements)

        # Create finding chain for backward compatibility
        finding_chain = [n.finding_id for n in nodes if n.finding_id]

        # Generate unique path ID
        path_id = hashlib.sha256(
            f"{':'.join(finding_chain)}:{target_node.node_id}".encode()
        ).hexdigest()[:16]

        return AttackPath(
            path_id=path_id,
            name=path_name,
            description=path_description,
            attack_vector=attack_vector,
            nodes=nodes,
            edges=edges,
            combined_risk_score=Decimal(str(risk_score)),
            exploitability=exploitability,
            confidence=confidence,
            impact_confidentiality=impact["impact_confidentiality"],
            impact_integrity=impact["impact_integrity"],
            impact_availability=impact["impact_availability"],
            requires_physical_access=requirements.get("requires_physical_access", False),
            requires_network_position=requirements.get("requires_network_position", False),
            skill_level_required=skill_level,
            mitre_techniques=mitre_techniques,
            exploitation_steps=exploitation_steps,
            poc_commands=poc_commands,
            finding_chain=finding_chain,
        )

    def _generate_path_description(
        self,
        nodes: list[AttackNode],
        edges: list[AttackEdge],
    ) -> str:
        """Generate human-readable path description."""
        if len(nodes) < 2:
            return "Invalid path"

        parts = []

        # Entry point
        entry = nodes[0]
        parts.append(f"Starting from {entry.title}")

        # Intermediate steps
        for i, node in enumerate(nodes[1:-1], 1):
            if i - 1 < len(edges) and edges[i - 1]:
                edge = edges[i - 1]
                parts.append(f"use {edge.edge_type or 'vulnerability'} to reach {node.title}")
            else:
                parts.append(f"proceed to {node.title}")

        # Target
        target = nodes[-1]
        parts.append(f"ultimately achieving {target.title}")

        return ", ".join(parts) + "."

    def _determine_attack_vector(
        self,
        entry_node: AttackNode,
        requirements: dict[str, bool],
    ) -> str:
        """Determine the attack vector type."""
        if requirements.get("requires_physical_access"):
            return "local"
        if requirements.get("requires_network_position"):
            return "network"

        category = entry_node.category.lower()
        if "network" in category:
            return "network"
        if "component" in category or "ipc" in category:
            return "local_app"
        if "webview" in category or "deep link" in category:
            return "remote"

        return "local"

    def _deduplicate_paths(
        self,
        paths: list[AttackPath],
    ) -> list[AttackPath]:
        """Remove duplicate or very similar paths."""
        seen_signatures: set[str] = set()
        unique_paths: list[AttackPath] = []

        for path in paths:
            # Create signature from finding chain and target
            signature = ":".join(path.finding_chain) + ":" + path.nodes[-1].node_id

            if signature not in seen_signatures:
                seen_signatures.add(signature)
                unique_paths.append(path)

        return unique_paths

    def get_graph_stats(self) -> dict[str, Any]:
        """Get statistics about the generated graph."""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "entry_points": len(self.graph_builder.get_entry_points()),
            "targets": len(self.graph_builder.get_targets()),
            "findings_count": len(self.findings),
        }

    def to_dict(self) -> dict[str, Any]:
        """Export graph as dictionary for serialization."""
        return {
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "stats": self.get_graph_stats(),
        }
