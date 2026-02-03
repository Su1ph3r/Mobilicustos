"""Build attack graph from findings."""

import hashlib
import logging
from typing import Any

from api.models.database import Finding
from api.services.attack_paths.edge_definitions import (
    EDGE_DEFINITIONS,
    ENTRY_POINT_TYPES,
    TARGET_TYPES,
    get_edge_for_finding,
)
from api.services.attack_paths.models import (
    AttackEdge,
    AttackNode,
    Exploitability,
    NodeType,
)

logger = logging.getLogger(__name__)


class AttackGraphBuilder:
    """Builds attack graph from findings."""

    def __init__(self, findings: list[Finding]):
        """Initialize with findings.

        Args:
            findings: List of Finding objects to build graph from
        """
        self.findings = findings
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []
        self.entry_points: list[AttackNode] = []
        self.targets: list[AttackNode] = []

    def build(self) -> tuple[dict[str, AttackNode], list[AttackEdge]]:
        """Build the attack graph.

        Returns:
            Tuple of (nodes dict, edges list)
        """
        # Create nodes from findings
        self._create_finding_nodes()

        # Create target nodes
        self._create_target_nodes()

        # Create edges between nodes
        self._create_edges()

        logger.info(
            f"Built attack graph with {len(self.nodes)} nodes and {len(self.edges)} edges"
        )

        return self.nodes, self.edges

    def _create_finding_nodes(self) -> None:
        """Create nodes from findings."""
        for finding in self.findings:
            node_id = f"finding_{finding.finding_id}"

            # Determine node type
            edge_matches = get_edge_for_finding(
                finding.title or "",
                finding.category or "",
                finding.severity,
            )

            # Check if this finding is an entry point
            is_entry_point = any(
                edge.get("entry_point_type") is not None
                for edge in edge_matches
            )

            node_type = NodeType.ENTRY_POINT if is_entry_point else NodeType.VULNERABILITY

            node = AttackNode(
                node_id=node_id,
                node_type=node_type,
                title=finding.title or "Unknown",
                severity=finding.severity,
                category=finding.category or "Unknown",
                finding_id=finding.finding_id,
                description=finding.description,
            )

            self.nodes[node_id] = node

            if is_entry_point:
                self.entry_points.append(node)

    def _create_target_nodes(self) -> None:
        """Create target nodes for attack objectives."""
        for target_id, target_info in TARGET_TYPES.items():
            node_id = f"target_{target_id}"
            node = AttackNode(
                node_id=node_id,
                node_type=NodeType.TARGET,
                title=target_info["name"],
                severity="critical",
                category="Attack Target",
                description=f"Attack objective: {target_info['name']}",
            )
            self.nodes[node_id] = node
            self.targets.append(node)

    def _create_edges(self) -> None:
        """Create edges between nodes based on edge definitions."""
        edge_count = 0

        for node_id, node in self.nodes.items():
            if node.node_type == NodeType.TARGET:
                continue

            # Get the finding for this node
            finding = self._get_finding_for_node(node)
            if not finding:
                continue

            # Find matching edge definitions
            edge_matches = get_edge_for_finding(
                finding.title or "",
                finding.category or "",
                finding.severity,
            )

            for edge_def in edge_matches:
                # Create edges to targets
                for target_type in edge_def.get("target_types", []):
                    target_node_id = f"target_{target_type}"
                    if target_node_id in self.nodes:
                        edge = self._create_edge(
                            node_id,
                            target_node_id,
                            edge_def,
                            finding,
                        )
                        self.edges.append(edge)
                        edge_count += 1

                # Create edges to capability nodes (other findings that enable)
                for enabled_cap in edge_def.get("enables", []):
                    self._create_capability_edges(node_id, enabled_cap, edge_def)

        logger.debug(f"Created {edge_count} edges to targets")

    def _create_edge(
        self,
        source_id: str,
        target_id: str,
        edge_def: dict[str, Any],
        finding: Finding,
    ) -> AttackEdge:
        """Create an edge between two nodes."""
        edge_id = hashlib.sha256(
            f"{source_id}:{target_id}:{edge_def.get('edge_id', '')}".encode()
        ).hexdigest()[:16]

        # Parse exploitability
        exploitability_str = edge_def.get("exploitability", "moderate")
        try:
            exploitability = Exploitability(exploitability_str)
        except ValueError:
            exploitability = Exploitability.MODERATE

        # Generate PoC command if template exists
        poc_command = None
        if edge_def.get("poc_template") and finding:
            poc_command = edge_def["poc_template"].format(
                package_name=getattr(finding, "app_id", "com.example"),
                component_name=self._extract_component_name(finding),
            )

        return AttackEdge(
            edge_id=edge_id,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_def.get("edge_id", "unknown"),
            exploitability=exploitability,
            confidence=edge_def.get("confidence", 0.5),
            requires_physical=edge_def.get("requires_physical", False),
            requires_network=edge_def.get("requires_network", False),
            poc_command=poc_command,
            mitre_techniques=edge_def.get("mitre_mobile", []),
            description=edge_def.get("description"),
        )

    def _create_capability_edges(
        self,
        source_id: str,
        capability: str,
        edge_def: dict[str, Any],
    ) -> None:
        """Create edges from capabilities to other findings that benefit."""
        # Find findings that could benefit from this capability
        for node_id, node in self.nodes.items():
            if node_id == source_id or node.node_type == NodeType.TARGET:
                continue

            finding = self._get_finding_for_node(node)
            if not finding:
                continue

            # Check if this finding could use the capability
            title_lower = (finding.title or "").lower()
            if capability in title_lower or self._capability_matches(capability, finding):
                edge = AttackEdge(
                    edge_id=hashlib.sha256(
                        f"{source_id}:{node_id}:cap:{capability}".encode()
                    ).hexdigest()[:16],
                    source_id=source_id,
                    target_id=node_id,
                    edge_type=f"enables_{capability}",
                    exploitability=Exploitability.MODERATE,
                    confidence=0.5,
                    description=f"Enables {capability}",
                )
                self.edges.append(edge)

    def _capability_matches(self, capability: str, finding: Finding) -> bool:
        """Check if a finding can use a capability."""
        cap_to_category = {
            "data_access": ["Data Protection", "Storage"],
            "credential_extraction": ["Secrets", "Authentication"],
            "network_interception": ["Network Security"],
            "code_execution": ["WebView", "Injection"],
            "debug_access": ["Configuration"],
        }

        matching_categories = cap_to_category.get(capability, [])
        return any(
            cat.lower() in (finding.category or "").lower()
            for cat in matching_categories
        )

    def _get_finding_for_node(self, node: AttackNode) -> Finding | None:
        """Get the Finding object for a node."""
        if not node.finding_id:
            return None

        for finding in self.findings:
            if finding.finding_id == node.finding_id:
                return finding

        return None

    def _extract_component_name(self, finding: Finding) -> str:
        """Extract component name from finding if available."""
        title = finding.title or ""
        # Look for component name in title like "Exported Activity: .MainActivity"
        if ":" in title:
            parts = title.split(":")
            if len(parts) > 1:
                return parts[-1].strip()
        return ".UnknownComponent"

    def get_entry_points(self) -> list[AttackNode]:
        """Get all entry point nodes."""
        return self.entry_points

    def get_targets(self) -> list[AttackNode]:
        """Get all target nodes."""
        return self.targets

    def get_adjacency_list(self) -> dict[str, list[str]]:
        """Get adjacency list representation of the graph."""
        adj: dict[str, list[str]] = {node_id: [] for node_id in self.nodes}

        for edge in self.edges:
            if edge.source_id in adj:
                adj[edge.source_id].append(edge.target_id)

        return adj
