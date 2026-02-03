"""Pathfinding algorithms for attack path analysis."""

import logging
from collections import defaultdict
from typing import Any

from api.services.attack_paths.models import (
    AttackEdge,
    AttackNode,
    Exploitability,
)

logger = logging.getLogger(__name__)


class AttackPathfinder:
    """Finds attack paths through the vulnerability graph."""

    def __init__(
        self,
        nodes: dict[str, AttackNode],
        edges: list[AttackEdge],
    ):
        """Initialize pathfinder.

        Args:
            nodes: Dictionary of node_id -> AttackNode
            edges: List of AttackEdge objects
        """
        self.nodes = nodes
        self.edges = edges

        # Build adjacency structures
        self.adjacency: dict[str, list[AttackEdge]] = defaultdict(list)
        for edge in edges:
            self.adjacency[edge.source_id].append(edge)

    def find_all_paths(
        self,
        entry_points: list[AttackNode],
        targets: list[AttackNode],
        max_depth: int = 10,
        min_confidence: float = 0.3,
    ) -> list[list[tuple[AttackNode, AttackEdge | None]]]:
        """Find all paths from entry points to targets.

        Uses DFS to find all paths within depth and confidence constraints.

        Args:
            entry_points: Starting nodes for paths
            targets: Goal nodes
            max_depth: Maximum path length
            min_confidence: Minimum combined path confidence

        Returns:
            List of paths, each path is a list of (node, edge_to_next) tuples
        """
        all_paths: list[list[tuple[AttackNode, AttackEdge | None]]] = []
        target_ids = {t.node_id for t in targets}

        for entry in entry_points:
            paths = self._dfs_paths(
                entry.node_id,
                target_ids,
                max_depth,
                min_confidence,
            )
            all_paths.extend(paths)

        logger.info(f"Found {len(all_paths)} attack paths")
        return all_paths

    def _dfs_paths(
        self,
        start_id: str,
        target_ids: set[str],
        max_depth: int,
        min_confidence: float,
    ) -> list[list[tuple[AttackNode, AttackEdge | None]]]:
        """DFS to find all paths from start to any target."""
        paths: list[list[tuple[AttackNode, AttackEdge | None]]] = []

        def dfs(
            current_id: str,
            path: list[tuple[AttackNode, AttackEdge | None]],
            visited: set[str],
            current_confidence: float,
        ) -> None:
            if len(path) > max_depth:
                return

            if current_confidence < min_confidence:
                return

            if current_id in target_ids:
                # Found a path to target
                paths.append(path.copy())
                return

            for edge in self.adjacency.get(current_id, []):
                next_id = edge.target_id

                if next_id in visited:
                    continue

                next_node = self.nodes.get(next_id)
                if not next_node:
                    continue

                # Update confidence (multiplicative)
                new_confidence = current_confidence * edge.confidence

                visited.add(next_id)
                path.append((next_node, edge))

                dfs(next_id, path, visited, new_confidence)

                path.pop()
                visited.remove(next_id)

        # Start DFS from start node
        start_node = self.nodes.get(start_id)
        if start_node:
            visited = {start_id}
            dfs(start_id, [(start_node, None)], visited, 1.0)

        return paths

    def find_shortest_path(
        self,
        start_id: str,
        end_id: str,
    ) -> list[tuple[AttackNode, AttackEdge | None]] | None:
        """Find shortest path between two nodes using BFS.

        Args:
            start_id: Starting node ID
            end_id: Target node ID

        Returns:
            Path as list of (node, edge) tuples, or None if no path
        """
        from collections import deque

        if start_id not in self.nodes or end_id not in self.nodes:
            return None

        queue: deque[tuple[str, list[tuple[AttackNode, AttackEdge | None]]]] = deque()
        queue.append((start_id, [(self.nodes[start_id], None)]))
        visited = {start_id}

        while queue:
            current_id, path = queue.popleft()

            if current_id == end_id:
                return path

            for edge in self.adjacency.get(current_id, []):
                next_id = edge.target_id
                if next_id not in visited:
                    visited.add(next_id)
                    next_node = self.nodes.get(next_id)
                    if next_node:
                        new_path = path + [(next_node, edge)]
                        queue.append((next_id, new_path))

        return None

    def find_easiest_path(
        self,
        start_id: str,
        end_id: str,
    ) -> list[tuple[AttackNode, AttackEdge | None]] | None:
        """Find path with highest confidence (easiest to exploit).

        Uses modified Dijkstra's algorithm where cost = -log(confidence).

        Args:
            start_id: Starting node ID
            end_id: Target node ID

        Returns:
            Easiest path or None if no path exists
        """
        import heapq
        import math

        if start_id not in self.nodes or end_id not in self.nodes:
            return None

        # Priority queue: (cost, node_id, path)
        # Cost = -sum(log(confidence)) = -log(product of confidences)
        pq: list[tuple[float, str, list[tuple[AttackNode, AttackEdge | None]]]] = []
        heapq.heappush(pq, (0, start_id, [(self.nodes[start_id], None)]))

        visited: dict[str, float] = {}

        while pq:
            cost, current_id, path = heapq.heappop(pq)

            if current_id in visited and visited[current_id] <= cost:
                continue
            visited[current_id] = cost

            if current_id == end_id:
                return path

            for edge in self.adjacency.get(current_id, []):
                next_id = edge.target_id
                next_node = self.nodes.get(next_id)

                if not next_node:
                    continue

                # Cost is negative log of confidence (lower is better = higher confidence)
                edge_cost = -math.log(max(edge.confidence, 0.01))
                new_cost = cost + edge_cost

                if next_id not in visited or visited[next_id] > new_cost:
                    new_path = path + [(next_node, edge)]
                    heapq.heappush(pq, (new_cost, next_id, new_path))

        return None

    def calculate_path_confidence(
        self,
        path: list[tuple[AttackNode, AttackEdge | None]],
    ) -> float:
        """Calculate combined confidence for a path.

        Confidence is multiplicative - each step reduces overall confidence.

        Args:
            path: List of (node, edge) tuples

        Returns:
            Combined confidence (0.0 - 1.0)
        """
        confidence = 1.0
        for _, edge in path:
            if edge:
                confidence *= edge.confidence
        return confidence

    def determine_path_exploitability(
        self,
        path: list[tuple[AttackNode, AttackEdge | None]],
    ) -> Exploitability:
        """Determine overall exploitability of a path.

        Takes the most difficult exploitability level in the chain.

        Args:
            path: List of (node, edge) tuples

        Returns:
            Overall Exploitability enum value
        """
        exploitability_order = [
            Exploitability.CONFIRMED,
            Exploitability.EASY,
            Exploitability.MODERATE,
            Exploitability.DIFFICULT,
            Exploitability.THEORETICAL,
        ]

        max_difficulty = 0
        for _, edge in path:
            if edge:
                try:
                    idx = exploitability_order.index(edge.exploitability)
                    max_difficulty = max(max_difficulty, idx)
                except ValueError:
                    pass

        return exploitability_order[max_difficulty]

    def get_path_requirements(
        self,
        path: list[tuple[AttackNode, AttackEdge | None]],
    ) -> dict[str, bool]:
        """Get requirements for exploiting a path.

        Args:
            path: List of (node, edge) tuples

        Returns:
            Dict with requirement flags
        """
        requires_physical = False
        requires_network = False

        for _, edge in path:
            if edge:
                requires_physical = requires_physical or edge.requires_physical
                requires_network = requires_network or edge.requires_network

        return {
            "requires_physical_access": requires_physical,
            "requires_network_position": requires_network,
        }

    def get_path_mitre_techniques(
        self,
        path: list[tuple[AttackNode, AttackEdge | None]],
    ) -> list[str]:
        """Get all MITRE ATT&CK techniques used in a path.

        Args:
            path: List of (node, edge) tuples

        Returns:
            List of unique technique IDs
        """
        techniques: set[str] = set()
        for _, edge in path:
            if edge and edge.mitre_techniques:
                techniques.update(edge.mitre_techniques)
        return sorted(techniques)
