"""Impact assessment for attack paths."""

import logging
from typing import Any

from api.services.attack_paths.edge_definitions import TARGET_TYPES
from api.services.attack_paths.models import AttackNode, AttackEdge, NodeType

logger = logging.getLogger(__name__)


# Category to CIA impact mapping
CATEGORY_IMPACT = {
    "Secrets": {"C": 90, "I": 30, "A": 10},
    "Data Protection": {"C": 80, "I": 40, "A": 20},
    "Cryptography": {"C": 70, "I": 50, "A": 10},
    "Network Security": {"C": 70, "I": 40, "A": 10},
    "Component Security": {"C": 50, "I": 50, "A": 20},
    "WebView": {"C": 60, "I": 60, "A": 20},
    "Configuration": {"C": 50, "I": 40, "A": 30},
    "Authentication": {"C": 80, "I": 60, "A": 30},
    "SQL Injection": {"C": 80, "I": 80, "A": 30},
    "Command Injection": {"C": 70, "I": 100, "A": 50},
    "File Security": {"C": 70, "I": 50, "A": 20},
    "Logging": {"C": 40, "I": 10, "A": 0},
    "Deep Links": {"C": 40, "I": 30, "A": 10},
    "Binary Protection": {"C": 30, "I": 40, "A": 20},
    "Permissions": {"C": 30, "I": 20, "A": 10},
}

# Severity to risk score multiplier
SEVERITY_MULTIPLIER = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.1,
}


class ImpactAssessor:
    """Assesses the impact of attack paths."""

    def assess_path_impact(
        self,
        path: list[tuple[AttackNode, AttackEdge | None]],
    ) -> dict[str, int]:
        """Calculate CIA impact scores for an attack path.

        Impact is calculated as the maximum impact across all nodes in the path,
        with additional weight from target nodes.

        Args:
            path: List of (node, edge) tuples

        Returns:
            Dict with C, I, A impact scores (0-100)
        """
        max_c = 0
        max_i = 0
        max_a = 0

        for node, _ in path:
            # Get category-based impact
            impact = CATEGORY_IMPACT.get(node.category, {"C": 30, "I": 30, "A": 10})

            # Apply severity multiplier
            multiplier = SEVERITY_MULTIPLIER.get(node.severity, 0.5)

            c = int(impact["C"] * multiplier)
            i = int(impact["I"] * multiplier)
            a = int(impact["A"] * multiplier)

            # Check if this is a target node
            if node.node_type == NodeType.TARGET:
                target_id = node.node_id.replace("target_", "")
                if target_id in TARGET_TYPES:
                    target_impact = TARGET_TYPES[target_id]
                    c = max(c, target_impact.get("impact_c", 0))
                    i = max(i, target_impact.get("impact_i", 0))
                    a = max(a, target_impact.get("impact_a", 0))

            max_c = max(max_c, c)
            max_i = max(max_i, i)
            max_a = max(max_a, a)

        return {
            "impact_confidentiality": max_c,
            "impact_integrity": max_i,
            "impact_availability": max_a,
        }

    def calculate_risk_score(
        self,
        path: list[tuple[AttackNode, AttackEdge | None]],
        confidence: float,
        impact: dict[str, int],
    ) -> float:
        """Calculate combined risk score for an attack path.

        Risk = Impact * Likelihood (confidence)

        Args:
            path: The attack path
            confidence: Path confidence (0-1)
            impact: CIA impact scores

        Returns:
            Risk score (0-10 scale)
        """
        # Calculate average impact
        avg_impact = (
            impact["impact_confidentiality"]
            + impact["impact_integrity"]
            + impact["impact_availability"]
        ) / 3

        # Normalize to 0-10 scale
        normalized_impact = avg_impact / 10

        # Factor in severity of nodes in path
        max_severity_weight = 0.0
        for node, _ in path:
            weight = {
                "critical": 10.0,
                "high": 8.0,
                "medium": 5.0,
                "low": 2.0,
                "info": 0.5,
            }.get(node.severity, 5.0)
            max_severity_weight = max(max_severity_weight, weight)

        # Combine: base from severity, modified by impact and confidence
        risk = max_severity_weight * (normalized_impact / 10) * (0.5 + 0.5 * confidence)

        # Boost for critical findings
        critical_count = sum(1 for n, _ in path if n.severity == "critical")
        if critical_count > 0:
            risk = min(10.0, risk * (1 + 0.1 * critical_count))

        return round(min(10.0, max(0.0, risk)), 2)

    def determine_skill_level(
        self,
        path: list[tuple[AttackNode, AttackEdge | None]],
    ) -> str:
        """Determine skill level required to exploit a path.

        Args:
            path: The attack path

        Returns:
            Skill level: novice, intermediate, advanced, expert
        """
        skill_levels = {"novice": 1, "intermediate": 2, "advanced": 3, "expert": 4}
        reverse_levels = {v: k for k, v in skill_levels.items()}

        max_skill = 1

        for _, edge in path:
            if edge:
                # Get edge skill level from definition (default to intermediate)
                # This would be looked up from edge_definitions
                edge_skill = "intermediate"

                # Some heuristics based on edge type
                if "injection" in (edge.edge_type or "").lower():
                    edge_skill = "intermediate"
                elif "debug" in (edge.edge_type or "").lower():
                    edge_skill = "intermediate"
                elif "ssl_bypass" in (edge.edge_type or "").lower():
                    edge_skill = "novice"
                elif "code_execution" in (edge.edge_type or "").lower():
                    edge_skill = "advanced"

                skill_num = skill_levels.get(edge_skill, 2)
                max_skill = max(max_skill, skill_num)

        return reverse_levels.get(max_skill, "intermediate")

    def generate_exploitation_steps(
        self,
        path: list[tuple[AttackNode, AttackEdge | None]],
        package_name: str = "com.example.app",
    ) -> list[dict[str, Any]]:
        """Generate step-by-step exploitation guide for a path.

        Args:
            path: The attack path
            package_name: Target app package name

        Returns:
            List of exploitation steps
        """
        steps: list[dict[str, Any]] = []
        step_num = 1

        for i, (node, edge) in enumerate(path):
            if node.node_type == NodeType.TARGET:
                # Final step - achieving the target
                steps.append({
                    "step": step_num,
                    "title": f"Achieve: {node.title}",
                    "description": f"Objective achieved: {node.description or node.title}",
                    "type": "objective",
                })
                continue

            # Add step for each vulnerability
            step = {
                "step": step_num,
                "title": f"Exploit: {node.title}",
                "description": node.description or f"Leverage {node.title}",
                "type": "exploit",
                "finding_id": node.finding_id,
                "severity": node.severity,
            }

            # Add PoC command if available
            if edge and edge.poc_command:
                poc = edge.poc_command.replace("{package_name}", package_name)
                step["poc_command"] = poc

            steps.append(step)
            step_num += 1

        return steps

    def collect_poc_commands(
        self,
        path: list[tuple[AttackNode, AttackEdge | None]],
        package_name: str = "com.example.app",
    ) -> list[dict[str, str]]:
        """Collect all PoC commands for a path.

        Args:
            path: The attack path
            package_name: Target app package name

        Returns:
            List of PoC commands with descriptions
        """
        commands: list[dict[str, str]] = []
        seen: set[str] = set()

        for node, edge in path:
            if edge and edge.poc_command:
                poc = edge.poc_command.replace("{package_name}", package_name)
                if poc not in seen:
                    seen.add(poc)
                    commands.append({
                        "command": poc,
                        "description": edge.description or f"Exploit {node.title}",
                        "edge_type": edge.edge_type,
                    })

        return commands
