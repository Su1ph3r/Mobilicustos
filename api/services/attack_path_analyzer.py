"""Attack path analyzer for generating attack chains from findings."""

import logging
from decimal import Decimal
from typing import Any

from api.models.database import Finding

logger = logging.getLogger(__name__)


# Attack path templates based on finding combinations
ATTACK_PATH_TEMPLATES = [
    {
        "name": "Data Exfiltration via Exported Component",
        "description": "Attacker exploits exported component to access sensitive data",
        "required_categories": ["Component Security", "Data Protection"],
        "attack_vector": "1. Invoke exported component\n2. Access stored credentials\n3. Exfiltrate data",
    },
    {
        "name": "Credential Theft via Insecure Storage",
        "description": "Attacker extracts credentials from insecure storage",
        "required_categories": ["Secrets", "Data Protection"],
        "attack_vector": "1. Extract APK/IPA\n2. Find hardcoded secrets\n3. Access backend services",
    },
    {
        "name": "Network MITM to Data Theft",
        "description": "Attacker intercepts network traffic to steal data",
        "required_categories": ["Network Security", "SSL Pinning"],
        "attack_vector": "1. Bypass SSL pinning\n2. Intercept network traffic\n3. Capture credentials",
    },
    {
        "name": "Debug to Full Compromise",
        "description": "Attacker uses debug features to compromise application",
        "required_categories": ["Configuration", "Entitlements"],
        "attack_vector": "1. Attach debugger\n2. Modify runtime behavior\n3. Extract secrets from memory",
    },
    {
        "name": "WebView Exploitation",
        "description": "Attacker exploits insecure WebView to execute code",
        "required_categories": ["WebView", "Component Security"],
        "attack_vector": "1. Find WebView with JS enabled\n2. Inject malicious script\n3. Access native bridge",
    },
    {
        "name": "SQL Injection to Data Breach",
        "description": "Attacker exploits SQL injection to extract database",
        "required_categories": ["SQL Injection"],
        "attack_vector": "1. Identify injection point\n2. Craft SQL payload\n3. Extract database contents",
    },
    {
        "name": "ML Model Theft and Abuse",
        "description": "Attacker extracts ML model for adversarial use",
        "required_categories": ["ML Security"],
        "attack_vector": "1. Extract model from app\n2. Analyze model structure\n3. Craft adversarial inputs",
    },
    {
        "name": "Deep Link Hijacking",
        "description": "Attacker hijacks deep links to steal data",
        "required_categories": ["Deep Links", "Component Security"],
        "attack_vector": "1. Register competing URL scheme\n2. Intercept sensitive links\n3. Capture authentication tokens",
    },
]


class AttackPathAnalyzer:
    """Analyzes findings to generate attack paths."""

    async def generate_paths(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Generate attack paths from a list of findings."""
        paths: list[dict[str, Any]] = []

        # Group findings by category
        by_category: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.category:
                if finding.category not in by_category:
                    by_category[finding.category] = []
                by_category[finding.category].append(finding)

        # Check each template
        for template in ATTACK_PATH_TEMPLATES:
            required_cats = template["required_categories"]

            # Check if all required categories have findings
            matching_findings = []
            all_matched = True

            for cat in required_cats:
                cat_findings = by_category.get(cat, [])
                if not cat_findings:
                    all_matched = False
                    break
                matching_findings.extend(cat_findings)

            if all_matched and matching_findings:
                # Calculate combined risk score
                risk_score = self._calculate_path_risk(matching_findings)
                exploitability = self._determine_exploitability(matching_findings)

                paths.append({
                    "name": template["name"],
                    "description": template["description"],
                    "attack_vector": template["attack_vector"],
                    "finding_chain": [f.finding_id for f in matching_findings],
                    "risk_score": risk_score,
                    "exploitability": exploitability,
                    "findings_summary": [
                        {
                            "finding_id": f.finding_id,
                            "title": f.title,
                            "severity": f.severity,
                        }
                        for f in matching_findings
                    ],
                })

        # Also generate paths based on severity chains
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        if len(critical_high) >= 2:
            paths.extend(await self._generate_severity_chains(critical_high))

        return paths

    def _calculate_path_risk(self, findings: list[Finding]) -> Decimal:
        """Calculate combined risk score for an attack path."""
        severity_weights = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 0.5,
        }

        total_weight = sum(
            severity_weights.get(f.severity, 1.0) for f in findings
        )

        # Normalize to 0-10 scale
        max_possible = len(findings) * 10.0
        score = (total_weight / max_possible) * 10 if max_possible > 0 else 0

        # Boost for having multiple high-severity findings
        critical_count = sum(1 for f in findings if f.severity == "critical")
        if critical_count > 1:
            score = min(10.0, score * 1.2)

        return Decimal(str(round(score, 2)))

    def _determine_exploitability(self, findings: list[Finding]) -> str:
        """Determine exploitability based on findings."""
        # Check for findings that make exploitation easier
        easy_indicators = [
            "debuggable",
            "exported",
            "cleartext",
            "hardcoded",
            "ssl pinning",
        ]

        easy_count = sum(
            1 for f in findings
            if any(ind in f.title.lower() for ind in easy_indicators)
        )

        if any(f.severity == "critical" for f in findings) and easy_count >= 2:
            return "trivial"
        elif any(f.severity == "critical" for f in findings):
            return "easy"
        elif easy_count >= 2:
            return "moderate"
        elif any(f.severity == "high" for f in findings):
            return "moderate"
        else:
            return "difficult"

    async def _generate_severity_chains(
        self,
        findings: list[Finding],
    ) -> list[dict[str, Any]]:
        """Generate attack paths based on severity chains."""
        paths: list[dict[str, Any]] = []

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.severity, 5),
        )

        # Create chains of 2-4 findings
        if len(sorted_findings) >= 2:
            chain = sorted_findings[:4]

            paths.append({
                "name": "High-Severity Finding Chain",
                "description": "Multiple high-severity findings that could be chained together",
                "attack_vector": "Chain of vulnerabilities leading to compromise",
                "finding_chain": [f.finding_id for f in chain],
                "risk_score": self._calculate_path_risk(chain),
                "exploitability": self._determine_exploitability(chain),
                "findings_summary": [
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity,
                    }
                    for f in chain
                ],
            })

        return paths

    async def sync_to_neo4j(self, paths: list[dict[str, Any]], neo4j_driver: Any):
        """Sync attack paths to Neo4j for graph visualization."""
        # This would create nodes and relationships in Neo4j
        # for graph-based visualization of attack paths

        # Placeholder for Neo4j integration
        logger.info(f"Would sync {len(paths)} attack paths to Neo4j")
