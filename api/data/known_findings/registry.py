"""Finding registry for centralized access to known finding definitions."""

import hashlib
import logging
from decimal import Decimal
from typing import Any

from api.data.known_findings.loader import load_all_definitions, reload_definitions
from api.data.known_findings.models import KnownFinding
from api.models.database import Finding, MobileApp

logger = logging.getLogger(__name__)


class FindingRegistry:
    """Central registry for known finding definitions.

    Provides lookup, filtering, and Finding object creation from
    pre-defined templates. Implements singleton pattern for efficiency.
    """

    _instance: "FindingRegistry | None" = None
    _initialized: bool = False

    def __new__(cls) -> "FindingRegistry":
        """Ensure singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize the registry (only runs once due to singleton)."""
        if FindingRegistry._initialized:
            return

        self._findings_by_id: dict[str, KnownFinding] = {}
        self._findings_by_platform: dict[str, list[KnownFinding]] = {}
        self._findings_by_category: dict[str, list[KnownFinding]] = {}
        self._load_all()
        FindingRegistry._initialized = True

    def _load_all(self) -> None:
        """Load all finding definitions into the registry."""
        findings = load_all_definitions()

        for f in findings:
            self._findings_by_id[f.id] = f

            # Index by platform
            if f.platform not in self._findings_by_platform:
                self._findings_by_platform[f.platform] = []
            self._findings_by_platform[f.platform].append(f)

            # Index by category
            if f.category not in self._findings_by_category:
                self._findings_by_category[f.category] = []
            self._findings_by_category[f.category].append(f)

        logger.info(
            f"FindingRegistry initialized with {len(self._findings_by_id)} definitions"
        )

    def reload(self) -> int:
        """Reload all definitions from disk.

        Returns:
            Number of definitions loaded
        """
        self._findings_by_id.clear()
        self._findings_by_platform.clear()
        self._findings_by_category.clear()
        reload_definitions()
        self._load_all()
        return len(self._findings_by_id)

    def get(self, finding_id: str) -> KnownFinding | None:
        """Get a known finding by ID.

        Args:
            finding_id: The finding definition ID

        Returns:
            KnownFinding if found, None otherwise
        """
        return self._findings_by_id.get(finding_id)

    def get_by_platform(self, platform: str) -> list[KnownFinding]:
        """Get all findings for a platform.

        Args:
            platform: Platform name (android, ios, cross_platform)

        Returns:
            List of KnownFinding objects
        """
        return self._findings_by_platform.get(platform.lower(), [])

    def get_by_category(self, category: str) -> list[KnownFinding]:
        """Get all findings in a category.

        Args:
            category: Category name

        Returns:
            List of KnownFinding objects
        """
        return self._findings_by_category.get(category, [])

    def search(
        self,
        query: str,
        platform: str | None = None,
        severity: str | None = None,
    ) -> list[KnownFinding]:
        """Search finding definitions by text.

        Args:
            query: Search text (searches in title, description, tags)
            platform: Optional platform filter
            severity: Optional severity filter

        Returns:
            List of matching KnownFinding objects
        """
        query_lower = query.lower()
        results = []

        for f in self._findings_by_id.values():
            # Apply filters
            if platform and f.platform != platform.lower():
                continue
            if severity and f.severity != severity.lower():
                continue

            # Search in title, description, tags
            if (
                query_lower in f.title.lower()
                or query_lower in f.description.lower()
                or any(query_lower in tag.lower() for tag in f.tags)
            ):
                results.append(f)

        return results

    def list_all(self) -> list[KnownFinding]:
        """Get all known finding definitions.

        Returns:
            List of all KnownFinding objects
        """
        return list(self._findings_by_id.values())

    def list_ids(self) -> list[str]:
        """Get all finding definition IDs.

        Returns:
            List of finding IDs
        """
        return list(self._findings_by_id.keys())

    def list_categories(self) -> list[str]:
        """Get all unique categories.

        Returns:
            List of category names
        """
        return list(self._findings_by_category.keys())

    def create_finding(
        self,
        known_finding_id: str,
        app: MobileApp,
        tool_name: str,
        file_path: str | None = None,
        line_number: int | None = None,
        code_snippet: str | None = None,
        component_name: str | None = None,
        additional_evidence: str | None = None,
        custom_description: str | None = None,
        custom_impact: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding | None:
        """Create a Finding object from a known finding definition.

        This is the primary method for analyzers to create findings from
        pre-defined templates, ensuring consistency in metadata.

        Args:
            known_finding_id: ID of the known finding definition
            app: The MobileApp being analyzed
            tool_name: Name of the analyzer creating this finding
            file_path: Path to the affected file
            line_number: Line number in the file
            code_snippet: Relevant code snippet
            component_name: Component name (for placeholder replacement)
            additional_evidence: Additional PoC evidence to append
            custom_description: Override the default description
            custom_impact: Override the default impact
            metadata: Additional metadata to include

        Returns:
            Finding object ready to persist, or None if ID not found
        """
        known = self.get(known_finding_id)
        if not known:
            logger.warning(f"Unknown finding ID: {known_finding_id}")
            return None

        # Generate unique finding ID
        finding_hash = hashlib.sha256(
            f"{app.app_id}:{tool_name}:{known.id}:{file_path}:{line_number}".encode()
        ).hexdigest()[:16]
        finding_id = f"{tool_name}-{finding_hash}"

        # Generate canonical ID for deduplication
        canonical_id = self._generate_canonical_id(app, known.title, known.category)

        # Build PoC evidence
        poc_evidence = f"Known finding: {known.id}"
        if additional_evidence:
            poc_evidence = f"{poc_evidence}\n{additional_evidence}"

        # Get PoC commands with placeholders filled
        poc_commands = known.get_poc_commands_for_app(
            package_name=app.package_name or "",
            component_name=component_name,
            file_path=file_path,
        )

        # Get Frida script with placeholders filled
        frida_script = known.get_frida_script_for_app(app.package_name or "")

        return Finding(
            finding_id=finding_id,
            canonical_id=canonical_id,
            app_id=app.app_id,
            tool=tool_name,
            tool_sources=[tool_name],
            platform=app.platform,
            severity=known.severity,
            category=known.category,
            title=known.title,
            description=custom_description or known.description,
            impact=custom_impact or known.impact,
            remediation=known.remediation,
            resource_type=known.category,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            poc_evidence=poc_evidence,
            poc_commands=poc_commands,
            poc_frida_script=frida_script,
            cwe_id=known.cwe_id,
            cwe_name=known.cwe_name,
            cvss_score=known.cvss_score,
            cvss_vector=known.cvss_vector,
            owasp_masvs_category=known.owasp_masvs_category,
            owasp_masvs_control=known.owasp_masvs_control,
            owasp_mastg_test=known.owasp_mastg_test,
            remediation_code=known.get_remediation_code_dict(),
            remediation_resources=known.get_remediation_resources_list(),
        )

    def _generate_canonical_id(
        self,
        app: MobileApp,
        title: str,
        category: str | None,
    ) -> str:
        """Generate canonical ID for finding deduplication."""
        import re

        normalized_title = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")
        parts = [
            (category or "unknown").lower(),
            normalized_title,
            app.app_id,
            app.platform,
        ]
        canonical = "_".join(parts)
        if len(canonical) > 200:
            return hashlib.sha256(canonical.encode()).hexdigest()[:32]
        return canonical

    def get_stats(self) -> dict[str, Any]:
        """Get registry statistics.

        Returns:
            Dict with counts and metadata
        """
        return {
            "total": len(self._findings_by_id),
            "platforms": {k: len(v) for k, v in self._findings_by_platform.items()},
            "categories": {k: len(v) for k, v in self._findings_by_category.items()},
            "ids": list(self._findings_by_id.keys()),
        }


# Module-level singleton getter
_registry: FindingRegistry | None = None


def get_finding_registry() -> FindingRegistry:
    """Get the global FindingRegistry instance.

    Returns:
        The singleton FindingRegistry instance
    """
    global _registry
    if _registry is None:
        _registry = FindingRegistry()
    return _registry
