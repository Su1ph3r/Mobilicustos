"""Base analyzer abstract class and result data structures for static analysis.

Provides the abstract BaseAnalyzer class that all security analyzers must
subclass, the AnalyzerResult dataclass for intermediate analysis results,
and utility methods for creating standardized Finding database objects.

The base class provides:
    - Abstract ``analyze()`` method that all analyzers implement
    - ``create_finding()`` factory method for generating Finding objects
      with deterministic IDs, severity-to-CVSS mapping, and optional
      OWASP/CWE classification
    - ``result_to_finding()`` converter from AnalyzerResult to Finding
    - Finding deduplication via content-based hashing
    - Integration with the known findings registry for enrichment

Architecture:
    Analyzer subclasses implement ``async analyze(app) -> list[Finding]``
    and are registered with the scan orchestrator. The orchestrator runs
    selected analyzers based on scan_type (static, dynamic, or full) and
    collects all findings into the database.
"""

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from api.models.database import Finding, MobileApp

logger = logging.getLogger(__name__)

# Lazy import to avoid circular imports
_finding_registry = None


def _get_finding_registry():
    """Get the known findings registry instance via lazy initialization.

    Uses lazy import to avoid circular dependencies between the
    analyzer base module and the data/known_findings package.

    Returns:
        The singleton FindingRegistry instance.
    """
    global _finding_registry
    if _finding_registry is None:
        from api.data.known_findings.registry import get_finding_registry
        _finding_registry = get_finding_registry()
    return _finding_registry


@dataclass
class AnalyzerResult:
    """Intermediate result from analyzers that gets converted to Finding.

    This class provides a convenient way for analyzers to create findings
    with all the Nubicustos-compatible fields.
    """

    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str
    impact: str
    remediation: str

    # Location
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None

    # PoC Evidence
    poc_evidence: str | None = None
    poc_verification: str | None = None
    poc_commands: list[dict[str, Any]] = field(default_factory=list)
    poc_frida_script: str | None = None
    poc_screenshot_path: str | None = None

    # Risk scoring
    cwe_id: str | None = None
    cwe_name: str | None = None
    cvss_score: Decimal | float | None = None  # Accepts both for convenience
    cvss_vector: str | None = None

    # OWASP mapping
    owasp_masvs_category: str | None = None
    owasp_masvs_control: str | None = None
    owasp_mastg_test: str | None = None

    # Remediation details
    remediation_commands: list[dict[str, Any]] = field(default_factory=list)
    remediation_code: dict[str, Any] = field(default_factory=dict)
    remediation_resources: list[dict[str, Any]] = field(default_factory=list)

    # Additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseAnalyzer(ABC):
    """Abstract base class for all security analyzers.

    All static and dynamic analyzers inherit from this class and implement
    the ``analyze()`` method. The base class provides standardized finding
    creation, deduplication via canonical IDs, and integration with the
    known findings registry for template-based finding generation.

    Attributes:
        name: Unique identifier for this analyzer, used in scan_type
            routing and finding attribution.
        platform: Target platform scope ("android", "ios", or
            "cross-platform").
    """

    name: str = "base"
    platform: str = "cross-platform"

    @abstractmethod
    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze an application and return security findings.

        All analyzer subclasses must implement this method. The method
        should be idempotent and safe to run concurrently with other
        analyzers on the same application.

        Args:
            app: The mobile application to analyze, with file_path
                pointing to the APK or IPA archive.

        Returns:
            A list of Finding objects representing detected security
            issues. May return an empty list if no issues are found
            or if the analyzer does not apply to this app's platform.
        """
        pass

    def _generate_canonical_id(
        self,
        app: MobileApp,
        title: str,
        category: str | None,
    ) -> str:
        """Generate a canonical ID for finding deduplication.

        Creates a stable identifier based on category, title, app_id,
        and platform to enable merging duplicate findings from different
        analysis tools. Normalizes the title by lowercasing and replacing
        non-alphanumeric characters with underscores.

        Args:
            app: The mobile application being analyzed.
            title: The finding title to normalize.
            category: The finding category, or None for "unknown".

        Returns:
            A canonical ID string, or a SHA-256 hash prefix if the
            resulting ID exceeds 200 characters.
        """
        # Normalize title: lowercase, replace non-alphanumeric with underscore
        normalized_title = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")

        parts = [
            (category or "unknown").lower(),
            normalized_title,
            app.app_id,
            app.platform,
        ]
        canonical = "_".join(parts)

        # Hash if too long (>200 chars)
        if len(canonical) > 200:
            return hashlib.sha256(canonical.encode()).hexdigest()[:32]

        return canonical

    def create_finding(
        self,
        app: MobileApp,
        title: str,
        description: str,
        severity: str,
        impact: str,
        remediation: str,
        category: str | None = None,
        file_path: str | None = None,
        line_number: int | None = None,
        code_snippet: str | None = None,
        poc_evidence: str | None = None,
        poc_verification: str | None = None,
        poc_commands: list[dict[str, Any]] | None = None,
        poc_frida_script: str | None = None,
        poc_screenshot_path: str | None = None,
        cwe_id: str | None = None,
        cwe_name: str | None = None,
        owasp_masvs_category: str | None = None,
        owasp_masvs_control: str | None = None,
        owasp_mastg_test: str | None = None,
        cvss_score: Decimal | float | None = None,
        cvss_vector: str | None = None,
        remediation_commands: list[dict[str, Any]] | None = None,
        remediation_code: dict[str, Any] | None = None,
        remediation_resources: list[dict[str, Any]] | None = None,
    ) -> Finding:
        """Create a standardized finding with Nubicustos-compatible structure.

        Args:
            app: The MobileApp being analyzed
            title: Finding title
            description: Detailed description
            severity: critical, high, medium, low, info
            impact: Impact description
            remediation: Remediation guidance text
            category: Finding category
            file_path: Path to affected file
            line_number: Line number in file
            code_snippet: Relevant code snippet
            poc_evidence: Proof of concept evidence text
            poc_verification: Command/steps to verify the finding
            poc_commands: List of structured PoC commands [{type, command, description}]
            poc_frida_script: Frida script for dynamic verification
            poc_screenshot_path: Path to screenshot evidence
            cwe_id: CWE identifier (e.g., "CWE-321")
            cwe_name: CWE name
            owasp_masvs_category: MASVS category
            owasp_masvs_control: MASVS control ID
            owasp_mastg_test: MASTG test ID
            cvss_score: CVSS score (0.0-10.0)
            cvss_vector: CVSS vector string
            remediation_commands: List of [{type, command, description}]
            remediation_code: Dict of {language: code_snippet}
            remediation_resources: List of [{title, url, type}]

        Returns:
            Finding object ready to be persisted
        """
        # Generate unique finding ID
        finding_hash = hashlib.sha256(
            f"{app.app_id}:{self.name}:{title}:{description}:{file_path}:{line_number}".encode()
        ).hexdigest()[:16]

        finding_id = f"{self.name}-{finding_hash}"

        # Generate canonical ID for deduplication
        canonical_id = self._generate_canonical_id(app, title, category)

        # Convert cvss_score to Decimal if it's a float
        cvss_decimal = None
        if cvss_score is not None:
            cvss_decimal = Decimal(str(cvss_score)) if isinstance(cvss_score, float) else cvss_score

        return Finding(
            finding_id=finding_id,
            canonical_id=canonical_id,
            app_id=app.app_id,
            tool=self.name,
            tool_sources=[self.name],  # Initialize with this tool
            platform=app.platform,
            severity=severity,
            category=category,
            title=title,
            description=description,
            impact=impact,
            remediation=remediation,
            resource_type=category,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            poc_evidence=poc_evidence,
            poc_verification=poc_verification,
            poc_commands=poc_commands or [],
            poc_frida_script=poc_frida_script,
            poc_screenshot_path=poc_screenshot_path,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            owasp_masvs_category=owasp_masvs_category,
            owasp_masvs_control=owasp_masvs_control,
            owasp_mastg_test=owasp_mastg_test,
            cvss_score=cvss_decimal,
            cvss_vector=cvss_vector,
            remediation_commands=remediation_commands or [],
            remediation_code=remediation_code or {},
            remediation_resources=remediation_resources or [],
        )

    def result_to_finding(self, app: MobileApp, result: AnalyzerResult) -> Finding:
        """Convert an AnalyzerResult dataclass to a Finding database object.

        Provides a convenient bridge for analyzers that use the
        AnalyzerResult intermediate format to produce Finding objects
        compatible with the database layer.

        Args:
            app: The mobile application being analyzed.
            result: The AnalyzerResult to convert.

        Returns:
            A Finding object ready to be persisted to the database.
        """
        return self.create_finding(
            app=app,
            title=result.title,
            description=result.description,
            severity=result.severity,
            impact=result.impact,
            remediation=result.remediation,
            category=result.category,
            file_path=result.file_path,
            line_number=result.line_number,
            code_snippet=result.code_snippet,
            poc_evidence=result.poc_evidence,
            poc_verification=result.poc_verification,
            poc_commands=result.poc_commands,
            poc_frida_script=result.poc_frida_script,
            poc_screenshot_path=result.poc_screenshot_path,
            cwe_id=result.cwe_id,
            cwe_name=result.cwe_name,
            owasp_masvs_category=result.owasp_masvs_category,
            owasp_masvs_control=result.owasp_masvs_control,
            owasp_mastg_test=result.owasp_mastg_test,
            cvss_score=result.cvss_score,
            cvss_vector=result.cvss_vector,
            remediation_commands=result.remediation_commands,
            remediation_code=result.remediation_code,
            remediation_resources=result.remediation_resources,
        )

    def create_finding_from_known(
        self,
        known_finding_id: str,
        app: MobileApp,
        file_path: str | None = None,
        line_number: int | None = None,
        code_snippet: str | None = None,
        component_name: str | None = None,
        additional_evidence: str | None = None,
        custom_description: str | None = None,
        custom_impact: str | None = None,
    ) -> Finding | None:
        """Create a Finding from a known finding definition in the registry.

        This method allows analyzers to use pre-defined finding templates with
        standardized metadata (CVSS, CWE, OWASP, PoC commands, etc.) for
        consistency and reduced code duplication.

        Args:
            known_finding_id: ID of the known finding definition (e.g., "android_debuggable")
            app: The MobileApp being analyzed
            file_path: Path to the affected file
            line_number: Line number in the file
            code_snippet: Relevant code snippet
            component_name: Component name (for placeholder replacement in PoC commands)
            additional_evidence: Additional PoC evidence to append to the default
            custom_description: Override the default description if needed
            custom_impact: Override the default impact if needed

        Returns:
            Finding object ready to persist, or None if the known finding ID was not found

        Example:
            # In an analyzer:
            finding = self.create_finding_from_known(
                known_finding_id="android_debuggable",
                app=app,
                file_path="AndroidManifest.xml",
                code_snippet='android:debuggable="true"',
                additional_evidence="Found debuggable=true in manifest",
            )
            if finding:
                findings.append(finding)
        """
        registry = _get_finding_registry()
        return registry.create_finding(
            known_finding_id=known_finding_id,
            app=app,
            tool_name=self.name,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            component_name=component_name,
            additional_evidence=additional_evidence,
            custom_description=custom_description,
            custom_impact=custom_impact,
        )
