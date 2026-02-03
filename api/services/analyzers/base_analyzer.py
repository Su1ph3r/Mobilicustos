"""Base analyzer class for all static analyzers."""

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from api.models.database import Finding, MobileApp

logger = logging.getLogger(__name__)


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
    """Abstract base class for all analyzers."""

    name: str = "base"
    platform: str = "cross-platform"

    @abstractmethod
    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze an app and return findings."""
        pass

    def _generate_canonical_id(
        self,
        app: MobileApp,
        title: str,
        category: str | None,
    ) -> str:
        """Generate canonical ID for finding deduplication.

        Creates a stable identifier based on category, title, app, and platform
        to enable merging duplicate findings from different tools.
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
        """Convert an AnalyzerResult to a Finding object.

        This provides a convenient way to convert the dataclass-based results
        to database Finding objects.
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
