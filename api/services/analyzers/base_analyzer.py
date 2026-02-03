"""Base analyzer class for all static analyzers."""

import hashlib
import logging
from abc import ABC, abstractmethod
from typing import Any

from api.models.database import Finding, MobileApp

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """Abstract base class for all analyzers."""

    name: str = "base"
    platform: str = "cross-platform"

    @abstractmethod
    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze an app and return findings."""
        pass

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
        poc_commands: list[str] | None = None,
        cwe_id: str | None = None,
        cwe_name: str | None = None,
        owasp_masvs_category: str | None = None,
        owasp_masvs_control: str | None = None,
        owasp_mastg_test: str | None = None,
        cvss_score: float | None = None,
        cvss_vector: str | None = None,
        remediation_commands: list[str] | None = None,
        remediation_code: dict[str, Any] | None = None,
    ) -> Finding:
        """Create a standardized finding."""
        # Generate unique finding ID - include description for uniqueness
        finding_hash = hashlib.sha256(
            f"{app.app_id}:{self.name}:{title}:{description}:{file_path}:{line_number}".encode()
        ).hexdigest()[:16]

        finding_id = f"{self.name}-{finding_hash}"

        return Finding(
            finding_id=finding_id,
            app_id=app.app_id,
            tool=self.name,
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
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            owasp_masvs_category=owasp_masvs_category,
            owasp_masvs_control=owasp_masvs_control,
            owasp_mastg_test=owasp_mastg_test,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            remediation_commands=remediation_commands or [],
            remediation_code=remediation_code or {},
        )
