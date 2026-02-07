"""CVE Detection orchestrator.

Main entry point for CVE detection combining:
- Library fingerprinting
- CPE mapping
- OSV/NVD queries
- Finding generation
"""

import logging
from pathlib import Path
from typing import Any

from api.models.database import MobileApp
from api.services.cve.models import (
    CVEInfo,
    DetectedLibrary,
    LibrarySource,
    LibraryVulnerability,
)
from api.services.cve.fingerprinter import LibraryFingerprinter
from api.services.cve.cpe_matcher import CPEMatcher
from api.services.cve.sources.osv_client import OSVClient
from api.services.cve.sources.nvd_client import NVDClient

logger = logging.getLogger(__name__)


class CVEDetector:
    """Main CVE detection orchestrator."""

    def __init__(
        self,
        nvd_api_key: str | None = None,
        enable_nvd: bool = True,
        enable_osv: bool = True,
        redis_client: Any = None,
        enable_epss: bool = True,
    ):
        """Initialize CVE detector.

        Args:
            nvd_api_key: NVD API key for higher rate limits
            enable_nvd: Enable NVD queries
            enable_osv: Enable OSV queries
            redis_client: Optional Redis client for caching
            enable_epss: Enable EPSS score enrichment
        """
        self.fingerprinter = LibraryFingerprinter()
        self.cpe_matcher = CPEMatcher()
        self.osv_client = OSVClient() if enable_osv else None
        self.nvd_client = NVDClient(api_key=nvd_api_key) if enable_nvd else None

        # Optional cache
        self.cache = None
        if redis_client:
            from api.services.cve.cache import CVECache
            self.cache = CVECache(redis_client=redis_client)

        # Optional EPSS enrichment
        self.epss_client = None
        if enable_epss:
            try:
                from api.services.cve.sources.epss_client import EPSSClient
                self.epss_client = EPSSClient()
            except ImportError:
                pass

    async def detect_all(
        self,
        app: MobileApp,
        extracted_path: Path,
        dex_classes: list[str] | None = None,
        dependencies: list[dict] | None = None,
    ) -> list[LibraryVulnerability]:
        """Detect all CVEs in an application.

        Args:
            app: Mobile application being analyzed
            extracted_path: Path to extracted app contents
            dex_classes: Optional list of class names from DEX analysis
            dependencies: Optional pre-parsed dependencies

        Returns:
            List of library vulnerabilities
        """
        vulnerabilities: list[LibraryVulnerability] = []

        # Step 1: Fingerprint libraries
        logger.info("Fingerprinting libraries...")
        detected_libs = self.fingerprinter.fingerprint_all(
            extracted_path,
            dex_classes,
        )

        # Add pre-parsed dependencies if provided
        if dependencies:
            for dep in dependencies:
                detected_libs.append(DetectedLibrary(
                    name=dep.get("name", ""),
                    version=dep.get("version"),
                    source=LibrarySource(dep.get("source", "gradle")),
                    detection_method=dep.get("detection_method", "manifest"),
                    file_path=dep.get("file_path"),
                    confidence=0.95,
                ))

        logger.info(f"Detected {len(detected_libs)} libraries")

        # Step 2: Query vulnerability databases
        if self.osv_client:
            logger.info("Querying OSV database...")
            osv_vulns = await self._query_osv(detected_libs)
            vulnerabilities.extend(osv_vulns)

        if self.nvd_client:
            logger.info("Querying NVD database...")
            nvd_vulns = await self._query_nvd(detected_libs)
            vulnerabilities.extend(nvd_vulns)

        # Step 3: Deduplicate results
        unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)

        # Step 4: Enrich with EPSS scores
        if self.epss_client and unique_vulns:
            await self._enrich_with_epss(unique_vulns)

        logger.info(f"Found {len(unique_vulns)} unique vulnerabilities")
        return unique_vulns

    async def _enrich_with_epss(
        self, vulnerabilities: list[LibraryVulnerability]
    ) -> None:
        """Enrich vulnerabilities with EPSS exploit probability scores."""
        cve_ids = [
            v.cve.cve_id for v in vulnerabilities
            if v.cve.cve_id.startswith("CVE-")
        ]
        if not cve_ids:
            return

        try:
            scores = await self.epss_client.get_scores(cve_ids)
            for vuln in vulnerabilities:
                score = scores.get(vuln.cve.cve_id)
                if score:
                    vuln.cve.epss_score = score.epss_score
                    vuln.cve.epss_percentile = score.percentile
        except Exception as e:
            logger.warning(f"EPSS enrichment failed: {e}")

    async def _query_osv(
        self,
        libraries: list[DetectedLibrary],
    ) -> list[LibraryVulnerability]:
        """Query OSV for all libraries, using cache when available."""
        vulnerabilities = []

        if not self.osv_client:
            return vulnerabilities

        # Separate cached vs uncached libraries
        uncached_libs = []
        cached_results: dict[str, list[CVEInfo]] = {}

        if self.cache:
            for lib in libraries:
                key = f"{lib.name}:{lib.version or 'unknown'}"
                cached = await self.cache.get_library_cves(lib.name, lib.version or "unknown")
                if cached is not None:
                    cached_results[key] = [
                        CVEInfo(**entry) for entry in cached
                    ]
                else:
                    uncached_libs.append(lib)
        else:
            uncached_libs = list(libraries)

        # Batch query only uncached libraries
        if uncached_libs:
            results = await self.osv_client.query_batch(uncached_libs)

            # Cache the results
            if self.cache:
                for lib in uncached_libs:
                    key = f"{lib.name}:{lib.version or 'unknown'}"
                    cves = results.get(key, [])
                    await self.cache.set_library_cves(
                        lib.name, lib.version or "unknown",
                        [self._cve_to_dict(c) for c in cves],
                    )
        else:
            results = {}

        # Merge cached + fresh results
        all_results = {**cached_results, **results}

        for lib in libraries:
            key = f"{lib.name}:{lib.version or 'unknown'}"
            cves = all_results.get(key, [])

            for cve in cves:
                vulnerabilities.append(LibraryVulnerability(
                    library=lib,
                    cve=cve,
                    is_vulnerable=True,
                    fixed_version=cve.fixed_versions[0] if cve.fixed_versions else None,
                ))

        return vulnerabilities

    @staticmethod
    def _cve_to_dict(cve: CVEInfo) -> dict:
        """Serialize CVEInfo to a dict for caching."""
        return {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "severity": cve.severity,
            "cvss_v3_score": str(cve.cvss_v3_score) if cve.cvss_v3_score else None,
            "cvss_v3_vector": cve.cvss_v3_vector,
            "cwe_ids": cve.cwe_ids,
            "affected_versions": cve.affected_versions,
            "fixed_versions": cve.fixed_versions,
            "references": cve.references,
            "exploit_available": cve.exploit_available,
        }

    async def _query_nvd(
        self,
        libraries: list[DetectedLibrary],
    ) -> list[LibraryVulnerability]:
        """Query NVD for all libraries using CPE matching."""
        vulnerabilities = []

        if not self.nvd_client:
            return vulnerabilities

        for lib in libraries:
            # Get CPE match
            cpe_match = self.cpe_matcher.match(lib)
            if not cpe_match:
                continue

            # Query NVD
            try:
                cves = await self.nvd_client.query_by_cpe(cpe_match)

                for cve in cves:
                    # Filter to matching versions if library has version
                    if lib.version and not self._version_affected(
                        lib.version,
                        cve.affected_versions,
                        cve.fixed_versions,
                    ):
                        continue

                    vulnerabilities.append(LibraryVulnerability(
                        library=lib,
                        cve=cve,
                        is_vulnerable=True,
                        fixed_version=cve.fixed_versions[0] if cve.fixed_versions else None,
                    ))

            except Exception as e:
                logger.warning(f"NVD query failed for {lib.name}: {e}")

        return vulnerabilities

    def _version_affected(
        self,
        version: str,
        affected: list[str],
        fixed: list[str],
    ) -> bool:
        """Check if a specific version is affected by a vulnerability.

        This is a simple check - production should use proper semver comparison.
        """
        # If no version info, assume affected
        if not affected and not fixed:
            return True

        # If version is in fixed list, not affected
        if version in fixed:
            return False

        # If version is explicitly in affected list
        if version in affected:
            return True

        # Try simple version comparison
        try:
            from packaging import version as pkg_version

            v = pkg_version.parse(version)

            # Check if version is before any fixed version
            for fix_ver in fixed:
                try:
                    fv = pkg_version.parse(fix_ver)
                    if v < fv:
                        return True
                except Exception:
                    pass

        except ImportError:
            # No packaging library, assume affected if we got here
            return True

        return True  # Conservative: assume affected if uncertain

    def _deduplicate_vulnerabilities(
        self,
        vulnerabilities: list[LibraryVulnerability],
    ) -> list[LibraryVulnerability]:
        """Remove duplicate vulnerability reports."""
        seen: dict[str, LibraryVulnerability] = {}

        for vuln in vulnerabilities:
            key = f"{vuln.library.name}:{vuln.cve.cve_id}"

            if key not in seen:
                seen[key] = vuln
            else:
                # Keep the one with more information
                existing = seen[key]
                if (vuln.cve.cvss_v3_score and not existing.cve.cvss_v3_score) or \
                   (vuln.fixed_version and not existing.fixed_version):
                    seen[key] = vuln

        return list(seen.values())

    def create_findings(
        self,
        vulnerabilities: list[LibraryVulnerability],
        app: MobileApp,
        scan_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Convert vulnerabilities to finding dictionaries.

        Args:
            vulnerabilities: List of detected vulnerabilities
            app: Mobile application
            scan_id: Optional scan ID

        Returns:
            List of finding dictionaries ready for database insertion
        """
        findings = []

        for vuln in vulnerabilities:
            finding = self._vulnerability_to_finding(vuln, app, scan_id)
            findings.append(finding)

        # Add summary finding if multiple vulnerabilities
        if len(vulnerabilities) > 1:
            summary = self._create_summary_finding(vulnerabilities, app, scan_id)
            findings.append(summary)

        return findings

    def _vulnerability_to_finding(
        self,
        vuln: LibraryVulnerability,
        app: MobileApp,
        scan_id: str | None,
    ) -> dict[str, Any]:
        """Convert a single vulnerability to finding dictionary."""
        lib = vuln.library
        cve = vuln.cve

        # Determine severity from CVSS or use CVE severity
        severity = cve.severity
        if cve.cvss_v3_score:
            score = float(cve.cvss_v3_score)
            if score >= 9.0:
                severity = "critical"
            elif score >= 7.0:
                severity = "high"
            elif score >= 4.0:
                severity = "medium"
            else:
                severity = "low"

        # Build remediation text
        remediation = f"Update {lib.name} to a non-vulnerable version."
        if vuln.fixed_version:
            remediation = f"Update {lib.name} to version {vuln.fixed_version} or later."

        # Build description
        description = f"The library '{lib.name}'"
        if lib.version:
            description += f" version {lib.version}"
        description += f" is affected by {cve.cve_id}.\n\n"
        description += cve.description

        return {
            "finding_id": f"cve_{cve.cve_id}_{lib.name}".replace(".", "_"),
            "scan_id": scan_id,
            "app_id": app.app_id,
            "tool": "cve_detector",
            "platform": app.platform,
            "severity": severity,
            "category": "Vulnerable Dependencies",
            "title": f"{cve.cve_id}: Vulnerability in {lib.name}",
            "description": description,
            "impact": f"This vulnerability may allow attackers to {self._get_impact_description(cve)}",
            "remediation": remediation,
            "file_path": lib.file_path,
            "cvss_score": cve.cvss_v3_score,
            "cvss_vector": cve.cvss_v3_vector,
            "cwe_id": cve.cwe_ids[0] if cve.cwe_ids else "CWE-1395",
            "cwe_name": "Dependency on Vulnerable Third-Party Component",
            "owasp_masvs_category": "MASVS-CODE",
            "owasp_masvs_control": "MSTG-CODE-5",
            "poc_evidence": f"Library: {lib.name}:{lib.version or 'unknown'}\nCVE: {cve.cve_id}",
            "metadata": {
                "cve_id": cve.cve_id,
                "library_name": lib.name,
                "library_version": lib.version,
                "library_source": lib.source.value,
                "detection_method": lib.detection_method.value,
                "fixed_versions": cve.fixed_versions,
                "references": cve.references[:5],
                "exploit_available": cve.exploit_available,
                "cpe": lib.cpe,
            },
        }

    def _create_summary_finding(
        self,
        vulnerabilities: list[LibraryVulnerability],
        app: MobileApp,
        scan_id: str | None,
    ) -> dict[str, Any]:
        """Create a summary finding for all vulnerabilities."""
        # Count by severity
        critical = sum(1 for v in vulnerabilities if v.cve.severity == "critical")
        high = sum(1 for v in vulnerabilities if v.cve.severity == "high")
        medium = sum(1 for v in vulnerabilities if v.cve.severity == "medium")
        low = sum(1 for v in vulnerabilities if v.cve.severity == "low")

        # Unique libraries affected
        affected_libs = set(v.library.name for v in vulnerabilities)

        # Overall severity
        if critical > 0:
            severity = "critical"
        elif high > 0:
            severity = "high"
        elif medium > 0:
            severity = "medium"
        else:
            severity = "low"

        # Build description
        lib_list = "\n".join([
            f"- {v.library.name}:{v.library.version or 'unknown'} ({v.cve.cve_id})"
            for v in vulnerabilities[:15]
        ])

        return {
            "finding_id": f"cve_summary_{app.app_id}",
            "scan_id": scan_id,
            "app_id": app.app_id,
            "tool": "cve_detector",
            "platform": app.platform,
            "severity": severity,
            "category": "Vulnerable Dependencies",
            "title": f"Multiple CVEs Detected ({len(vulnerabilities)} vulnerabilities in {len(affected_libs)} libraries)",
            "description": f"The application uses libraries with {len(vulnerabilities)} known vulnerabilities:\n\nCritical: {critical}, High: {high}, Medium: {medium}, Low: {low}\n\nAffected components:\n{lib_list}",
            "impact": "Using vulnerable libraries exposes the application to known exploits that may allow data theft, code execution, or denial of service.",
            "remediation": "1. Update all vulnerable dependencies to their latest secure versions\n2. Enable dependency scanning in CI/CD\n3. Use automated security updates (Dependabot, Renovate)\n4. Review and minimize unnecessary dependencies",
            "cwe_id": "CWE-1395",
            "cwe_name": "Dependency on Vulnerable Third-Party Component",
            "owasp_masvs_category": "MASVS-CODE",
            "owasp_masvs_control": "MSTG-CODE-5",
            "metadata": {
                "total_vulnerabilities": len(vulnerabilities),
                "affected_libraries": list(affected_libs),
                "critical_count": critical,
                "high_count": high,
                "medium_count": medium,
                "low_count": low,
            },
        }

    def _get_impact_description(self, cve: CVEInfo) -> str:
        """Generate impact description based on CWE."""
        cwe_impacts = {
            "CWE-79": "execute malicious scripts in user browsers (XSS)",
            "CWE-89": "execute arbitrary database queries (SQL Injection)",
            "CWE-78": "execute arbitrary system commands",
            "CWE-94": "execute arbitrary code",
            "CWE-287": "bypass authentication mechanisms",
            "CWE-200": "access sensitive information",
            "CWE-22": "access files outside intended directories (Path Traversal)",
            "CWE-352": "perform unauthorized actions (CSRF)",
            "CWE-502": "execute code through insecure deserialization",
            "CWE-918": "make unauthorized requests (SSRF)",
        }

        for cwe_id in cve.cwe_ids:
            short_id = cwe_id.replace("CWE-", "")
            full_id = f"CWE-{short_id}"
            if full_id in cwe_impacts:
                return cwe_impacts[full_id]

        return "compromise application security through known exploit techniques"
