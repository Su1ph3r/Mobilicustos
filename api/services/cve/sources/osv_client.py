"""OSV (Open Source Vulnerabilities) API client."""

import logging
from decimal import Decimal
from datetime import datetime
from typing import Any

import httpx

from api.services.cve.models import CVEInfo, DetectedLibrary, LibrarySource

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1"


# Ecosystem mapping for OSV
ECOSYSTEM_MAP = {
    LibrarySource.GRADLE: "Maven",
    LibrarySource.COCOAPODS: "CocoaPods",
    LibrarySource.NPM: "npm",
    LibrarySource.PUB: "Pub",
    LibrarySource.NATIVE: None,  # OSV doesn't track native libs directly
    LibrarySource.SDK: "Maven",  # Most SDKs are Maven
    LibrarySource.FRAMEWORK: None,
}


class OSVClient:
    """Client for OSV vulnerability database."""

    def __init__(self, timeout: int = 10):
        """Initialize OSV client.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.base_url = OSV_API_URL

    async def query_vulnerability(
        self,
        library: DetectedLibrary,
    ) -> list[CVEInfo]:
        """Query OSV for vulnerabilities affecting a library.

        Args:
            library: Detected library to check

        Returns:
            List of CVE information
        """
        ecosystem = ECOSYSTEM_MAP.get(library.source)
        if ecosystem is None:
            logger.debug(f"No OSV ecosystem for {library.source}, skipping")
            return []

        # Build query payload
        payload = self._build_query_payload(library, ecosystem)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/query",
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()

                return self._parse_response(data)

        except httpx.TimeoutException:
            logger.warning(f"OSV query timeout for {library.name}")
            return []
        except httpx.HTTPError as e:
            logger.warning(f"OSV query failed for {library.name}: {e}")
            return []

    async def query_batch(
        self,
        libraries: list[DetectedLibrary],
    ) -> dict[str, list[CVEInfo]]:
        """Query OSV for multiple libraries in batch.

        Args:
            libraries: List of libraries to check

        Returns:
            Dictionary mapping library name to CVE list
        """
        results: dict[str, list[CVEInfo]] = {}

        # Build batch query
        queries = []
        lib_indices: dict[int, DetectedLibrary] = {}

        for i, library in enumerate(libraries):
            ecosystem = ECOSYSTEM_MAP.get(library.source)
            if ecosystem is None:
                continue

            queries.append(self._build_query_payload(library, ecosystem))
            lib_indices[len(queries) - 1] = library

        if not queries:
            return results

        # Chunk into batches of 50 to avoid OSV API limits
        batch_size = 50

        try:
            async with httpx.AsyncClient(timeout=self.timeout * 2) as client:
                for chunk_start in range(0, len(queries), batch_size):
                    chunk = queries[chunk_start:chunk_start + batch_size]
                    response = await client.post(
                        f"{self.base_url}/querybatch",
                        json={"queries": chunk},
                    )
                    response.raise_for_status()
                    data = response.json()

                    for i, result in enumerate(data.get("results", [])):
                        abs_idx = chunk_start + i
                        library = lib_indices.get(abs_idx)
                        if library:
                            key = f"{library.name}:{library.version or 'unknown'}"
                            results[key] = self._parse_response(result)

        except Exception as e:
            logger.warning(f"OSV batch query failed: {e}")
            # Fall back to individual queries
            for library in libraries:
                key = f"{library.name}:{library.version or 'unknown'}"
                results[key] = await self.query_vulnerability(library)

        return results

    async def get_vulnerability_details(self, vuln_id: str) -> CVEInfo | None:
        """Get detailed information about a specific vulnerability.

        Args:
            vuln_id: Vulnerability ID (CVE, GHSA, etc.)

        Returns:
            CVE information or None
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/vulns/{vuln_id}",
                )
                response.raise_for_status()
                data = response.json()

                return self._parse_vulnerability(data)

        except Exception as e:
            logger.warning(f"Failed to get details for {vuln_id}: {e}")
            return None

    def _build_query_payload(
        self,
        library: DetectedLibrary,
        ecosystem: str,
    ) -> dict[str, Any]:
        """Build OSV query payload."""
        # Extract package name (remove group ID for Maven)
        package_name = library.name
        if ":" in package_name:
            # Maven format: group:artifact
            package_name = package_name.split(":")[-1]

        payload: dict[str, Any] = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            }
        }

        if library.version:
            payload["version"] = library.version

        return payload

    def _parse_response(self, data: dict) -> list[CVEInfo]:
        """Parse OSV API response."""
        vulnerabilities = []

        for vuln in data.get("vulns", []):
            cve_info = self._parse_vulnerability(vuln)
            if cve_info:
                vulnerabilities.append(cve_info)

        return vulnerabilities

    def _parse_vulnerability(self, vuln: dict) -> CVEInfo | None:
        """Parse a single OSV vulnerability."""
        vuln_id = vuln.get("id", "")

        # Get CVE ID if available (prefer CVE over GHSA, etc.)
        cve_id = vuln_id
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        # Parse severity
        severity = self._parse_severity(vuln)
        cvss_score, cvss_vector = self._parse_cvss(vuln)

        # Parse CWE IDs
        cwe_ids = []
        for cwe in vuln.get("database_specific", {}).get("cwe_ids", []):
            cwe_ids.append(cwe)

        # Parse affected versions and fixed versions
        affected_versions = []
        fixed_versions = []
        for affected in vuln.get("affected", []):
            for range_info in affected.get("ranges", []):
                for event in range_info.get("events", []):
                    if "introduced" in event:
                        affected_versions.append(event["introduced"])
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

        # Parse references
        references = [ref.get("url") for ref in vuln.get("references", []) if ref.get("url")]

        # Parse dates
        published = None
        modified = None
        if vuln.get("published"):
            try:
                published = datetime.fromisoformat(vuln["published"].replace("Z", "+00:00"))
            except ValueError:
                pass
        if vuln.get("modified"):
            try:
                modified = datetime.fromisoformat(vuln["modified"].replace("Z", "+00:00"))
            except ValueError:
                pass

        return CVEInfo(
            cve_id=cve_id,
            description=vuln.get("summary", vuln.get("details", ""))[:500],
            severity=severity,
            cvss_v3_score=cvss_score,
            cvss_v3_vector=cvss_vector,
            cwe_ids=cwe_ids,
            affected_versions=affected_versions,
            fixed_versions=fixed_versions,
            references=references[:10],  # Limit references
            published_date=published,
            last_modified=modified,
        )

    def _parse_severity(self, vuln: dict) -> str:
        """Extract severity from OSV vulnerability."""
        # Try severity array
        severity_info = vuln.get("severity", [])
        if severity_info:
            for sev in severity_info:
                if sev.get("type") == "CVSS_V3":
                    score = sev.get("score", "")
                    try:
                        if ":" in score:
                            # CVSS vector format
                            cvss_score = float(score.split("/")[0].split(":")[1])
                        else:
                            cvss_score = float(score)

                        if cvss_score >= 9.0:
                            return "critical"
                        elif cvss_score >= 7.0:
                            return "high"
                        elif cvss_score >= 4.0:
                            return "medium"
                        else:
                            return "low"
                    except (ValueError, IndexError):
                        pass

        # Fallback to database_specific
        db_specific = vuln.get("database_specific", {})
        if "severity" in db_specific:
            return db_specific["severity"].lower()

        return "medium"

    def _parse_cvss(self, vuln: dict) -> tuple[Decimal | None, str | None]:
        """Extract CVSS score and vector from vulnerability."""
        severity_info = vuln.get("severity", [])

        for sev in severity_info:
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                try:
                    if "CVSS:" in score_str:
                        # Full vector format
                        # Extract score from first metric
                        parts = score_str.split("/")
                        for part in parts:
                            if part.startswith("CVSS:3"):
                                continue
                            if ":" in part:
                                # This is a metric, not the score
                                continue
                        # Try to calculate from vector or use database
                        return None, score_str
                    else:
                        return Decimal(score_str), None
                except (ValueError, IndexError):
                    pass

        return None, None
