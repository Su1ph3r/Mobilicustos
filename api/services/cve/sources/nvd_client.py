"""NVD (National Vulnerability Database) API client."""

import logging
import os
from decimal import Decimal
from datetime import datetime
from typing import Any

import httpx

from api.services.cve.models import CVEInfo
from api.services.cve.cpe_matcher import CPEMatch

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient:
    """Client for NVD CVE database."""

    def __init__(
        self,
        api_key: str | None = None,
        timeout: int = 30,
    ):
        """Initialize NVD client.

        Args:
            api_key: NVD API key for higher rate limits (optional)
            timeout: Request timeout in seconds
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.timeout = timeout
        self.base_url = NVD_API_URL

    async def query_by_cpe(
        self,
        cpe_match: CPEMatch,
        results_per_page: int = 20,
    ) -> list[CVEInfo]:
        """Query NVD for CVEs affecting a CPE.

        Args:
            cpe_match: CPE match information
            results_per_page: Number of results per page

        Returns:
            List of CVE information
        """
        params = {
            "cpeName": cpe_match.cpe_string,
            "resultsPerPage": results_per_page,
        }

        return await self._query(params)

    async def query_by_keyword(
        self,
        keyword: str,
        results_per_page: int = 20,
    ) -> list[CVEInfo]:
        """Query NVD by keyword search.

        Args:
            keyword: Search keyword
            results_per_page: Number of results per page

        Returns:
            List of CVE information
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        }

        return await self._query(params)

    async def get_cve_details(self, cve_id: str) -> CVEInfo | None:
        """Get detailed information about a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-1234")

        Returns:
            CVE information or None
        """
        params = {
            "cveId": cve_id,
        }

        results = await self._query(params)
        return results[0] if results else None

    async def query_recent(
        self,
        days: int = 30,
        results_per_page: int = 100,
    ) -> list[CVEInfo]:
        """Query recently published/modified CVEs.

        Args:
            days: Number of days to look back
            results_per_page: Number of results per page

        Returns:
            List of CVE information
        """
        from datetime import timedelta

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": results_per_page,
        }

        return await self._query(params)

    async def _query(self, params: dict[str, Any]) -> list[CVEInfo]:
        """Execute NVD API query.

        Args:
            params: Query parameters

        Returns:
            List of CVE information
        """
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

                return self._parse_response(data)

        except httpx.TimeoutException:
            logger.warning("NVD query timeout")
            return []
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.warning("NVD rate limit exceeded. Consider using an API key.")
            else:
                logger.warning(f"NVD query failed: {e}")
            return []
        except Exception as e:
            logger.warning(f"NVD query error: {e}")
            return []

    def _parse_response(self, data: dict) -> list[CVEInfo]:
        """Parse NVD API response."""
        vulnerabilities = []

        for vuln_item in data.get("vulnerabilities", []):
            cve = vuln_item.get("cve", {})
            cve_info = self._parse_cve(cve)
            if cve_info:
                vulnerabilities.append(cve_info)

        return vulnerabilities

    def _parse_cve(self, cve: dict) -> CVEInfo | None:
        """Parse a single CVE from NVD response."""
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Parse description
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Parse CVSS
        cvss_score, cvss_vector, severity = self._parse_cvss(cve)

        # Parse CWE IDs
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwe_ids.append(cwe_value)

        # Parse affected configurations (for version info)
        affected_versions = []
        fixed_versions = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        if match.get("versionStartIncluding"):
                            affected_versions.append(match["versionStartIncluding"])
                        if match.get("versionEndExcluding"):
                            fixed_versions.append(match["versionEndExcluding"])

        # Parse references
        references = [
            ref.get("url")
            for ref in cve.get("references", [])
            if ref.get("url")
        ][:10]

        # Check for exploits
        exploit_available = any(
            "Exploit" in ref.get("tags", [])
            for ref in cve.get("references", [])
        )

        # Parse dates
        published = None
        modified = None
        if cve.get("published"):
            try:
                published = datetime.fromisoformat(
                    cve["published"].replace("Z", "+00:00")
                )
            except ValueError:
                pass
        if cve.get("lastModified"):
            try:
                modified = datetime.fromisoformat(
                    cve["lastModified"].replace("Z", "+00:00")
                )
            except ValueError:
                pass

        return CVEInfo(
            cve_id=cve_id,
            description=description[:1000],
            severity=severity,
            cvss_v3_score=cvss_score,
            cvss_v3_vector=cvss_vector,
            cwe_ids=cwe_ids,
            affected_versions=affected_versions,
            fixed_versions=fixed_versions,
            references=references,
            published_date=published,
            last_modified=modified,
            exploit_available=exploit_available,
        )

    def _parse_cvss(self, cve: dict) -> tuple[Decimal | None, str | None, str]:
        """Extract CVSS information from CVE.

        Returns:
            Tuple of (score, vector, severity)
        """
        metrics = cve.get("metrics", {})

        # Try CVSS v3.1 first
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            cvss_data = cvss_v31[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity", "MEDIUM").lower()

            return (
                Decimal(str(score)) if score else None,
                vector,
                severity,
            )

        # Try CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            cvss_data = cvss_v30[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity", "MEDIUM").lower()

            return (
                Decimal(str(score)) if score else None,
                vector,
                severity,
            )

        # Fallback to CVSS v2
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            cvss_data = cvss_v2[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")

            # Convert v2 severity
            if score:
                if score >= 7.0:
                    severity = "high"
                elif score >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"
            else:
                severity = "medium"

            return (
                Decimal(str(score)) if score else None,
                vector,
                severity,
            )

        return None, None, "medium"
