"""FIRST.org EPSS (Exploit Prediction Scoring System) API client.

Fetches exploit probability scores for CVEs to help prioritize
remediation based on likelihood of exploitation.
"""

import logging
from dataclasses import dataclass
from decimal import Decimal

import httpx

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"


@dataclass
class EPSSScore:
    """EPSS score for a CVE."""
    cve_id: str
    epss_score: Decimal  # Probability of exploitation (0.0-1.0)
    percentile: Decimal   # Percentile rank (0.0-1.0)


class EPSSClient:
    """Client for FIRST.org EPSS API."""

    def __init__(self, timeout: int = 15):
        """Initialize EPSS client.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.base_url = EPSS_API_URL

    async def get_scores(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Get EPSS scores for a list of CVE IDs.

        Batches up to 100 CVE IDs per request per FIRST.org API limits.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping CVE ID to EPSSScore
        """
        if not cve_ids:
            return {}

        results: dict[str, EPSSScore] = {}

        # Batch into chunks of 100
        for i in range(0, len(cve_ids), 100):
            chunk = cve_ids[i:i + 100]
            chunk_results = await self._fetch_batch(chunk)
            results.update(chunk_results)

        return results

    async def get_score(self, cve_id: str) -> EPSSScore | None:
        """Get EPSS score for a single CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            EPSSScore or None if not found
        """
        results = await self.get_scores([cve_id])
        return results.get(cve_id)

    async def _fetch_batch(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Fetch EPSS scores for a batch of CVE IDs.

        Args:
            cve_ids: List of CVE IDs (max 100)

        Returns:
            Dictionary mapping CVE ID to EPSSScore
        """
        results: dict[str, EPSSScore] = {}

        try:
            params = {"cve": ",".join(cve_ids)}
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()
                data = response.json()

                for item in data.get("data", []):
                    cve_id = item.get("cve", "")
                    if not cve_id:
                        continue
                    try:
                        results[cve_id] = EPSSScore(
                            cve_id=cve_id,
                            epss_score=Decimal(str(item.get("epss", "0"))),
                            percentile=Decimal(str(item.get("percentile", "0"))),
                        )
                    except Exception:
                        continue

        except httpx.TimeoutException:
            logger.warning("EPSS query timeout")
        except httpx.HTTPStatusError as e:
            logger.warning(f"EPSS query failed: {e}")
        except Exception as e:
            logger.warning(f"EPSS query error: {e}")

        return results
