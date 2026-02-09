"""Redis-backed CVE cache with configurable TTL.

Caches CVE lookups and library vulnerability queries to reduce
external API calls to NVD and OSV databases.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_TTL = 86400  # 24 hours


class CVECache:
    """Redis-backed cache for CVE data.

    Key scheme:
        cve:{cve_id}           — single CVE info
        lib_cves:{name}:{ver}  — library vulnerability results
    """

    def __init__(self, redis_client: Any, ttl: int = DEFAULT_TTL):
        """Initialize cache.

        Args:
            redis_client: Redis client instance (sync or async)
            ttl: Cache TTL in seconds (default: 24 hours)
        """
        self.redis = redis_client
        self.ttl = ttl

    async def get_cve(self, cve_id: str) -> dict | None:
        """Get cached CVE data.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-1234")

        Returns:
            Cached CVE data dict, or None if not cached
        """
        key = f"cve:{cve_id}"
        try:
            data = await self.redis.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(f"Cache get failed for {key}: {e}")
        return None

    async def set_cve(self, cve_id: str, data: dict) -> None:
        """Cache CVE data.

        Args:
            cve_id: CVE identifier
            data: CVE data to cache
        """
        key = f"cve:{cve_id}"
        try:
            await self.redis.set(key, json.dumps(data, default=str), ex=self.ttl)
        except Exception as e:
            logger.warning(f"Cache set failed for {key}: {e}")

    @staticmethod
    def _sanitize_key(value: str) -> str:
        """Sanitize a value for use in Redis keys."""
        return value.replace(":", "_").replace(" ", "_")[:200]

    async def get_library_cves(self, name: str, version: str) -> list[dict] | None:
        """Get cached library vulnerability results.

        Args:
            name: Library name
            version: Library version

        Returns:
            Cached vulnerability list, or None if not cached
        """
        key = f"lib_cves:{self._sanitize_key(name)}:{self._sanitize_key(version)}"
        try:
            data = await self.redis.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(f"Cache get failed for {key}: {e}")
        return None

    async def set_library_cves(self, name: str, version: str, cves: list[dict]) -> None:
        """Cache library vulnerability results.

        Args:
            name: Library name
            version: Library version
            cves: List of CVE data dicts
        """
        key = f"lib_cves:{self._sanitize_key(name)}:{self._sanitize_key(version)}"
        try:
            await self.redis.set(key, json.dumps(cves, default=str), ex=self.ttl)
        except Exception as e:
            logger.warning(f"Cache set failed for {key}: {e}")

    async def invalidate_cve(self, cve_id: str) -> None:
        """Remove a specific CVE from cache."""
        try:
            await self.redis.delete(f"cve:{cve_id}")
        except Exception as e:
            logger.warning(f"Cache invalidate failed for {cve_id}: {e}")

    async def clear_all(self) -> int:
        """Clear all CVE cache entries.

        Returns:
            Number of keys deleted
        """
        count = 0
        try:
            async for key in self.redis.scan_iter("cve:*"):
                await self.redis.delete(key)
                count += 1
            async for key in self.redis.scan_iter("lib_cves:*"):
                await self.redis.delete(key)
                count += 1
        except Exception as e:
            logger.warning(f"Cache clear failed: {e}")
        return count
