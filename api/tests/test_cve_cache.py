"""Tests for CVE Redis cache."""

import json
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from api.services.cve.cache import CVECache


class FakeRedis:
    """In-memory fake Redis for testing (async interface)."""

    def __init__(self):
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value
        if ex:
            self.ttls[key] = ex

    async def delete(self, key: str) -> None:
        self.store.pop(key, None)
        self.ttls.pop(key, None)

    async def scan_iter(self, pattern: str):
        prefix = pattern.replace("*", "")
        for key in list(self.store.keys()):
            if key.startswith(prefix):
                yield key


class TestCVECache:
    @pytest_asyncio.fixture
    async def cache(self):
        redis = FakeRedis()
        return CVECache(redis_client=redis, ttl=3600)

    @pytest.mark.asyncio
    async def test_set_and_get_cve(self, cache):
        cve_data = {"cve_id": "CVE-2023-1234", "severity": "high"}
        await cache.set_cve("CVE-2023-1234", cve_data)
        result = await cache.get_cve("CVE-2023-1234")
        assert result == cve_data

    @pytest.mark.asyncio
    async def test_get_missing_cve_returns_none(self, cache):
        result = await cache.get_cve("CVE-9999-0000")
        assert result is None

    @pytest.mark.asyncio
    async def test_set_and_get_library_cves(self, cache):
        cves = [
            {"cve_id": "CVE-2023-1234", "severity": "high"},
            {"cve_id": "CVE-2023-5678", "severity": "medium"},
        ]
        await cache.set_library_cves("okhttp", "4.9.0", cves)
        result = await cache.get_library_cves("okhttp", "4.9.0")
        assert result == cves

    @pytest.mark.asyncio
    async def test_get_missing_library_returns_none(self, cache):
        result = await cache.get_library_cves("nonexistent", "1.0.0")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalidate_cve(self, cache):
        await cache.set_cve("CVE-2023-1234", {"severity": "high"})
        await cache.invalidate_cve("CVE-2023-1234")
        result = await cache.get_cve("CVE-2023-1234")
        assert result is None

    @pytest.mark.asyncio
    async def test_clear_all(self, cache):
        await cache.set_cve("CVE-2023-1234", {"severity": "high"})
        await cache.set_library_cves("okhttp", "4.9.0", [])
        count = await cache.clear_all()
        assert count == 2
        assert await cache.get_cve("CVE-2023-1234") is None
        assert await cache.get_library_cves("okhttp", "4.9.0") is None

    @pytest.mark.asyncio
    async def test_ttl_is_set(self, cache):
        await cache.set_cve("CVE-2023-1234", {"severity": "high"})
        assert cache.redis.ttls["cve:CVE-2023-1234"] == 3600

    @pytest.mark.asyncio
    async def test_cache_handles_redis_errors_gracefully(self):
        """Cache should not raise on Redis errors."""
        broken_redis = AsyncMock()
        broken_redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))
        broken_redis.set = AsyncMock(side_effect=ConnectionError("Redis down"))

        cache = CVECache(redis_client=broken_redis, ttl=3600)
        result = await cache.get_cve("CVE-2023-1234")
        assert result is None

        # Should not raise
        await cache.set_cve("CVE-2023-1234", {"severity": "high"})
