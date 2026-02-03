"""
Tests for health check router.
"""

import pytest
from fastapi.testclient import TestClient


class TestHealthRouter:
    """Tests for the health check endpoints."""

    def test_health_check(self, client: TestClient):
        """Test basic health check returns 200."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_root_endpoint(self, client: TestClient):
        """Test root endpoint returns API info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Mobilicustos"
        assert "version" in data
        assert "description" in data
