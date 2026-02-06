"""
Tests for bypass router.
"""

import pytest
from fastapi.testclient import TestClient


class TestBypassRouter:
    """Tests for the bypass API endpoints."""

    def test_list_results(self, client: TestClient):
        """Test listing bypass results."""
        response = client.get("/api/bypass/results")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data or isinstance(data, list)

    def test_list_results_by_app(self, client: TestClient):
        """Test listing bypass results filtered by app."""
        response = client.get("/api/bypass/results?app_id=test-app-123")
        assert response.status_code == 200

    def test_analyze_protections_missing_app(self, client: TestClient):
        """Test analyzing protections for non-existent app."""
        response = client.post("/api/bypass/analyze", params={"app_id": "nonexistent-app"})
        assert response.status_code in [400, 404]

    def test_attempt_bypass_validation(self, client: TestClient):
        """Test bypass attempt with incomplete data."""
        response = client.post("/api/bypass/attempt", params={
            "app_id": "test-app-123",
            # Missing device_id and detection_type
        })
        assert response.status_code == 422

    def test_auto_bypass_missing_params(self, client: TestClient):
        """Test auto bypass with missing parameters."""
        response = client.post("/api/bypass/auto-bypass", params={
            "app_id": "test-app-123"
            # Missing device_id
        })
        assert response.status_code == 422

    def test_get_detection_types(self, client: TestClient):
        """Test getting available detection types."""
        response = client.get("/api/bypass/detection-types")
        assert response.status_code == 200
        data = response.json()
        # API returns {"detection_types": [...]} or a list
        if isinstance(data, dict):
            assert "detection_types" in data
            types_list = data["detection_types"]
        else:
            types_list = data
        assert isinstance(types_list, list)

    def test_get_recommended_scripts(self, client: TestClient):
        """Test getting recommended bypass scripts."""
        response = client.get("/api/bypass/scripts/recommended", params={
            "app_id": "test-app-123",
            "detection_type": "ssl_pinning",
        })
        assert response.status_code in [200, 404]
