"""
Tests for findings router.
"""

import pytest
from uuid import uuid4
from fastapi.testclient import TestClient


class TestFindingsRouter:
    """Tests for the findings API endpoints."""

    def test_list_findings_empty(self, client: TestClient):
        """Test listing findings when none exist."""
        response = client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_list_findings_with_filters(self, client: TestClient):
        """Test listing findings with severity filter."""
        response = client.get("/api/findings?severity=critical&severity=high")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data

    def test_list_findings_by_app(self, client: TestClient):
        """Test filtering findings by app_id."""
        response = client.get("/api/findings?app_id=test-app-123")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data

    def test_list_findings_by_scan(self, client: TestClient):
        """Test filtering findings by scan_id (must be valid UUID)."""
        fake_uuid = str(uuid4())
        response = client.get(f"/api/findings?scan_id={fake_uuid}")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data

    def test_get_finding_not_found(self, client: TestClient):
        """Test getting a non-existent finding returns 404."""
        response = client.get("/api/findings/nonexistent-finding-id")
        assert response.status_code == 404

    def test_get_findings_summary(self, client: TestClient):
        """Test getting findings summary."""
        response = client.get("/api/findings/summary")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "by_severity" in data

    def test_get_findings_summary_by_app(self, client: TestClient):
        """Test getting findings summary filtered by app."""
        response = client.get("/api/findings/summary?app_id=test-app-123")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data

    def test_update_finding_status_not_found(self, client: TestClient):
        """Test updating status of non-existent finding."""
        response = client.patch(
            "/api/findings/nonexistent-id/status",
            params={"new_status": "confirmed"}
        )
        assert response.status_code == 404

    def test_bulk_update_status_empty(self, client: TestClient):
        """Test bulk update with empty list."""
        response = client.post(
            "/api/findings/bulk-status",
            json=[],
            params={"new_status": "confirmed"}
        )
        # Empty list finds no matching findings, so 404 is expected
        assert response.status_code in [200, 400, 404]

    def test_get_filter_options(self, client: TestClient):
        """Test getting available filter options."""
        response = client.get("/api/findings/filters/options")
        assert response.status_code == 200
        data = response.json()
        assert "severities" in data
        assert "statuses" in data
