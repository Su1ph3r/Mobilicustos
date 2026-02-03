"""
Tests for scans router.
"""

import pytest
from uuid import uuid4
from fastapi.testclient import TestClient


class TestScansRouter:
    """Tests for the scans API endpoints."""

    def test_list_scans_empty(self, client: TestClient):
        """Test listing scans when none exist."""
        response = client.get("/api/scans")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_list_scans_with_filters(self, client: TestClient):
        """Test listing scans with various filters."""
        response = client.get("/api/scans?status=running&scan_type=static")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data

    def test_get_scan_not_found(self, client: TestClient):
        """Test getting a non-existent scan returns 404."""
        # Use a valid UUID format that doesn't exist
        fake_uuid = str(uuid4())
        response = client.get(f"/api/scans/{fake_uuid}")
        assert response.status_code == 404

    def test_get_scan_invalid_uuid(self, client: TestClient):
        """Test getting scan with invalid UUID returns 422."""
        response = client.get("/api/scans/not-a-valid-uuid")
        assert response.status_code == 422

    def test_create_scan_missing_app(self, client: TestClient):
        """Test creating scan for non-existent app."""
        response = client.post("/api/scans", json={
            "app_id": "nonexistent-app-id",
            "scan_type": "static",
        })
        assert response.status_code in [400, 404]

    def test_create_scan_invalid_type(self, client: TestClient):
        """Test creating scan with invalid scan type."""
        response = client.post("/api/scans", json={
            "app_id": "some-app-id",
            "scan_type": "invalid_type",
        })
        assert response.status_code == 422  # Validation error

    def test_cancel_scan_not_found(self, client: TestClient):
        """Test cancelling a non-existent scan returns 404."""
        fake_uuid = str(uuid4())
        response = client.post(f"/api/scans/{fake_uuid}/cancel")
        assert response.status_code == 404

    def test_cancel_scan_invalid_uuid(self, client: TestClient):
        """Test cancelling scan with invalid UUID returns 422."""
        response = client.post("/api/scans/not-a-uuid/cancel")
        assert response.status_code == 422

    def test_get_scan_progress_not_found(self, client: TestClient):
        """Test getting progress for non-existent scan returns 404."""
        fake_uuid = str(uuid4())
        response = client.get(f"/api/scans/{fake_uuid}/progress")
        assert response.status_code == 404

    def test_delete_scan_not_found(self, client: TestClient):
        """Test deleting a non-existent scan returns 404."""
        fake_uuid = str(uuid4())
        response = client.delete(f"/api/scans/{fake_uuid}")
        assert response.status_code == 404
