"""
Tests for secrets router.
"""

import pytest
from uuid import uuid4
from fastapi.testclient import TestClient


class TestSecretsRouter:
    """Tests for the secrets API endpoints."""

    def test_list_secrets(self, client: TestClient):
        """Test listing secrets."""
        response = client.get("/api/secrets")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data or isinstance(data, list)

    def test_list_secrets_by_app(self, client: TestClient):
        """Test listing secrets filtered by app."""
        response = client.get("/api/secrets?app_id=test-app-123")
        assert response.status_code == 200

    def test_list_secrets_by_type(self, client: TestClient):
        """Test listing secrets filtered by type."""
        response = client.get("/api/secrets?secret_type=api_key")
        assert response.status_code == 200

    def test_get_secret_not_found(self, client: TestClient):
        """Test getting a non-existent secret."""
        fake_uuid = str(uuid4())
        response = client.get(f"/api/secrets/{fake_uuid}")
        assert response.status_code == 404

    def test_get_secret_invalid_uuid(self, client: TestClient):
        """Test getting secret with invalid UUID returns 422."""
        response = client.get("/api/secrets/not-a-valid-uuid")
        assert response.status_code == 422

    def test_get_secrets_summary(self, client: TestClient):
        """Test getting secrets summary."""
        response = client.get("/api/secrets/summary")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data or isinstance(data, dict)

    def test_validate_secret_not_found(self, client: TestClient):
        """Test validating a non-existent secret."""
        fake_uuid = str(uuid4())
        response = client.post(f"/api/secrets/{fake_uuid}/validate")
        assert response.status_code == 404

    def test_get_secret_types(self, client: TestClient):
        """Test getting available secret types."""
        response = client.get("/api/secrets/types")
        assert response.status_code == 200
        data = response.json()
        assert "types" in data

    def test_get_providers(self, client: TestClient):
        """Test getting available providers."""
        response = client.get("/api/secrets/providers")
        assert response.status_code == 200
        data = response.json()
        assert "providers" in data
