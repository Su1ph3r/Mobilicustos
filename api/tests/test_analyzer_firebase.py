"""Tests for FirebaseAnalyzer."""

import json
import pytest
from unittest.mock import patch, AsyncMock
from api.tests.conftest import create_test_archive, make_mock_app


GOOGLE_SERVICES = json.dumps({
    "project_info": {
        "project_id": "test-firebase-project",
        "firebase_url": "https://test-firebase-project.firebaseio.com",
        "project_number": "123456789",
        "storage_bucket": "test-firebase-project.appspot.com",
    },
    "client": [
        {
            "client_info": {
                "mobilesdk_app_id": "1:123456789:android:abc123",
                "android_client_info": {"package_name": "com.example.testapp"},
            },
            "api_key": [{"current_key": "AIzaSyTestKey12345678901234567890AB"}],
        }
    ],
})


class TestFirebaseAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.firebase_analyzer import FirebaseAnalyzer
        return FirebaseAnalyzer()

    @pytest.fixture
    def firebase_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "google-services.json": GOOGLE_SERVICES,
        })

    @pytest.fixture
    def no_firebase_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "res/values/strings.xml": "<resources></resources>",
        })

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_analyze_detects_firebase_config(self, mock_get, analyzer, firebase_app):
        # Mock HTTP calls to Firebase to avoid real network requests
        mock_response = AsyncMock()
        mock_response.status_code = 401
        mock_response.text = "Permission denied"
        mock_get.return_value = mock_response
        findings = await analyzer.analyze(firebase_app)
        assert isinstance(findings, list)
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_no_firebase_returns_empty(self, analyzer, no_firebase_app):
        findings = await analyzer.analyze(no_firebase_app)
        assert findings == []

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_findings_have_required_fields(self, mock_get, analyzer, firebase_app):
        mock_response = AsyncMock()
        mock_response.status_code = 401
        mock_response.text = "Permission denied"
        mock_get.return_value = mock_response
        findings = await analyzer.analyze(firebase_app)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "firebase_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
