"""Tests for ReactNativeAnalyzer."""

import pytest
from unittest.mock import patch, AsyncMock
from api.tests.conftest import make_mock_app


class TestReactNativeAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.react_native_analyzer import ReactNativeAnalyzer
        return ReactNativeAnalyzer()

    @pytest.fixture
    def rn_app_with_secrets(self, tmp_path):
        """React Native Android app with hardcoded secrets in JS bundle.

        NOTE: The bundle content intentionally contains insecure patterns
        (hardcoded keys, HTTP URLs, debug flags) to test the analyzer's
        ability to detect them. These are test fixtures, not real secrets.
        """
        bundle_content = (
            'var config = {\n'
            '  api_key: "sk_test_abcd1234efgh5678ijkl9012mnop3456qrst",\n'
            '  firebase_key: "AIzaSyA1234567890abcdefghijklmnopqrstuvw",\n'
            '  aws_key: "AKIAIOSFODNN7EXAMPLE",\n'
            '  baseUrl: "https://api.example.com/v1/users",\n'
            '  authUrl: "https://auth.example.com/v2/oauth",\n'
            '  debug: __DEV__,\n'
            '};\n'
            'function loadData() {\n'
            '  fetch("http://insecure.example.com/data")\n'
            '  AsyncStorage.setItem("password", userPass)\n'
            '}\n'
            'var debuggerEnabled = true;\n'
        )
        app = make_mock_app(tmp_path, {
            "assets/index.android.bundle": bundle_content,
        })
        app.framework = "react_native"
        return app

    @pytest.fixture
    def rn_clean_app(self, tmp_path):
        """React Native app with no secrets."""
        app = make_mock_app(tmp_path, {
            "assets/index.android.bundle": "var App = function() { return null; };",
        })
        app.framework = "react_native"
        return app

    @pytest.fixture
    def non_rn_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "classes.dex": b"dex\n035\x00regular android app",
        })

    @pytest.mark.asyncio
    async def test_detects_hardcoded_secrets(self, analyzer, rn_app_with_secrets):
        findings = await analyzer.analyze(rn_app_with_secrets)
        assert isinstance(findings, list)
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_detects_api_endpoints(self, analyzer, rn_app_with_secrets):
        findings = await analyzer.analyze(rn_app_with_secrets)
        texts = " ".join((f.title + " " + f.description).lower() for f in findings)
        has_relevant = (
            "secret" in texts or "key" in texts or "api" in texts
            or "endpoint" in texts or "debug" in texts or "http" in texts
        )
        assert has_relevant

    @pytest.mark.asyncio
    async def test_clean_app_fewer_findings(self, analyzer, rn_clean_app):
        findings = await analyzer.analyze(rn_clean_app)
        critical = [f for f in findings if f.severity in ("critical", "high")]
        assert len(critical) == 0

    @pytest.mark.asyncio
    async def test_non_rn_app_returns_empty(self, analyzer, non_rn_app):
        findings = await analyzer.analyze(non_rn_app)
        assert findings == []

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, rn_app_with_secrets):
        findings = await analyzer.analyze(rn_app_with_secrets)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "react_native_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
