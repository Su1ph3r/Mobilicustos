"""Tests for PermissionsAnalyzer."""

import pytest
from api.tests.conftest import make_mock_app


MANIFEST_DANGEROUS_PERMS = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp">
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <application />
</manifest>"""

MANIFEST_MINIMAL_PERMS = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp">
    <uses-permission android:name="android.permission.INTERNET" />
    <application />
</manifest>"""


class TestPermissionsAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.permissions_analyzer import PermissionsAnalyzer
        return PermissionsAnalyzer()

    @pytest.fixture
    def dangerous_perms_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "AndroidManifest.xml": MANIFEST_DANGEROUS_PERMS,
        })

    @pytest.fixture
    def minimal_perms_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "AndroidManifest.xml": MANIFEST_MINIMAL_PERMS,
        })

    @pytest.mark.asyncio
    async def test_detects_dangerous_permissions(self, analyzer, dangerous_perms_app):
        findings = await analyzer.analyze(dangerous_perms_app)
        assert isinstance(findings, list)
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_detects_special_permissions(self, analyzer, dangerous_perms_app):
        findings = await analyzer.analyze(dangerous_perms_app)
        texts = " ".join((f.title + " " + f.description).lower() for f in findings)
        assert "permission" in texts or "overlay" in texts or "location" in texts

    @pytest.mark.asyncio
    async def test_minimal_perms_fewer_findings(self, analyzer, minimal_perms_app):
        findings = await analyzer.analyze(minimal_perms_app)
        # INTERNET permission is not dangerous
        dangerous_findings = [f for f in findings if f.severity in ("high", "critical")]
        assert len(dangerous_findings) == 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, dangerous_perms_app):
        findings = await analyzer.analyze(dangerous_perms_app)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "permissions_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
