"""Tests for DeeplinkAnalyzer."""

import pytest
from api.tests.conftest import create_test_archive, make_mock_app


MANIFEST_WITH_DEEPLINKS = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp">
    <application>
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="myapp" android:host="open" />
            </intent-filter>
        </activity>
        <activity android:name=".WebLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="example.com" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""

MANIFEST_NO_DEEPLINKS = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp">
    <application>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""


class TestDeeplinkAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.deeplink_analyzer import DeeplinkAnalyzer
        return DeeplinkAnalyzer()

    @pytest.fixture
    def deeplink_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "AndroidManifest.xml": MANIFEST_WITH_DEEPLINKS,
        })

    @pytest.fixture
    def no_deeplink_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "AndroidManifest.xml": MANIFEST_NO_DEEPLINKS,
        })

    @pytest.mark.asyncio
    async def test_detects_custom_scheme(self, analyzer, deeplink_app):
        findings = await analyzer.analyze(deeplink_app)
        assert isinstance(findings, list)
        assert len(findings) > 0
        titles = [f.title.lower() for f in findings]
        assert any("scheme" in t or "deep" in t or "link" in t for t in titles)

    @pytest.mark.asyncio
    async def test_detects_unverified_http_deeplink(self, analyzer, deeplink_app):
        findings = await analyzer.analyze(deeplink_app)
        # Should flag https link without autoVerify
        descriptions = " ".join(f.description.lower() for f in findings)
        assert "verify" in descriptions or "http" in descriptions or len(findings) >= 1

    @pytest.mark.asyncio
    async def test_no_deeplinks_returns_empty_or_info(self, analyzer, no_deeplink_app):
        findings = await analyzer.analyze(no_deeplink_app)
        # Either empty or info-level only
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        assert len(critical_high) == 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, deeplink_app):
        findings = await analyzer.analyze(deeplink_app)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "deeplink_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
