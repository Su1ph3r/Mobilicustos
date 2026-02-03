"""
Tests for analyzer services.
"""

import pytest
import tempfile
import os
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

from api.services.analyzers.manifest_analyzer import ManifestAnalyzer
from api.services.analyzers.secret_scanner import SecretScanner
from api.services.analyzers.plist_analyzer import PlistAnalyzer


def create_mock_mobile_app(
    app_id: str = "test-app-123",
    package_name: str = "com.example.testapp",
    platform: str = "android",
    file_path: str | None = None,
) -> MagicMock:
    """Create a mock MobileApp object."""
    app = MagicMock()
    app.app_id = app_id
    app.package_name = package_name
    app.platform = platform
    app.file_path = file_path
    return app


class TestManifestAnalyzer:
    """Tests for the Android manifest analyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ManifestAnalyzer()

    @pytest.fixture
    def sample_manifest_xml(self):
        """Sample decoded AndroidManifest.xml content."""
        return '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp"
    android:versionCode="1"
    android:versionName="1.0.0">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.CAMERA" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:networkSecurityConfig="@xml/network_security_config"
        android:usesCleartextTraffic="true">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity
            android:name=".DeepLinkActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="testapp" android:host="open" />
            </intent-filter>
        </activity>

        <provider
            android:name=".DataProvider"
            android:authorities="com.example.testapp.provider"
            android:exported="true" />

        <receiver
            android:name=".BootReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

    </application>
</manifest>'''

    @pytest.fixture
    def mock_app(self):
        """Create a mock MobileApp for testing."""
        return create_mock_mobile_app(file_path="/fake/path/app.apk")

    @pytest.mark.asyncio
    async def test_analyze_manifest(self, analyzer, mock_app, sample_manifest_xml):
        """Test manifest analysis produces findings."""
        with patch.object(analyzer, "_extract_manifest", return_value=sample_manifest_xml):
            findings = await analyzer.analyze(mock_app)

            assert isinstance(findings, list)
            # Should find debuggable, cleartext traffic, exported components
            assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_detect_debuggable(self, analyzer, mock_app, sample_manifest_xml):
        """Test detection of debuggable flag."""
        with patch.object(analyzer, "_extract_manifest", return_value=sample_manifest_xml):
            findings = await analyzer.analyze(mock_app)

            debuggable_finding = next(
                (f for f in findings if "debuggable" in f.title.lower()),
                None
            )
            assert debuggable_finding is not None
            assert debuggable_finding.severity in ["high", "critical"]

    @pytest.mark.asyncio
    async def test_detect_cleartext_traffic(self, analyzer, mock_app, sample_manifest_xml):
        """Test detection of cleartext traffic."""
        with patch.object(analyzer, "_extract_manifest", return_value=sample_manifest_xml):
            findings = await analyzer.analyze(mock_app)

            cleartext_finding = next(
                (f for f in findings if "clear" in f.title.lower() and "traffic" in f.title.lower()),
                None
            )
            assert cleartext_finding is not None

    @pytest.mark.asyncio
    async def test_detect_exported_components(self, analyzer, mock_app, sample_manifest_xml):
        """Test detection of exported components."""
        with patch.object(analyzer, "_extract_manifest", return_value=sample_manifest_xml):
            findings = await analyzer.analyze(mock_app)

            exported_findings = [
                f for f in findings
                if "exported" in f.title.lower()
            ]
            assert len(exported_findings) > 0

    @pytest.mark.asyncio
    async def test_detect_backup_enabled(self, analyzer, mock_app, sample_manifest_xml):
        """Test detection of backup enabled."""
        with patch.object(analyzer, "_extract_manifest", return_value=sample_manifest_xml):
            findings = await analyzer.analyze(mock_app)

            backup_finding = next(
                (f for f in findings if "backup" in f.title.lower()),
                None
            )
            assert backup_finding is not None

    @pytest.mark.asyncio
    async def test_no_file_path_returns_empty(self, analyzer):
        """Test that no file path returns empty findings."""
        mock_app = create_mock_mobile_app(file_path=None)
        findings = await analyzer.analyze(mock_app)
        assert findings == []

    @pytest.mark.asyncio
    async def test_manifest_extraction_failure(self, analyzer, mock_app):
        """Test graceful handling of manifest extraction failure."""
        with patch.object(analyzer, "_extract_manifest", return_value=None):
            findings = await analyzer.analyze(mock_app)
            assert findings == []


class TestSecretScanner:
    """Tests for the secret scanner."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return SecretScanner()

    @pytest.fixture
    def test_apk(self):
        """Create temporary APK with files containing secrets."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            # File with API key (AIza + exactly 35 chars = 39 total)
            # Example: AIza + SyA1234567890abcdefghijklmnop123456 (35 chars)
            zf.writestr("res/values/config.xml", '''
            <resources>
                <string name="api_key">AIzaSyA1234567890abcdefghijklmnop123456</string>
                <string name="aws_key">AKIAIOSFODNN7EXAMPLE</string>
            </resources>
            ''')

            # File with password
            zf.writestr("assets/secrets.json", '''
            {
                "db_password": "super_secret_password_123",
                "stripe_key": "REDACTED_TEST_KEY"
            }
            ''')

            # Java file with hardcoded key (AIza + exactly 35 chars)
            zf.writestr("classes/com/example/Config.java", '''
            public class Config {
                private static final String API_KEY = "AIzaSyA1234567890abcdefghijklmnop123456";
            }
            ''')

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def mock_app_with_apk(self, test_apk):
        """Create mock app with test APK path."""
        return create_mock_mobile_app(file_path=str(test_apk))

    @pytest.mark.asyncio
    async def test_scan_files(self, scanner, mock_app_with_apk):
        """Test scanning files for secrets."""
        findings = await scanner.analyze(mock_app_with_apk)

        assert isinstance(findings, list)
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_detect_google_api_keys(self, scanner, mock_app_with_apk):
        """Test detection of Google API keys."""
        findings = await scanner.analyze(mock_app_with_apk)

        google_findings = [
            f for f in findings
            if "google" in f.title.lower() or "AIza" in str(f.description)
        ]
        assert len(google_findings) > 0

    @pytest.mark.asyncio
    async def test_detect_aws_credentials(self, scanner, mock_app_with_apk):
        """Test detection of AWS credentials."""
        findings = await scanner.analyze(mock_app_with_apk)

        aws_findings = [
            f for f in findings
            if "aws" in f.title.lower() or "AKIA" in str(f.description)
        ]
        assert len(aws_findings) > 0

    @pytest.mark.asyncio
    async def test_detect_stripe_keys(self, scanner, mock_app_with_apk):
        """Test detection of Stripe keys."""
        findings = await scanner.analyze(mock_app_with_apk)

        stripe_findings = [
            f for f in findings
            if "stripe" in f.title.lower()
        ]
        assert len(stripe_findings) > 0

    @pytest.mark.asyncio
    async def test_no_file_path_returns_empty(self, scanner):
        """Test that no file path returns empty findings."""
        mock_app = create_mock_mobile_app(file_path=None)
        findings = await scanner.analyze(mock_app)
        assert findings == []

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, scanner, mock_app_with_apk):
        """Test that findings have all required fields."""
        findings = await scanner.analyze(mock_app_with_apk)

        for finding in findings:
            assert finding.title is not None
            assert finding.description is not None
            assert finding.severity is not None
            assert finding.tool == "secret_scanner"


class TestPlistAnalyzer:
    """Tests for the iOS plist analyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return PlistAnalyzer()

    @pytest.fixture
    def sample_info_plist(self):
        """Sample Info.plist content as dict."""
        return {
            "CFBundleIdentifier": "com.example.testapp",
            "CFBundleName": "TestApp",
            "CFBundleDisplayName": "Test App",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1",
            "CFBundleExecutable": "TestApp",
            "MinimumOSVersion": "14.0",
            "UIDeviceFamily": [1, 2],
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": True,
            },
            "CFBundleURLTypes": [
                {
                    "CFBundleURLName": "com.example.testapp",
                    "CFBundleURLSchemes": ["testapp", "fb12345"],
                }
            ],
            "NSCameraUsageDescription": "We need camera access",
            "NSLocationWhenInUseUsageDescription": "We need your location",
        }

    @pytest.fixture
    def test_ipa(self, sample_info_plist):
        """Create temporary IPA with Info.plist."""
        import plistlib

        with tempfile.NamedTemporaryFile(suffix=".ipa", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            plist_data = plistlib.dumps(sample_info_plist)
            zf.writestr("Payload/TestApp.app/Info.plist", plist_data)

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def mock_app_with_ipa(self, test_ipa):
        """Create mock app with test IPA path."""
        return create_mock_mobile_app(
            platform="ios",
            file_path=str(test_ipa),
        )

    @pytest.mark.asyncio
    async def test_analyze_plist(self, analyzer, mock_app_with_ipa):
        """Test plist analysis produces findings."""
        findings = await analyzer.analyze(mock_app_with_ipa)

        assert isinstance(findings, list)
        # Should find ATS issues
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_detect_ats_disabled(self, analyzer, mock_app_with_ipa):
        """Test detection of disabled ATS."""
        findings = await analyzer.analyze(mock_app_with_ipa)

        ats_finding = next(
            (f for f in findings if "transport" in f.title.lower() or "ats" in f.title.lower()),
            None
        )
        assert ats_finding is not None
        assert ats_finding.severity in ["high", "medium"]

    @pytest.mark.asyncio
    async def test_detect_url_schemes(self, analyzer, mock_app_with_ipa):
        """Test detection of URL schemes."""
        findings = await analyzer.analyze(mock_app_with_ipa)

        url_finding = next(
            (f for f in findings if "url" in f.title.lower() or "scheme" in f.title.lower()),
            None
        )
        assert url_finding is not None

    @pytest.mark.asyncio
    async def test_detect_permissions(self, analyzer, mock_app_with_ipa):
        """Test detection of sensitive permissions."""
        findings = await analyzer.analyze(mock_app_with_ipa)

        permission_finding = next(
            (f for f in findings if "permission" in f.title.lower()),
            None
        )
        assert permission_finding is not None

    @pytest.mark.asyncio
    async def test_no_file_path_returns_empty(self, analyzer):
        """Test that no file path returns empty findings."""
        mock_app = create_mock_mobile_app(platform="ios", file_path=None)
        findings = await analyzer.analyze(mock_app)
        assert findings == []

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, mock_app_with_ipa):
        """Test that findings have all required fields."""
        findings = await analyzer.analyze(mock_app_with_ipa)

        for finding in findings:
            assert finding.title is not None
            assert finding.description is not None
            assert finding.severity is not None
            assert finding.tool == "plist_analyzer"
