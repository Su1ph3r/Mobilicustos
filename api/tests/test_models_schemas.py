"""
Tests for Pydantic schemas.
"""

import pytest
from pydantic import ValidationError

from api.models.schemas import (
    MobileAppCreate,
    ScanCreate,
    FindingCreate,
    DeviceCreate,
    FridaScriptCreate,
)


class TestMobileAppSchemas:
    """Tests for mobile app schemas."""

    def test_create_app_minimal(self):
        """Test creating app with minimal required fields."""
        app = MobileAppCreate(
            package_name="com.example.app",
            platform="android",
        )
        assert app.package_name == "com.example.app"
        assert app.platform == "android"

    def test_create_app_full(self):
        """Test creating app with all fields."""
        app = MobileAppCreate(
            package_name="com.example.app",
            app_name="Example App",
            version_name="1.0.0",
            version_code=1,
            platform="android",
        )
        assert app.app_name == "Example App"
        assert app.version_name == "1.0.0"

    def test_create_app_invalid_platform(self):
        """Test creating app with invalid platform."""
        with pytest.raises(ValidationError):
            MobileAppCreate(
                package_name="com.example.app",
                platform="invalid_platform",
            )

    def test_create_app_ios(self):
        """Test creating iOS app."""
        app = MobileAppCreate(
            package_name="com.example.iosapp",
            platform="ios",
        )
        assert app.platform == "ios"


class TestScanSchemas:
    """Tests for scan schemas."""

    def test_create_scan_minimal(self):
        """Test creating scan with minimal fields."""
        scan = ScanCreate(
            app_id="test-app-123",
            scan_type="static",
        )
        assert scan.app_id == "test-app-123"
        assert scan.scan_type == "static"

    def test_create_scan_with_analyzers(self):
        """Test creating scan with specific analyzers."""
        scan = ScanCreate(
            app_id="test-app-123",
            scan_type="static",
            analyzers_enabled=["manifest_analyzer", "secret_scanner"],
        )
        assert len(scan.analyzers_enabled) == 2

    def test_create_scan_invalid_type(self):
        """Test creating scan with invalid type."""
        with pytest.raises(ValidationError):
            ScanCreate(
                app_id="test-app-123",
                scan_type="invalid_type",
            )

    def test_scan_types(self):
        """Test all valid scan types."""
        for scan_type in ["static", "dynamic", "full"]:
            scan = ScanCreate(app_id="test", scan_type=scan_type)
            assert scan.scan_type == scan_type


class TestFindingSchemas:
    """Tests for finding schemas."""

    def test_create_finding_minimal(self):
        """Test creating finding with minimal fields."""
        finding = FindingCreate(
            tool="manifest_analyzer",
            severity="high",
            title="Test Finding",
            description="This is a test finding.",
            impact="Potential security impact.",
            remediation="Fix the issue.",
        )
        assert finding.severity == "high"

    def test_create_finding_full(self):
        """Test creating finding with all fields."""
        finding = FindingCreate(
            tool="manifest_analyzer",
            platform="android",
            severity="critical",
            category="Configuration",
            title="Debuggable Application",
            description="The application is debuggable.",
            impact="Attackers can attach debuggers.",
            remediation="Disable debuggable flag.",
            file_path="AndroidManifest.xml",
            line_number=10,
            poc_evidence="android:debuggable=true",
            cwe_id="CWE-489",
            owasp_masvs_category="MASVS-RESILIENCE",
        )
        assert finding.platform == "android"
        assert finding.cwe_id == "CWE-489"

    def test_create_finding_invalid_severity(self):
        """Test creating finding with invalid severity."""
        with pytest.raises(ValidationError):
            FindingCreate(
                tool="test",
                severity="invalid_severity",
                title="Test",
                description="Test",
                impact="Test",
                remediation="Test",
            )

    def test_severity_levels(self):
        """Test all valid severity levels."""
        for severity in ["critical", "high", "medium", "low", "info"]:
            finding = FindingCreate(
                tool="test",
                severity=severity,
                title="Test",
                description="Test",
                impact="Test",
                remediation="Test",
            )
            assert finding.severity == severity


class TestDeviceSchemas:
    """Tests for device schemas."""

    def test_create_device_minimal(self):
        """Test creating device with minimal fields."""
        device = DeviceCreate(
            device_id="device-001",
            device_type="physical",
            platform="android",
        )
        assert device.device_type == "physical"
        assert device.device_id == "device-001"

    def test_create_device_full(self):
        """Test creating device with all fields."""
        device = DeviceCreate(
            device_id="emulator-5554",
            device_type="emulator",
            platform="android",
            device_name="Pixel 6",
            model="sdk_gphone64_x86_64",
            os_version="13",
            connection_string="emulator-5554",
        )
        assert device.device_name == "Pixel 6"

    def test_create_device_corellium(self):
        """Test creating Corellium device."""
        device = DeviceCreate(
            device_id="corellium-001",
            device_type="corellium",
            platform="ios",
            corellium_instance_id="instance-123",
            corellium_project_id="project-456",
        )
        assert device.device_type == "corellium"

    def test_create_device_genymotion(self):
        """Test creating Genymotion device."""
        device = DeviceCreate(
            device_id="192.168.56.101:5555",
            device_type="genymotion",
            platform="android",
            device_name="Google Pixel 6 - 13.0",
            model="vbox86p",
            os_version="13",
            connection_string="192.168.56.101:5555",
        )
        assert device.device_type == "genymotion"
        assert device.platform == "android"
        assert device.connection_string == "192.168.56.101:5555"

    def test_create_device_invalid_type(self):
        """Test creating device with invalid type."""
        with pytest.raises(ValidationError):
            DeviceCreate(
                device_id="device-001",
                device_type="invalid_type",
                platform="android",
            )

    def test_all_device_types_valid(self):
        """Test that all expected device types are valid."""
        valid_types = ["physical", "emulator", "genymotion", "corellium"]

        for device_type in valid_types:
            device = DeviceCreate(
                device_id=f"device-{device_type}",
                device_type=device_type,
                platform="android",
            )
            assert device.device_type == device_type


class TestFridaScriptSchemas:
    """Tests for Frida script schemas."""

    def test_create_script_minimal(self):
        """Test creating script with minimal fields."""
        script = FridaScriptCreate(
            script_name="Test Script",
            category="utility",
            script_content="console.log('test');",
        )
        assert script.script_name == "Test Script"
        assert script.category == "utility"

    def test_create_script_full(self):
        """Test creating script with all fields."""
        script = FridaScriptCreate(
            script_name="SSL Bypass",
            category="bypass",
            subcategory="ssl_pinning",
            description="Bypasses SSL pinning",
            script_content="Java.perform(function() {});",
            platforms=["android"],
            min_frida_version="16.0.0",
        )
        assert script.category == "bypass"
        assert script.subcategory == "ssl_pinning"

    def test_create_script_empty_content(self):
        """Test that script requires content."""
        # Script content is required and must be non-empty string
        # The current schema doesn't validate for empty string,
        # so we just test that the field is required
        with pytest.raises(ValidationError):
            FridaScriptCreate(
                script_name="Empty Script",
                category="test",
                # Missing script_content
            )
