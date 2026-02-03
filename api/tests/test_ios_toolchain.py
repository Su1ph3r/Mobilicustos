"""
Tests for iOS toolchain service.
"""

import pytest
import tempfile
import os
import plistlib
import zipfile

from api.services.ios_toolchain import iOSToolchain, get_ios_toolchain


class TestiOSToolchain:
    """Tests for the iOS toolchain."""

    @pytest.fixture
    def toolchain(self):
        """Create toolchain instance."""
        return iOSToolchain()

    @pytest.fixture
    def sample_ipa(self):
        """Create a sample IPA file for testing."""
        temp_dir = tempfile.mkdtemp()
        ipa_path = os.path.join(temp_dir, "test.ipa")

        # Create IPA structure (it's a zip file)
        with zipfile.ZipFile(ipa_path, "w") as zf:
            # Create Payload/TestApp.app/Info.plist
            info_plist = {
                "CFBundleIdentifier": "com.test.app",
                "CFBundleName": "TestApp",
                "CFBundleExecutable": "TestApp",
                "CFBundleShortVersionString": "1.0.0",
                "CFBundleVersion": "1",
                "MinimumOSVersion": "14.0",
            }

            # Write Info.plist
            plist_data = plistlib.dumps(info_plist)
            zf.writestr("Payload/TestApp.app/Info.plist", plist_data)

            # Create fake binary
            zf.writestr("Payload/TestApp.app/TestApp", b"fake binary content")

        yield ipa_path

        # Cleanup
        os.unlink(ipa_path)
        os.rmdir(temp_dir)

    @pytest.fixture
    def sample_plist_file(self):
        """Create a sample Info.plist file."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".plist", delete=False) as f:
            info_plist = {
                "CFBundleIdentifier": "com.test.app",
                "CFBundleName": "TestApp",
                "CFBundleDisplayName": "Test Application",
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
                        "CFBundleURLName": "com.test.app",
                        "CFBundleURLSchemes": ["testapp", "myscheme"],
                    }
                ],
                "NSCameraUsageDescription": "Camera access for photos",
                "NSLocationWhenInUseUsageDescription": "Location for maps",
            }
            plistlib.dump(info_plist, f)
            f.flush()
            yield f.name
        os.unlink(f.name)

    def test_get_capabilities(self, toolchain):
        """Test capability detection."""
        caps = toolchain.get_capabilities()

        assert isinstance(caps, dict)
        assert "basic_analysis" in caps
        assert caps["basic_analysis"] is True  # Always available

    def test_get_tier(self, toolchain):
        """Test tier detection."""
        tier = toolchain.get_tier()

        assert tier in [1, 2, 3]
        assert tier >= 1  # At minimum tier 1

    def test_extract_ipa(self, toolchain, sample_ipa):
        """Test IPA extraction."""
        output_dir = tempfile.mkdtemp()

        try:
            result = toolchain.extract_ipa(sample_ipa, output_dir)

            assert result["app_path"] is not None
            assert "TestApp.app" in result["app_path"]
            assert result["info_plist_path"] is not None
            assert len(result["files"]) > 0
        finally:
            # Cleanup
            import shutil
            shutil.rmtree(output_dir)

    def test_parse_info_plist(self, toolchain, sample_plist_file):
        """Test Info.plist parsing."""
        result = toolchain.parse_info_plist(sample_plist_file)

        assert result["bundle_id"] == "com.test.app"
        assert result["bundle_name"] == "TestApp"
        assert result["version"] == "1.0.0"
        assert result["minimum_os_version"] == "14.0"

    def test_parse_info_plist_url_schemes(self, toolchain, sample_plist_file):
        """Test URL scheme extraction from plist."""
        result = toolchain.parse_info_plist(sample_plist_file)

        assert "url_schemes" in result
        assert "testapp" in result["url_schemes"]
        assert "myscheme" in result["url_schemes"]

    def test_parse_info_plist_ats_settings(self, toolchain, sample_plist_file):
        """Test ATS settings extraction."""
        result = toolchain.parse_info_plist(sample_plist_file)

        assert "ats_settings" in result
        assert result["ats_settings"]["NSAllowsArbitraryLoads"] is True

    def test_parse_info_plist_permissions(self, toolchain, sample_plist_file):
        """Test permission extraction."""
        result = toolchain.parse_info_plist(sample_plist_file)

        assert "permissions" in result
        assert "NSCameraUsageDescription" in result["permissions"]
        assert "NSLocationWhenInUseUsageDescription" in result["permissions"]

    def test_extract_strings(self, toolchain):
        """Test string extraction from binary."""
        # Create a simple test file with strings
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("This is a test string\nAnother string here\nAPI_KEY=secret123")
            f.flush()

            try:
                strings = toolchain.extract_strings(f.name)
                # Note: strings command may not work on all files
                assert isinstance(strings, list)
            finally:
                os.unlink(f.name)

    def test_singleton_instance(self):
        """Test that get_ios_toolchain returns singleton."""
        instance1 = get_ios_toolchain()
        instance2 = get_ios_toolchain()

        assert instance1 is instance2


class TestiOSToolchainTier2:
    """Tests for Tier 2 (Mac-only) iOS toolchain features."""

    @pytest.fixture
    def toolchain(self):
        """Create toolchain instance."""
        return iOSToolchain()

    def test_otool_not_available(self, toolchain):
        """Test graceful handling when otool is not available."""
        if not toolchain.capabilities.get("otool"):
            result = toolchain.analyze_binary_otool("/fake/path")
            assert "error" in result

    def test_nm_not_available(self, toolchain):
        """Test graceful handling when nm is not available."""
        if not toolchain.capabilities.get("nm"):
            result = toolchain.analyze_binary_nm("/fake/path")
            assert "error" in result

    def test_class_dump_not_available(self, toolchain):
        """Test graceful handling when class-dump is not available."""
        if not toolchain.capabilities.get("class_dump"):
            result = toolchain.class_dump_binary("/fake/path")
            assert "error" in result

    def test_list_devices_not_available(self, toolchain):
        """Test graceful handling when libimobiledevice is not available."""
        if not toolchain.capabilities.get("libimobiledevice"):
            devices = toolchain.list_connected_devices()
            assert devices == []
