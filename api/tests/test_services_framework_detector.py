"""
Tests for framework detection service.
"""

import pytest
import tempfile
import os
import zipfile
from pathlib import Path

from api.services.framework_detector import detect_framework


class TestFrameworkDetector:
    """Tests for the framework detection service."""

    @pytest.fixture
    def flutter_apk(self):
        """Create temporary APK with Flutter indicators."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            # Flutter indicators
            zf.writestr("lib/arm64-v8a/libflutter.so", "fake flutter library")
            zf.writestr("lib/arm64-v8a/libapp.so", "fake dart aot")
            zf.writestr("assets/flutter_assets/AssetManifest.json", "{}")
            zf.writestr("assets/flutter_assets/version", "3.16.0")

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def react_native_apk(self):
        """Create temporary APK with React Native indicators."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            # React Native indicators
            zf.writestr("assets/index.android.bundle", '__d(function(global){"react-native": "0.72.0"});')
            zf.writestr("lib/arm64-v8a/libreactnativejni.so", "fake rn library")
            zf.writestr("lib/arm64-v8a/libhermes.so", "fake hermes")

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def xamarin_apk(self):
        """Create temporary APK with Xamarin indicators."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("assemblies/Xamarin.Android.dll", "fake xamarin")
            zf.writestr("lib/arm64-v8a/libmonosgen-2.0.so", "fake mono")

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def maui_apk(self):
        """Create temporary APK with MAUI indicators."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("assemblies/Microsoft.Maui.dll", "fake maui")
            zf.writestr("lib/arm64-v8a/libmonosgen-2.0.so", "fake mono")

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def cordova_apk(self):
        """Create temporary APK with Cordova indicators."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("assets/www/index.html", "<html></html>")
            zf.writestr("assets/www/cordova.js", "CORDOVA_JS_BUILD_LABEL = '12.0.0'")

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def unity_apk(self):
        """Create temporary APK with Unity indicators."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("lib/arm64-v8a/libunity.so", "fake unity")
            zf.writestr("lib/arm64-v8a/libil2cpp.so", "fake il2cpp")
            zf.writestr("assets/bin/Data/level0", "fake level")

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def native_apk(self):
        """Create temporary APK for native app (no framework)."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", "fake manifest")
            zf.writestr("classes.dex", "fake dex")
            zf.writestr("res/values/strings.xml", "fake strings")

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def flutter_ipa(self):
        """Create temporary IPA with Flutter indicators."""
        with tempfile.NamedTemporaryFile(suffix=".ipa", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("Payload/App.app/Frameworks/Flutter.framework/Flutter", "fake flutter")
            zf.writestr("Payload/App.app/Frameworks/App.framework/App", "fake app")

        yield Path(temp_path)

        os.unlink(temp_path)

    @pytest.fixture
    def react_native_ipa(self):
        """Create temporary IPA with React Native indicators."""
        with tempfile.NamedTemporaryFile(suffix=".ipa", delete=False) as f:
            temp_path = f.name

        with zipfile.ZipFile(temp_path, "w") as zf:
            zf.writestr("Payload/App.app/main.jsbundle", "fake bundle")
            zf.writestr("Payload/App.app/Frameworks/hermes.framework/hermes", "fake hermes")

        yield Path(temp_path)

        os.unlink(temp_path)

    # Android Tests

    @pytest.mark.asyncio
    async def test_detect_flutter_android(self, flutter_apk):
        """Test detection of Flutter framework in Android APK."""
        result = await detect_framework(flutter_apk, "android")

        assert result["framework"] == "flutter"
        assert result["details"]["aot_snapshot"] is True
        assert result["details"]["analysis_method"] == "blutter"

    @pytest.mark.asyncio
    async def test_detect_flutter_version(self, flutter_apk):
        """Test extraction of Flutter version."""
        result = await detect_framework(flutter_apk, "android")

        assert result["version"] == "3.16.0"

    @pytest.mark.asyncio
    async def test_detect_react_native_android(self, react_native_apk):
        """Test detection of React Native framework in Android APK."""
        result = await detect_framework(react_native_apk, "android")

        assert result["framework"] == "react_native"
        assert result["details"]["hermes_enabled"] is True
        assert result["details"]["analysis_method"] == "hermes-dec"

    @pytest.mark.asyncio
    async def test_detect_xamarin_android(self, xamarin_apk):
        """Test detection of Xamarin framework in Android APK."""
        result = await detect_framework(xamarin_apk, "android")

        assert result["framework"] == "xamarin"
        assert result["details"]["analysis_method"] == "ilspy"

    @pytest.mark.asyncio
    async def test_detect_maui_android(self, maui_apk):
        """Test detection of MAUI framework in Android APK."""
        result = await detect_framework(maui_apk, "android")

        assert result["framework"] == "maui"
        assert result["details"]["analysis_method"] == "ilspy"

    @pytest.mark.asyncio
    async def test_detect_cordova_android(self, cordova_apk):
        """Test detection of Cordova framework in Android APK."""
        result = await detect_framework(cordova_apk, "android")

        assert result["framework"] == "cordova"
        assert result["details"]["analysis_method"] == "www_extraction"

    @pytest.mark.asyncio
    async def test_detect_unity_android(self, unity_apk):
        """Test detection of Unity framework in Android APK."""
        result = await detect_framework(unity_apk, "android")

        assert result["framework"] == "unity"
        assert result["details"]["analysis_method"] == "il2cpp"

    @pytest.mark.asyncio
    async def test_detect_native_android(self, native_apk):
        """Test detection of native app (no framework)."""
        result = await detect_framework(native_apk, "android")

        assert result["framework"] == "native"

    # iOS Tests

    @pytest.mark.asyncio
    async def test_detect_flutter_ios(self, flutter_ipa):
        """Test detection of Flutter framework in iOS IPA."""
        result = await detect_framework(flutter_ipa, "ios")

        assert result["framework"] == "flutter"
        assert result["details"]["analysis_method"] == "blutter"

    @pytest.mark.asyncio
    async def test_detect_react_native_ios(self, react_native_ipa):
        """Test detection of React Native framework in iOS IPA."""
        result = await detect_framework(react_native_ipa, "ios")

        assert result["framework"] == "react_native"
        assert result["details"]["hermes_enabled"] is True

    # Error Handling

    @pytest.mark.asyncio
    async def test_invalid_file_path(self):
        """Test handling of invalid file path."""
        result = await detect_framework(Path("/nonexistent/file.apk"), "android")

        # Should return native as fallback on error
        assert result["framework"] == "native"

    @pytest.mark.asyncio
    async def test_corrupted_zip(self):
        """Test handling of corrupted ZIP file."""
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"not a valid zip file")
            temp_path = f.name

        try:
            result = await detect_framework(Path(temp_path), "android")
            assert result["framework"] == "native"
        finally:
            os.unlink(temp_path)
