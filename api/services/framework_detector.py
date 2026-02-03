"""Framework detector service for identifying cross-platform frameworks."""

import logging
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


async def detect_framework(file_path: Path, platform: str) -> dict[str, Any]:
    """Detect the framework used to build a mobile app."""
    result: dict[str, Any] = {
        "framework": "native",
        "version": None,
        "details": {},
    }

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            file_list = archive.namelist()

            if platform == "android":
                result = await _detect_android_framework(archive, file_list)
            else:
                result = await _detect_ios_framework(archive, file_list)

    except Exception as e:
        logger.error(f"Framework detection failed: {e}")

    return result


async def _detect_android_framework(
    archive: zipfile.ZipFile,
    file_list: list[str],
) -> dict[str, Any]:
    """Detect framework for Android APK."""

    # Flutter detection
    flutter_indicators = [
        "lib/arm64-v8a/libflutter.so",
        "lib/armeabi-v7a/libflutter.so",
        "lib/x86_64/libflutter.so",
        "assets/flutter_assets/",
    ]
    if any(ind in file_list or any(f.startswith(ind) for f in file_list) for ind in flutter_indicators):
        details = {"aot_snapshot": False}

        # Check for AOT snapshot
        if any("libapp.so" in f for f in file_list):
            details["aot_snapshot"] = True
            details["analysis_method"] = "blutter"
        else:
            details["analysis_method"] = "dart_snapshot"

        return {
            "framework": "flutter",
            "version": await _get_flutter_version(archive, file_list),
            "details": details,
        }

    # React Native detection
    rn_indicators = [
        "assets/index.android.bundle",
        "lib/arm64-v8a/libreactnativejni.so",
        "lib/armeabi-v7a/libreactnativejni.so",
    ]
    if any(ind in file_list for ind in rn_indicators):
        details = {"hermes_enabled": False}

        # Check for Hermes bytecode
        if any("libhermes.so" in f for f in file_list):
            details["hermes_enabled"] = True
            details["analysis_method"] = "hermes-dec"
        else:
            details["analysis_method"] = "js_bundle"

        return {
            "framework": "react_native",
            "version": await _get_rn_version(archive, file_list),
            "details": details,
        }

    # Xamarin/MAUI detection
    xamarin_indicators = [
        "assemblies/",
        "lib/arm64-v8a/libmonosgen-2.0.so",
        "lib/arm64-v8a/libmonodroid.so",
    ]
    if any(ind in file_list or any(f.startswith(ind) for f in file_list) for ind in xamarin_indicators):
        # Check for MAUI vs Xamarin
        is_maui = any("Microsoft.Maui" in f for f in file_list)

        return {
            "framework": "maui" if is_maui else "xamarin",
            "version": None,
            "details": {"analysis_method": "ilspy"},
        }

    # Cordova/PhoneGap detection
    if any("assets/www/" in f for f in file_list):
        return {
            "framework": "cordova",
            "version": await _get_cordova_version(archive, file_list),
            "details": {"analysis_method": "www_extraction"},
        }

    # Unity detection
    if any("libunity.so" in f or "assets/bin/Data/" in f for f in file_list):
        return {
            "framework": "unity",
            "version": None,
            "details": {"analysis_method": "il2cpp" if any("libil2cpp.so" in f for f in file_list) else "mono"},
        }

    return {"framework": "native", "version": None, "details": {}}


async def _detect_ios_framework(
    archive: zipfile.ZipFile,
    file_list: list[str],
) -> dict[str, Any]:
    """Detect framework for iOS IPA."""

    # Flutter detection
    flutter_indicators = [
        "Frameworks/Flutter.framework/",
        "Frameworks/App.framework/",
    ]
    if any(any(f.startswith(ind) or ind in f for f in file_list) for ind in flutter_indicators):
        return {
            "framework": "flutter",
            "version": None,
            "details": {"analysis_method": "blutter"},
        }

    # React Native detection
    if any("jsbundle" in f.lower() or "main.jsbundle" in f for f in file_list):
        details = {"hermes_enabled": False}

        # Check for Hermes
        if any("hermes" in f.lower() for f in file_list):
            details["hermes_enabled"] = True
            details["analysis_method"] = "hermes-dec"
        else:
            details["analysis_method"] = "js_bundle"

        return {
            "framework": "react_native",
            "version": None,
            "details": details,
        }

    # Xamarin/MAUI detection
    if any("Xamarin." in f or "Mono." in f for f in file_list):
        is_maui = any("Microsoft.Maui" in f for f in file_list)
        return {
            "framework": "maui" if is_maui else "xamarin",
            "version": None,
            "details": {"analysis_method": "ilspy"},
        }

    # Cordova detection
    if any("www/" in f for f in file_list):
        return {
            "framework": "cordova",
            "version": None,
            "details": {"analysis_method": "www_extraction"},
        }

    # Unity detection
    if any("UnityFramework" in f or "Data/Managed/" in f for f in file_list):
        return {
            "framework": "unity",
            "version": None,
            "details": {"analysis_method": "il2cpp"},
        }

    return {"framework": "native", "version": None, "details": {}}


async def _get_flutter_version(
    archive: zipfile.ZipFile,
    file_list: list[str],
) -> str | None:
    """Try to extract Flutter version."""
    try:
        # Look for version in flutter_assets
        for f in file_list:
            if "flutter_assets/version" in f:
                return archive.read(f).decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    return None


async def _get_rn_version(
    archive: zipfile.ZipFile,
    file_list: list[str],
) -> str | None:
    """Try to extract React Native version."""
    try:
        # Look in the JS bundle for version
        for f in file_list:
            if "index.android.bundle" in f:
                content = archive.read(f).decode("utf-8", errors="ignore")
                # Search for version pattern
                import re
                match = re.search(r'"react-native":\s*"([^"]+)"', content)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return None


async def _get_cordova_version(
    archive: zipfile.ZipFile,
    file_list: list[str],
) -> str | None:
    """Try to extract Cordova version."""
    try:
        for f in file_list:
            if "cordova.js" in f:
                content = archive.read(f).decode("utf-8", errors="ignore")
                import re
                match = re.search(r'CORDOVA_JS_BUILD_LABEL\s*=\s*[\'"]([^\'"]+)[\'"]', content)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return None
