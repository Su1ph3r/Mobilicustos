"""App parser service for extracting metadata from APK/IPA files."""

import asyncio
import logging
import plistlib
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)


async def parse_android_app(file_path: Path) -> dict[str, Any]:
    """Parse an Android APK file."""
    metadata: dict[str, Any] = {}

    try:
        with zipfile.ZipFile(file_path, "r") as apk:
            # Parse AndroidManifest.xml
            if "AndroidManifest.xml" in apk.namelist():
                manifest_data = apk.read("AndroidManifest.xml")
                manifest_info = await _parse_android_manifest(manifest_data)
                metadata.update(manifest_info)

            # Get signing info from META-INF
            signing_info = await _get_android_signing_info(apk)
            metadata["signing_info"] = signing_info

    except zipfile.BadZipFile:
        logger.error(f"Invalid APK file: {file_path}")
    except Exception as e:
        logger.error(f"Failed to parse APK: {e}")

    return metadata


async def _parse_android_manifest(manifest_data: bytes) -> dict[str, Any]:
    """Parse Android binary manifest."""
    # For binary XML, we need to decode it using androguard
    try:
        # androguard 4.x uses different import paths
        from androguard.core.axml import AXMLPrinter

        axml = AXMLPrinter(manifest_data)
        xml_content = axml.get_xml()

        root = ET.fromstring(xml_content)

        # Extract namespace
        ns = {"android": "http://schemas.android.com/apk/res/android"}

        package_name = root.get("package", "")
        version_code = root.get(f"{{{ns['android']}}}versionCode", "")
        version_name = root.get(f"{{{ns['android']}}}versionName", "")

        # Get application info
        app_elem = root.find("application")
        app_name = ""
        if app_elem is not None:
            app_name = app_elem.get(f"{{{ns['android']}}}label", "")

        # Get SDK versions
        uses_sdk = root.find("uses-sdk")
        min_sdk = target_sdk = None
        if uses_sdk is not None:
            min_sdk = uses_sdk.get(f"{{{ns['android']}}}minSdkVersion")
            target_sdk = uses_sdk.get(f"{{{ns['android']}}}targetSdkVersion")

        return {
            "package_name": package_name,
            "app_name": app_name,
            "version_name": version_name,
            "version_code": int(version_code) if version_code else None,
            "min_sdk_version": int(min_sdk) if min_sdk else None,
            "target_sdk_version": int(target_sdk) if target_sdk else None,
        }

    except ImportError:
        logger.warning("androguard not installed, using basic parsing")
        return {"package_name": "unknown"}
    except Exception as e:
        logger.error(f"Failed to parse manifest: {e}")
        return {"package_name": "unknown"}


async def _get_android_signing_info(apk: zipfile.ZipFile) -> dict[str, Any]:
    """Extract signing information from APK."""
    signing_info: dict[str, Any] = {
        "v1_signed": False,
        "v2_signed": False,
        "v3_signed": False,
    }

    # Check for V1 signature
    for name in apk.namelist():
        if name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC")):
            signing_info["v1_signed"] = True
            signing_info["cert_file"] = name
            break

    # V2/V3 signatures are in APK Signing Block (not in ZIP)
    # Would need to parse the APK binary for those

    return signing_info


async def parse_ios_app(file_path: Path) -> dict[str, Any]:
    """Parse an iOS IPA file."""
    metadata: dict[str, Any] = {}

    try:
        with zipfile.ZipFile(file_path, "r") as ipa:
            # Find Info.plist
            info_plist_path = None
            for name in ipa.namelist():
                if name.endswith("Info.plist") and "Payload/" in name:
                    info_plist_path = name
                    break

            if info_plist_path:
                plist_data = ipa.read(info_plist_path)
                plist_info = await _parse_info_plist(plist_data)
                metadata.update(plist_info)

            # Find embedded.mobileprovision
            for name in ipa.namelist():
                if name.endswith("embedded.mobileprovision"):
                    prov_data = ipa.read(name)
                    prov_info = await _parse_provisioning_profile(prov_data)
                    metadata["signing_info"] = prov_info
                    break

    except zipfile.BadZipFile:
        logger.error(f"Invalid IPA file: {file_path}")
    except Exception as e:
        logger.error(f"Failed to parse IPA: {e}")

    return metadata


async def _parse_info_plist(plist_data: bytes) -> dict[str, Any]:
    """Parse iOS Info.plist."""
    try:
        plist = plistlib.loads(plist_data)

        # Convert version_code to int (CFBundleVersion can be string like "1" or "123")
        version_code_raw = plist.get("CFBundleVersion")
        version_code = None
        if version_code_raw:
            try:
                version_code = int(version_code_raw)
            except (ValueError, TypeError):
                # Some apps use non-numeric build numbers
                version_code = None

        return {
            "package_name": plist.get("CFBundleIdentifier", ""),
            "app_name": plist.get("CFBundleDisplayName") or plist.get("CFBundleName", ""),
            "version_name": plist.get("CFBundleShortVersionString", ""),
            "version_code": version_code,
            "min_ios_version": plist.get("MinimumOSVersion", ""),
        }

    except Exception as e:
        logger.error(f"Failed to parse Info.plist: {e}")
        return {"package_name": "unknown"}


async def _parse_provisioning_profile(prov_data: bytes) -> dict[str, Any]:
    """Parse iOS provisioning profile."""
    # Provisioning profile is a CMS/PKCS7 signed plist
    # Need to extract the plist from the signature
    try:
        # Find plist within the signature
        start = prov_data.find(b"<?xml")
        end = prov_data.find(b"</plist>") + len(b"</plist>")

        if start > 0 and end > start:
            plist_data = prov_data[start:end]
            plist = plistlib.loads(plist_data)

            return {
                "app_id": plist.get("application-identifier"),
                "team_id": plist.get("TeamIdentifier", [None])[0],
                "team_name": plist.get("TeamName"),
                "expiration": str(plist.get("ExpirationDate", "")),
                "provisions_all_devices": plist.get("ProvisionsAllDevices", False),
            }

    except Exception as e:
        logger.error(f"Failed to parse provisioning profile: {e}")

    return {}
