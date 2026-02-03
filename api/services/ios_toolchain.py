"""
iOS Toolchain Service

Provides iOS-specific analysis capabilities with tiered support:
- Tier 1 (Docker): Basic IPA analysis, plist parsing, string extraction
- Tier 2 (Mac Host): libimobiledevice, ios-deploy, class-dump, otool
- Tier 3 (Corellium): Full virtual iOS device with root access
"""

import os
import json
import plistlib
import subprocess
import tempfile
import zipfile
from typing import Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class iOSToolchain:
    """iOS analysis toolchain with capability detection"""

    def __init__(self):
        self.capabilities = self._detect_capabilities()
        self.corellium_client: Optional["CorelliumClient"] = None

    def _detect_capabilities(self) -> dict[str, bool]:
        """Detect available iOS analysis capabilities"""
        caps = {
            "basic_analysis": True,  # Always available
            "libimobiledevice": False,
            "ios_deploy": False,
            "class_dump": False,
            "otool": False,
            "nm": False,
            "frida": False,
            "corellium": False,
        }

        # Check for Mac-only tools
        if os.path.exists("/usr/bin/otool") or self._which("otool"):
            caps["otool"] = True

        if os.path.exists("/usr/bin/nm") or self._which("nm"):
            caps["nm"] = True

        if self._which("idevice_id"):
            caps["libimobiledevice"] = True

        if self._which("ios-deploy"):
            caps["ios_deploy"] = True

        if self._which("class-dump"):
            caps["class_dump"] = True

        if self._which("frida"):
            caps["frida"] = True

        # Check for Corellium credentials
        if os.environ.get("CORELLIUM_API_TOKEN"):
            caps["corellium"] = True

        return caps

    def _which(self, program: str) -> Optional[str]:
        """Find program in PATH"""
        for path in os.environ.get("PATH", "").split(os.pathsep):
            exe = os.path.join(path, program)
            if os.path.isfile(exe) and os.access(exe, os.X_OK):
                return exe
        return None

    def get_capabilities(self) -> dict[str, bool]:
        """Get current capabilities"""
        return self.capabilities

    def get_tier(self) -> int:
        """Get current capability tier"""
        if self.capabilities["corellium"]:
            return 3
        if self.capabilities["libimobiledevice"] or self.capabilities["otool"]:
            return 2
        return 1

    # =========================================================================
    # Tier 1: Basic Analysis (Always Available)
    # =========================================================================

    def extract_ipa(self, ipa_path: str, output_dir: str) -> dict[str, Any]:
        """Extract IPA contents"""
        result = {
            "app_path": None,
            "info_plist_path": None,
            "binary_path": None,
            "files": [],
        }

        with zipfile.ZipFile(ipa_path, "r") as zf:
            zf.extractall(output_dir)
            result["files"] = zf.namelist()

        # Find .app directory
        payload_dir = Path(output_dir) / "Payload"
        if payload_dir.exists():
            for item in payload_dir.iterdir():
                if item.suffix == ".app":
                    result["app_path"] = str(item)
                    result["info_plist_path"] = str(item / "Info.plist")
                    # Find main binary
                    info_plist = item / "Info.plist"
                    if info_plist.exists():
                        with open(info_plist, "rb") as f:
                            plist = plistlib.load(f)
                            executable = plist.get("CFBundleExecutable")
                            if executable:
                                result["binary_path"] = str(item / executable)
                    break

        return result

    def parse_info_plist(self, plist_path: str) -> dict[str, Any]:
        """Parse Info.plist file"""
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)

        return {
            "bundle_id": plist.get("CFBundleIdentifier"),
            "bundle_name": plist.get("CFBundleName"),
            "bundle_display_name": plist.get("CFBundleDisplayName"),
            "version": plist.get("CFBundleShortVersionString"),
            "build": plist.get("CFBundleVersion"),
            "executable": plist.get("CFBundleExecutable"),
            "minimum_os_version": plist.get("MinimumOSVersion"),
            "device_family": plist.get("UIDeviceFamily"),
            "supported_platforms": plist.get("CFBundleSupportedPlatforms"),
            "url_schemes": self._extract_url_schemes(plist),
            "ats_settings": plist.get("NSAppTransportSecurity"),
            "background_modes": plist.get("UIBackgroundModes"),
            "required_capabilities": plist.get("UIRequiredDeviceCapabilities"),
            "permissions": self._extract_permissions(plist),
        }

    def _extract_url_schemes(self, plist: dict) -> list[str]:
        """Extract URL schemes from plist"""
        schemes = []
        url_types = plist.get("CFBundleURLTypes", [])
        for url_type in url_types:
            url_schemes = url_type.get("CFBundleURLSchemes", [])
            schemes.extend(url_schemes)
        return schemes

    def _extract_permissions(self, plist: dict) -> dict[str, str]:
        """Extract permission usage descriptions"""
        permission_keys = [
            "NSCameraUsageDescription",
            "NSPhotoLibraryUsageDescription",
            "NSLocationWhenInUseUsageDescription",
            "NSLocationAlwaysUsageDescription",
            "NSMicrophoneUsageDescription",
            "NSContactsUsageDescription",
            "NSCalendarsUsageDescription",
            "NSRemindersUsageDescription",
            "NSHealthShareUsageDescription",
            "NSHealthUpdateUsageDescription",
            "NSMotionUsageDescription",
            "NSBluetoothPeripheralUsageDescription",
            "NSAppleMusicUsageDescription",
            "NSSpeechRecognitionUsageDescription",
            "NSFaceIDUsageDescription",
            "NSHomeKitUsageDescription",
            "NSSiriUsageDescription",
        ]
        return {k: v for k, v in plist.items() if k in permission_keys and v}

    def parse_entitlements(self, entitlements_path: str) -> dict[str, Any]:
        """Parse entitlements file"""
        with open(entitlements_path, "rb") as f:
            entitlements = plistlib.load(f)

        security_relevant = {
            "get-task-allow": entitlements.get("get-task-allow"),
            "keychain-access-groups": entitlements.get("keychain-access-groups"),
            "application-identifier": entitlements.get("application-identifier"),
            "team-identifier": entitlements.get("com.apple.developer.team-identifier"),
            "aps-environment": entitlements.get("aps-environment"),
            "associated-domains": entitlements.get("com.apple.developer.associated-domains"),
            "app-groups": entitlements.get("com.apple.security.application-groups"),
        }

        return {
            "all": entitlements,
            "security_relevant": security_relevant,
        }

    def extract_strings(self, binary_path: str) -> list[str]:
        """Extract strings from binary"""
        try:
            result = subprocess.run(
                ["strings", binary_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            return result.stdout.splitlines()
        except Exception as e:
            logger.error(f"Failed to extract strings: {e}")
            return []

    # =========================================================================
    # Tier 2: Mac Host Tools
    # =========================================================================

    def analyze_binary_otool(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary using otool"""
        if not self.capabilities["otool"]:
            return {"error": "otool not available"}

        result = {
            "architecture": None,
            "load_commands": [],
            "linked_libraries": [],
            "segments": [],
            "encryption_info": None,
        }

        try:
            # Get architecture info
            arch_result = subprocess.run(
                ["otool", "-hv", binary_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            result["architecture"] = arch_result.stdout

            # Get load commands
            lc_result = subprocess.run(
                ["otool", "-l", binary_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            result["load_commands"] = lc_result.stdout

            # Check for encryption
            if "cryptid 1" in lc_result.stdout.lower():
                result["encryption_info"] = {"encrypted": True}
            else:
                result["encryption_info"] = {"encrypted": False}

            # Get linked libraries
            lib_result = subprocess.run(
                ["otool", "-L", binary_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            libraries = []
            for line in lib_result.stdout.splitlines()[1:]:
                lib = line.strip().split(" (")[0]
                if lib:
                    libraries.append(lib)
            result["linked_libraries"] = libraries

        except Exception as e:
            logger.error(f"otool analysis failed: {e}")
            result["error"] = str(e)

        return result

    def analyze_binary_nm(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary symbols using nm"""
        if not self.capabilities["nm"]:
            return {"error": "nm not available"}

        result = {
            "symbols": [],
            "security_functions": [],
            "crypto_functions": [],
        }

        try:
            nm_result = subprocess.run(
                ["nm", "-U", binary_path],
                capture_output=True,
                text=True,
                timeout=60,
            )

            symbols = []
            security_funcs = []
            crypto_funcs = []

            security_patterns = [
                "SecKeyCreate",
                "SecItemAdd",
                "SecItemCopy",
                "CCCrypt",
                "SecTrust",
                "kSecAttr",
                "SSL",
                "TLS",
            ]

            crypto_patterns = [
                "AES",
                "RSA",
                "SHA",
                "HMAC",
                "PBKDF",
                "encrypt",
                "decrypt",
                "cipher",
            ]

            for line in nm_result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    symbol = parts[-1]
                    symbols.append(symbol)

                    for pattern in security_patterns:
                        if pattern.lower() in symbol.lower():
                            security_funcs.append(symbol)
                            break

                    for pattern in crypto_patterns:
                        if pattern.lower() in symbol.lower():
                            crypto_funcs.append(symbol)
                            break

            result["symbols"] = symbols[:1000]  # Limit
            result["security_functions"] = list(set(security_funcs))
            result["crypto_functions"] = list(set(crypto_funcs))

        except Exception as e:
            logger.error(f"nm analysis failed: {e}")
            result["error"] = str(e)

        return result

    def class_dump_binary(self, binary_path: str) -> dict[str, Any]:
        """Dump Objective-C class information"""
        if not self.capabilities["class_dump"]:
            return {"error": "class-dump not available"}

        result = {
            "classes": [],
            "protocols": [],
            "categories": [],
        }

        try:
            dump_result = subprocess.run(
                ["class-dump", binary_path],
                capture_output=True,
                text=True,
                timeout=120,
            )

            output = dump_result.stdout

            # Parse classes
            import re
            class_pattern = r"@interface\s+(\w+)"
            protocol_pattern = r"@protocol\s+(\w+)"
            category_pattern = r"@interface\s+(\w+)\s*\((\w+)\)"

            result["classes"] = re.findall(class_pattern, output)
            result["protocols"] = re.findall(protocol_pattern, output)
            result["categories"] = re.findall(category_pattern, output)

            result["raw_output"] = output[:50000]  # Limit output

        except Exception as e:
            logger.error(f"class-dump failed: {e}")
            result["error"] = str(e)

        return result

    def list_connected_devices(self) -> list[dict[str, Any]]:
        """List connected iOS devices via libimobiledevice"""
        if not self.capabilities["libimobiledevice"]:
            return []

        devices = []
        try:
            result = subprocess.run(
                ["idevice_id", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for udid in result.stdout.strip().splitlines():
                if udid:
                    device_info = self._get_device_info(udid)
                    devices.append(device_info)

        except Exception as e:
            logger.error(f"Failed to list devices: {e}")

        return devices

    def _get_device_info(self, udid: str) -> dict[str, Any]:
        """Get device information"""
        info = {"udid": udid}
        try:
            result = subprocess.run(
                ["ideviceinfo", "-u", udid],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.splitlines():
                if ": " in line:
                    key, value = line.split(": ", 1)
                    if key in ["DeviceName", "ProductType", "ProductVersion"]:
                        info[key] = value

        except Exception as e:
            logger.error(f"Failed to get device info: {e}")

        return info

    # =========================================================================
    # Tier 3: Corellium Integration
    # =========================================================================

    def init_corellium(self, api_token: str, endpoint: str = "https://app.corellium.com"):
        """Initialize Corellium client"""
        self.corellium_client = CorelliumClient(api_token, endpoint)
        self.capabilities["corellium"] = True

    def get_corellium_client(self) -> Optional["CorelliumClient"]:
        """Get Corellium client if available"""
        return self.corellium_client


class CorelliumClient:
    """Corellium API client for virtual iOS device management"""

    def __init__(self, api_token: str, endpoint: str = "https://app.corellium.com"):
        self.api_token = api_token
        self.endpoint = endpoint.rstrip("/")
        self.session = None

    async def _get_session(self):
        """Get or create HTTP session"""
        if self.session is None:
            import aiohttp
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json",
                }
            )
        return self.session

    async def list_projects(self) -> list[dict[str, Any]]:
        """List Corellium projects"""
        session = await self._get_session()
        async with session.get(f"{self.endpoint}/api/v1/projects") as resp:
            return await resp.json()

    async def list_instances(self, project_id: str) -> list[dict[str, Any]]:
        """List instances in a project"""
        session = await self._get_session()
        async with session.get(
            f"{self.endpoint}/api/v1/projects/{project_id}/instances"
        ) as resp:
            return await resp.json()

    async def get_instance(self, instance_id: str) -> dict[str, Any]:
        """Get instance details"""
        session = await self._get_session()
        async with session.get(
            f"{self.endpoint}/api/v1/instances/{instance_id}"
        ) as resp:
            return await resp.json()

    async def create_instance(
        self,
        project_id: str,
        flavor: str = "iphone12pro",
        os_version: str = "17.0",
        name: str = "mobilicustos-instance",
    ) -> dict[str, Any]:
        """Create a new iOS instance"""
        session = await self._get_session()
        data = {
            "project": project_id,
            "flavor": flavor,
            "os": os_version,
            "name": name,
        }
        async with session.post(
            f"{self.endpoint}/api/v1/instances", json=data
        ) as resp:
            return await resp.json()

    async def start_instance(self, instance_id: str) -> dict[str, Any]:
        """Start an instance"""
        session = await self._get_session()
        async with session.post(
            f"{self.endpoint}/api/v1/instances/{instance_id}/start"
        ) as resp:
            return await resp.json()

    async def stop_instance(self, instance_id: str) -> dict[str, Any]:
        """Stop an instance"""
        session = await self._get_session()
        async with session.post(
            f"{self.endpoint}/api/v1/instances/{instance_id}/stop"
        ) as resp:
            return await resp.json()

    async def delete_instance(self, instance_id: str) -> bool:
        """Delete an instance"""
        session = await self._get_session()
        async with session.delete(
            f"{self.endpoint}/api/v1/instances/{instance_id}"
        ) as resp:
            return resp.status == 204

    async def install_app(self, instance_id: str, ipa_path: str) -> dict[str, Any]:
        """Install an app on the instance"""
        session = await self._get_session()

        with open(ipa_path, "rb") as f:
            data = aiohttp.FormData()
            data.add_field("file", f, filename=Path(ipa_path).name)

            async with session.post(
                f"{self.endpoint}/api/v1/instances/{instance_id}/apps",
                data=data,
            ) as resp:
                return await resp.json()

    async def list_apps(self, instance_id: str) -> list[dict[str, Any]]:
        """List installed apps"""
        session = await self._get_session()
        async with session.get(
            f"{self.endpoint}/api/v1/instances/{instance_id}/apps"
        ) as resp:
            return await resp.json()

    async def get_console_log(self, instance_id: str) -> str:
        """Get console log from instance"""
        session = await self._get_session()
        async with session.get(
            f"{self.endpoint}/api/v1/instances/{instance_id}/console"
        ) as resp:
            return await resp.text()

    async def run_frida_script(
        self, instance_id: str, bundle_id: str, script: str
    ) -> dict[str, Any]:
        """Run a Frida script on the instance"""
        session = await self._get_session()
        data = {
            "bundleId": bundle_id,
            "script": script,
        }
        async with session.post(
            f"{self.endpoint}/api/v1/instances/{instance_id}/agent/run",
            json=data,
        ) as resp:
            return await resp.json()

    async def close(self):
        """Close the session"""
        if self.session:
            await self.session.close()
            self.session = None


# Singleton instance
_ios_toolchain: Optional[iOSToolchain] = None


def get_ios_toolchain() -> iOSToolchain:
    """Get iOS toolchain singleton"""
    global _ios_toolchain
    if _ios_toolchain is None:
        _ios_toolchain = iOSToolchain()
    return _ios_toolchain
