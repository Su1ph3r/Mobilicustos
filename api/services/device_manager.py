"""Device manager service for ADB and iOS device management."""

import asyncio
import logging
import re
import subprocess
from typing import Any

from api.config import get_settings
from api.models.database import Device

logger = logging.getLogger(__name__)
settings = get_settings()

# Regex pattern for valid device IDs (alphanumeric, dots, colons, hyphens, underscores)
VALID_DEVICE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9.:_-]+$')


def _validate_device_id(device_id: str) -> str:
    """Validate device ID to prevent command injection.

    Args:
        device_id: Device identifier string

    Returns:
        Validated device ID

    Raises:
        ValueError: If device ID contains invalid characters
    """
    if not device_id or len(device_id) > 128:
        raise ValueError("Invalid device ID length")
    if not VALID_DEVICE_ID_PATTERN.match(device_id):
        raise ValueError(f"Invalid device ID format: {device_id}")
    return device_id


class DeviceManager:
    """Manages Android and iOS device connections."""

    async def discover_android_devices(self) -> list[dict[str, Any]]:
        """Discover connected Android devices via ADB."""
        devices = []

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.strip().split("\n")[1:]:
                if not line.strip() or "offline" in line:
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    device_id = parts[0]
                    device_info = await self._get_android_device_info(device_id)
                    devices.append(device_info)

        except subprocess.TimeoutExpired:
            logger.warning("ADB command timed out")
        except FileNotFoundError:
            logger.warning("ADB not found in PATH")
        except Exception as e:
            logger.error(f"Failed to discover Android devices: {e}")

        return devices

    async def _get_android_device_info(self, device_id: str) -> dict[str, Any]:
        """Get detailed info for an Android device."""
        # Validate device_id to prevent command injection
        device_id = _validate_device_id(device_id)

        info = {
            "device_id": device_id,
            "device_type": "physical",
            "platform": "android",
            "connection_type": "adb",
            "connection_string": device_id,
            "status": "connected",
        }

        try:
            # Get device model
            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "-s", device_id, "shell", "getprop", "ro.product.model"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            info["model"] = result.stdout.strip()

            # Get device name
            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "-s", device_id, "shell", "getprop", "ro.product.device"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            info["device_name"] = result.stdout.strip()

            # Get OS version
            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            info["os_version"] = result.stdout.strip()

            # Check if rooted
            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "-s", device_id, "shell", "which", "su"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            info["is_rooted"] = bool(result.stdout.strip())

            # Check for Genymotion first (more specific)
            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "-s", device_id, "shell", "getprop", "ro.genymotion.version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.stdout.strip():
                info["device_type"] = "genymotion"
            else:
                # Check for generic emulator
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["adb", "-s", device_id, "shell", "getprop", "ro.kernel.qemu"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.stdout.strip() == "1":
                    info["device_type"] = "emulator"

        except Exception as e:
            logger.warning(f"Failed to get device info for {device_id}: {e}")

        return info

    async def discover_ios_devices(self) -> list[dict[str, Any]]:
        """Discover connected iOS devices via libimobiledevice."""
        devices = []

        try:
            # Check if idevice_id is available
            result = await asyncio.to_thread(
                subprocess.run,
                ["idevice_id", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.strip().split("\n"):
                device_id = line.strip()
                if device_id:
                    device_info = await self._get_ios_device_info(device_id)
                    devices.append(device_info)

        except FileNotFoundError:
            logger.info("libimobiledevice not found (expected on non-Mac systems)")
        except Exception as e:
            logger.error(f"Failed to discover iOS devices: {e}")

        return devices

    async def _get_ios_device_info(self, device_id: str) -> dict[str, Any]:
        """Get detailed info for an iOS device."""
        # Validate device_id to prevent command injection
        device_id = _validate_device_id(device_id)

        info = {
            "device_id": device_id,
            "device_type": "physical",
            "platform": "ios",
            "connection_type": "usb",
            "connection_string": device_id,
            "status": "connected",
        }

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["ideviceinfo", "-u", device_id],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()

                    if key == "DeviceName":
                        info["device_name"] = value
                    elif key == "ProductType":
                        info["model"] = value
                    elif key == "ProductVersion":
                        info["os_version"] = value

        except Exception as e:
            logger.warning(f"Failed to get iOS device info for {device_id}: {e}")

        return info

    async def connect(self, device: Device) -> bool:
        """Establish connection to a device."""
        if device.platform == "android":
            return await self._connect_android(device)
        elif device.platform == "ios":
            return await self._connect_ios(device)
        else:
            raise ValueError(f"Unsupported platform: {device.platform}")

    async def _connect_android(self, device: Device) -> bool:
        """Connect to an Android device."""
        try:
            # Validate device_id to prevent command injection
            device_id = _validate_device_id(device.device_id)

            if device.device_type == "corellium":
                # Would use Corellium API
                raise NotImplementedError("Corellium connection not implemented")

            # For physical/emulator, just verify connection
            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "-s", device_id, "get-state"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            return result.stdout.strip() == "device"

        except Exception as e:
            logger.error(f"Failed to connect to Android device: {e}")
            return False

    async def _connect_ios(self, device: Device) -> bool:
        """Connect to an iOS device."""
        try:
            # Validate device_id to prevent command injection
            device_id = _validate_device_id(device.device_id)

            result = await asyncio.to_thread(
                subprocess.run,
                ["ideviceinfo", "-u", device_id],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to connect to iOS device: {e}")
            return False

    async def install_frida_server(self, device: Device) -> str:
        """Install Frida server on a device."""
        version = settings.frida_server_version

        if device.platform == "android":
            return await self._install_frida_android(device, version)
        elif device.platform == "ios":
            return await self._install_frida_ios(device, version)
        else:
            raise ValueError(f"Unsupported platform: {device.platform}")

    async def _install_frida_android(self, device: Device, version: str) -> str:
        """Install Frida server on Android."""
        # Validate device_id to prevent command injection
        device_id = _validate_device_id(device.device_id)

        # Get architecture
        result = await asyncio.to_thread(
            subprocess.run,
            ["adb", "-s", device_id, "shell", "getprop", "ro.product.cpu.abi"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        arch = result.stdout.strip()

        # Map architecture
        arch_map = {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
            "x86_64": "x86_64",
            "x86": "x86",
        }
        frida_arch = arch_map.get(arch, "arm64")

        # Download and push Frida server
        frida_url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{frida_arch}.xz"

        # In production, would download, extract, and push
        logger.info(f"Would install Frida server from: {frida_url}")

        return version

    async def _install_frida_ios(self, device: Device, version: str) -> str:
        """Install Frida on iOS (requires jailbreak)."""
        # Would use Cydia or manual installation
        logger.info(f"Would install Frida {version} on iOS device")
        return version

    async def start_frida_server(self, device: Device) -> bool:
        """Start Frida server on a device."""
        if device.platform != "android":
            # iOS uses frida-server started via SSH
            return True

        try:
            # Validate device_id to prevent command injection
            device_id = _validate_device_id(device.device_id)

            # Kill existing server
            await asyncio.to_thread(
                subprocess.run,
                ["adb", "-s", device_id, "shell", "pkill", "-f", "frida-server"],
                capture_output=True,
                timeout=5,
            )

            # Start server in background
            await asyncio.to_thread(
                subprocess.Popen,
                ["adb", "-s", device_id, "shell", "/data/local/tmp/frida-server", "&"],
            )

            # Wait briefly and verify
            await asyncio.sleep(2)

            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "-s", device_id, "shell", "pgrep", "-f", "frida-server"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            return bool(result.stdout.strip())

        except Exception as e:
            logger.error(f"Failed to start Frida server: {e}")
            return False

    async def install_app(self, device: Device, app_path: str) -> bool:
        """Install an app on a device."""
        # Validate device_id to prevent command injection
        device_id = _validate_device_id(device.device_id)

        if device.platform == "android":
            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "-s", device_id, "install", "-r", app_path],
                capture_output=True,
                timeout=120,
            )
            return result.returncode == 0
        elif device.platform == "ios":
            result = await asyncio.to_thread(
                subprocess.run,
                ["ideviceinstaller", "-u", device_id, "-i", app_path],
                capture_output=True,
                timeout=120,
            )
            return result.returncode == 0
        else:
            return False

    async def launch_app(self, device: Device, package_name: str) -> bool:
        """Launch an app on a device."""
        # Validate device_id to prevent command injection
        device_id = _validate_device_id(device.device_id)

        # Validate package_name (alphanumeric with dots and underscores only)
        if not re.match(r'^[a-zA-Z0-9._]+$', package_name):
            raise ValueError(f"Invalid package name format: {package_name}")

        if device.platform == "android":
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "adb", "-s", device_id, "shell",
                    "monkey", "-p", package_name, "-c",
                    "android.intent.category.LAUNCHER", "1"
                ],
                capture_output=True,
                timeout=30,
            )
            return result.returncode == 0
        elif device.platform == "ios":
            # Would use idevicedebug or similar
            return False
        else:
            return False
