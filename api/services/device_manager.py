"""Device manager service for ADB and iOS device management.

Provides an async interface for discovering, connecting to, and managing
Android (ADB) and iOS (libimobiledevice) devices. Also handles Frida server
installation/startup and application deployment.

Security:
    All device ID inputs are validated via ``_validate_device_id()`` before
    being interpolated into subprocess commands to prevent shell injection.

Supported device types:
    - Physical Android devices connected via USB (ADB).
    - Android emulators (AOSP, Genymotion) connected via ADB.
    - Corellium virtual Android devices connected via API.
    - Physical iOS devices connected via USB (libimobiledevice).
"""

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
    """Manages Android and iOS device discovery, connection, and tooling.

    All methods are async and delegate blocking subprocess calls to
    ``asyncio.to_thread`` to avoid blocking the event loop. Subprocess
    commands use explicit argument lists (no shell=True) and validated
    device IDs to prevent command injection.
    """

    async def discover_android_devices(self) -> list[dict[str, Any]]:
        """Discover connected Android devices via ``adb devices -l``.

        Parses the output of ADB to find all non-offline devices, then
        queries each device for detailed information (model, OS version,
        root status, emulator detection).

        Returns:
            List of device info dicts with keys: ``device_id``, ``device_type``
            (``"physical"``/``"emulator"``/``"genymotion"``), ``platform``,
            ``connection_type``, ``model``, ``os_version``, ``is_rooted``, etc.
            Returns an empty list if ADB is unavailable or no devices found.
        """
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
        """Get detailed info for an Android device via ADB shell getprop.

        Queries device properties including model name, OS version, root
        status (presence of ``su`` binary), and device type (physical vs.
        emulator vs. Genymotion).

        Args:
            device_id: Validated ADB device serial string.

        Returns:
            Dict with device metadata. Always contains ``device_id``,
            ``device_type``, ``platform``, ``connection_type``, ``status``.
            Additional keys (``model``, ``os_version``, ``is_rooted``) are
            populated on a best-effort basis.
        """
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
        """Discover connected iOS devices via ``idevice_id -l``.

        Requires libimobiledevice to be installed on the host system.
        Typically only available on macOS.

        Returns:
            List of device info dicts with keys: ``device_id``, ``device_type``,
            ``platform``, ``device_name``, ``model``, ``os_version``, etc.
            Returns an empty list if libimobiledevice is not installed or
            no devices are connected.
        """
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
        """Get detailed info for an iOS device via ``ideviceinfo``.

        Args:
            device_id: Validated iOS device UDID string.

        Returns:
            Dict with device metadata including ``device_name``, ``model``
            (ProductType), and ``os_version`` (ProductVersion) when available.
        """
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
        """Establish and verify connection to a device.

        Dispatches to platform-specific connection logic based on the
        device's platform field. For Corellium virtual devices, uses the
        Corellium REST API to verify instance state.

        Args:
            device: Device ORM model with ``platform`` and ``device_id`` set.

        Returns:
            True if the device is reachable and in a connected state.

        Raises:
            ValueError: If the device platform is not ``"android"`` or ``"ios"``.
        """
        if device.platform == "android":
            return await self._connect_android(device)
        elif device.platform == "ios":
            return await self._connect_ios(device)
        else:
            raise ValueError(f"Unsupported platform: {device.platform}")

    async def _connect_android(self, device: Device) -> bool:
        """Verify connectivity to an Android device via ``adb get-state``.

        Args:
            device: Device ORM model. If ``device_type`` is ``"corellium"``,
                delegates to ``_connect_corellium_android()``.

        Returns:
            True if ADB reports the device state as ``"device"`` (connected).
        """
        try:
            # Validate device_id to prevent command injection
            device_id = _validate_device_id(device.device_id)

            if device.device_type == "corellium":
                return await self._connect_corellium_android(device)

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
        """Verify connectivity to an iOS device via ``ideviceinfo``.

        Args:
            device: Device ORM model with a valid iOS UDID.

        Returns:
            True if ``ideviceinfo`` exits with return code 0.
        """
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

    async def _connect_corellium_android(self, device: Device) -> bool:
        """Verify a Corellium Android virtual device is powered on.

        Uses the Corellium REST API to query instance state. Requires
        ``corellium_api_key`` and ``corellium_domain`` in application settings
        and ``corellium_instance_id`` on the device record.

        Args:
            device: Device ORM model with ``corellium_instance_id`` set.

        Returns:
            True if the Corellium instance state is ``"on"``.
        """
        try:
            from api.services.corellium_service import CorelliumClient

            if not settings.corellium_api_key:
                logger.error("Corellium API key not configured")
                return False

            if not device.corellium_instance_id:
                logger.error(f"No corellium_instance_id on device {device.device_id}")
                return False

            client = CorelliumClient(settings.corellium_domain, settings.corellium_api_key)
            try:
                info = await client.get_device(device.corellium_instance_id)
                state = info.get("state", "")
                if state == "on":
                    logger.info(f"Corellium device {device.corellium_instance_id} is running")
                    return True
                else:
                    logger.warning(f"Corellium device state is '{state}', not 'on'")
                    return False
            finally:
                await client.close()

        except Exception as e:
            logger.error(f"Failed to connect to Corellium device: {e}")
            return False

    async def install_frida_server(self, device: Device) -> str:
        """Install Frida server on a device.

        Downloads the appropriate frida-server binary from the official
        GitHub releases for the device's CPU architecture, then deploys it.

        Args:
            device: Device ORM model with ``platform`` and ``device_id`` set.

        Returns:
            The installed Frida server version string.

        Raises:
            ValueError: If the device platform is unsupported.
            RuntimeError: If download, extraction, or installation fails.
        """
        version = settings.frida_server_version

        if device.platform == "android":
            return await self._install_frida_android(device, version)
        elif device.platform == "ios":
            return await self._install_frida_ios(device, version)
        else:
            raise ValueError(f"Unsupported platform: {device.platform}")

    async def _install_frida_android(self, device: Device, version: str) -> str:
        """Download and install frida-server on an Android device.

        Performs the full deployment pipeline: detect CPU architecture,
        download the matching frida-server xz archive from GitHub, extract it,
        push via ``adb push`` to ``/data/local/tmp/frida-server``, and set
        executable permissions.

        Args:
            device: Device ORM model with a valid ADB device ID.
            version: Frida server version string (e.g., ``"16.5.9"``).

        Returns:
            The installed version string.

        Raises:
            RuntimeError: If any step (download, extract, push, chmod) fails.
        """
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

        # Download, extract, and push Frida server
        frida_url = f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{frida_arch}.xz"
        local_xz = f"/tmp/frida-server-{version}-{frida_arch}.xz"
        local_bin = f"/tmp/frida-server-{version}-{frida_arch}"
        remote_path = "/data/local/tmp/frida-server"

        logger.info(f"Downloading Frida server from: {frida_url}")

        # Download
        dl_result = await asyncio.to_thread(
            subprocess.run,
            ["curl", "-fSL", "-o", local_xz, frida_url],
            capture_output=True,
            timeout=120,
        )
        if dl_result.returncode != 0:
            raise RuntimeError(f"Failed to download Frida server: {dl_result.stderr.decode()}")

        # Extract
        extract_result = await asyncio.to_thread(
            subprocess.run,
            ["xz", "-d", "-f", local_xz],
            capture_output=True,
            timeout=60,
        )
        if extract_result.returncode != 0:
            raise RuntimeError(f"Failed to extract Frida server: {extract_result.stderr.decode()}")

        # Push to device
        push_result = await asyncio.to_thread(
            subprocess.run,
            ["adb", "-s", device_id, "push", local_bin, remote_path],
            capture_output=True,
            timeout=60,
        )
        if push_result.returncode != 0:
            raise RuntimeError(f"Failed to push Frida server: {push_result.stderr.decode()}")

        # Make executable
        chmod_result = await asyncio.to_thread(
            subprocess.run,
            ["adb", "-s", device_id, "shell", "chmod", "755", remote_path],
            capture_output=True,
            timeout=10,
        )
        if chmod_result.returncode != 0:
            raise RuntimeError(f"Failed to chmod Frida server: {chmod_result.stderr.decode()}")

        # Clean up local file
        import os
        try:
            os.remove(local_bin)
        except OSError:
            pass

        logger.info(f"Frida server {version} installed on device {device_id}")
        return version

    async def _install_frida_ios(self, device: Device, version: str) -> str:
        """Install Frida on an iOS device (requires jailbreak).

        Note:
            This is a placeholder. Full iOS Frida installation typically
            requires Cydia/Sileo or manual deployment via SSH.

        Args:
            device: Device ORM model with a valid iOS UDID.
            version: Frida server version string.

        Returns:
            The version string (no actual installation performed).
        """
        # Would use Cydia or manual installation
        logger.info(f"Would install Frida {version} on iOS device")
        return version

    async def start_frida_server(self, device: Device) -> bool:
        """Start the frida-server daemon on a device.

        For Android: kills any existing frida-server process, launches a
        new instance via ``nohup`` with the ``-D`` (daemonize) flag, waits
        briefly, then verifies the process is running via ``pgrep``.

        For iOS: assumes frida-server is already running (started via SSH).

        Args:
            device: Device ORM model with ``platform`` and ``device_id`` set.

        Returns:
            True if frida-server is confirmed running after startup.
        """
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

            # Start server in background using nohup with shell for proper daemonization
            await asyncio.to_thread(
                subprocess.Popen,
                ["adb", "-s", device_id, "shell",
                 "nohup", "/data/local/tmp/frida-server", "-D"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
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
        """Install an application package on a device.

        Uses ``adb install -r`` for Android (allowing reinstall) or
        ``ideviceinstaller -i`` for iOS.

        Args:
            device: Device ORM model with ``platform`` and ``device_id`` set.
            app_path: Local filesystem path to the APK (Android) or IPA (iOS).

        Returns:
            True if the installation command exits successfully.
        """
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
        """Launch an application on a device.

        For Android, uses ``adb shell monkey`` to trigger the app's launcher
        activity. The package name is validated against an alphanumeric-with-dots
        pattern to prevent command injection.

        Args:
            device: Device ORM model with ``platform`` and ``device_id`` set.
            package_name: Android package name (e.g., ``"com.example.app"``)
                or iOS bundle identifier.

        Returns:
            True if the launch command exits successfully.

        Raises:
            ValueError: If the package name contains invalid characters.
        """
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
