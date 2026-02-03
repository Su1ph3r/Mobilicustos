"""Objection service for runtime mobile app manipulation."""

import asyncio
import logging
import re
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# Validate package names to prevent command injection
PACKAGE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._]+$')


def _validate_package_name(package: str) -> bool:
    """Validate package name format."""
    if not package or len(package) > 256:
        return False
    return bool(PACKAGE_NAME_PATTERN.match(package))


def _validate_path(path: str) -> bool:
    """Validate file path to prevent path traversal."""
    if not path:
        return False
    # Prevent path traversal
    normalized = re.sub(r'/+', '/', path)
    if ".." in normalized:
        return False
    return True


# Built-in Objection commands grouped by category
OBJECTION_COMMANDS = {
    "SSL Pinning": [
        {
            "name": "android sslpinning disable",
            "description": "Disable SSL pinning on Android",
            "platform": "android",
        },
        {
            "name": "ios sslpinning disable",
            "description": "Disable SSL pinning on iOS",
            "platform": "ios",
        },
    ],
    "Root/Jailbreak Detection": [
        {
            "name": "android root disable",
            "description": "Disable root detection on Android",
            "platform": "android",
        },
        {
            "name": "android root simulate",
            "description": "Simulate rooted environment on Android",
            "platform": "android",
        },
        {
            "name": "ios jailbreak disable",
            "description": "Disable jailbreak detection on iOS",
            "platform": "ios",
        },
        {
            "name": "ios jailbreak simulate",
            "description": "Simulate jailbroken environment on iOS",
            "platform": "ios",
        },
    ],
    "File System": [
        {
            "name": "env",
            "description": "Show environment information",
            "platform": "both",
        },
        {
            "name": "file download",
            "description": "Download a file from device",
            "platform": "both",
            "args": ["remote_path", "local_path"],
        },
        {
            "name": "file upload",
            "description": "Upload a file to device",
            "platform": "both",
            "args": ["local_path", "remote_path"],
        },
        {
            "name": "file cat",
            "description": "Print file contents",
            "platform": "both",
            "args": ["path"],
        },
        {
            "name": "android filesystem ls",
            "description": "List directory contents on Android",
            "platform": "android",
            "args": ["path"],
        },
        {
            "name": "ios plist cat",
            "description": "Read iOS plist file",
            "platform": "ios",
            "args": ["path"],
        },
    ],
    "Memory": [
        {
            "name": "memory list modules",
            "description": "List loaded modules",
            "platform": "both",
        },
        {
            "name": "memory list exports",
            "description": "List module exports",
            "platform": "both",
            "args": ["module_name"],
        },
        {
            "name": "memory search",
            "description": "Search memory for string",
            "platform": "both",
            "args": ["pattern"],
        },
        {
            "name": "memory dump all",
            "description": "Dump all memory",
            "platform": "both",
            "args": ["output_file"],
        },
        {
            "name": "memory dump from_base",
            "description": "Dump memory from base address",
            "platform": "both",
            "args": ["base_address", "size", "output_file"],
        },
    ],
    "Keychain/Keystore": [
        {
            "name": "android keystore list",
            "description": "List Android keystore entries",
            "platform": "android",
        },
        {
            "name": "android keystore clear",
            "description": "Clear Android keystore",
            "platform": "android",
        },
        {
            "name": "ios keychain dump",
            "description": "Dump iOS keychain",
            "platform": "ios",
        },
        {
            "name": "ios keychain clear",
            "description": "Clear iOS keychain items",
            "platform": "ios",
        },
    ],
    "SQLite": [
        {
            "name": "sqlite connect",
            "description": "Connect to SQLite database",
            "platform": "both",
            "args": ["db_path"],
        },
        {
            "name": "sqlite execute query",
            "description": "Execute SQL query",
            "platform": "both",
            "args": ["query"],
        },
    ],
    "Hooking": [
        {
            "name": "android hooking list activities",
            "description": "List activities",
            "platform": "android",
        },
        {
            "name": "android hooking list services",
            "description": "List services",
            "platform": "android",
        },
        {
            "name": "android hooking list receivers",
            "description": "List broadcast receivers",
            "platform": "android",
        },
        {
            "name": "android hooking list classes",
            "description": "List loaded classes",
            "platform": "android",
        },
        {
            "name": "android hooking list class_methods",
            "description": "List methods of a class",
            "platform": "android",
            "args": ["class_name"],
        },
        {
            "name": "android hooking watch class",
            "description": "Watch all methods of a class",
            "platform": "android",
            "args": ["class_name"],
        },
        {
            "name": "android hooking watch class_method",
            "description": "Watch a specific method",
            "platform": "android",
            "args": ["class_method"],
        },
        {
            "name": "ios hooking list classes",
            "description": "List ObjC classes",
            "platform": "ios",
        },
        {
            "name": "ios hooking list class_methods",
            "description": "List methods of an ObjC class",
            "platform": "ios",
            "args": ["class_name"],
        },
        {
            "name": "ios hooking watch class",
            "description": "Watch all methods of an ObjC class",
            "platform": "ios",
            "args": ["class_name"],
        },
        {
            "name": "ios hooking watch method",
            "description": "Watch a specific ObjC method",
            "platform": "ios",
            "args": ["method"],
        },
    ],
    "Intent/URL": [
        {
            "name": "android intent launch_activity",
            "description": "Launch an activity",
            "platform": "android",
            "args": ["activity_class"],
        },
        {
            "name": "android intent launch_service",
            "description": "Launch a service",
            "platform": "android",
            "args": ["service_class"],
        },
        {
            "name": "ios ui biometrics_bypass",
            "description": "Bypass biometric authentication",
            "platform": "ios",
        },
    ],
    "Clipboard": [
        {
            "name": "android clipboard monitor",
            "description": "Monitor Android clipboard",
            "platform": "android",
        },
        {
            "name": "ios pasteboard monitor",
            "description": "Monitor iOS pasteboard",
            "platform": "ios",
        },
    ],
}


class ObjectionService:
    """Service for Objection runtime manipulation."""

    def __init__(self):
        self.active_sessions: dict[str, dict] = {}

    async def check_objection_installed(self) -> bool:
        """Check if Objection is installed."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "objection", "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except (FileNotFoundError, OSError):
            return False

    async def list_commands(self, platform: str | None = None) -> dict[str, list[dict]]:
        """List available Objection commands."""
        commands: dict[str, list[dict]] = {}

        for category, cmd_list in OBJECTION_COMMANDS.items():
            filtered = []
            for cmd in cmd_list:
                if platform is None or cmd["platform"] in (platform, "both"):
                    filtered.append(cmd)
            if filtered:
                commands[category] = filtered

        return commands

    async def start_session(
        self,
        device_id: str,
        package_name: str,
        platform: str,
    ) -> dict[str, Any]:
        """Start an Objection session."""
        if not _validate_package_name(package_name):
            return {
                "status": "error",
                "error": "Invalid package name format",
            }

        session_info = {
            "device_id": device_id,
            "package_name": package_name,
            "platform": platform,
            "status": "starting",
            "started_at": datetime.utcnow().isoformat(),
        }

        try:
            if not await self.check_objection_installed():
                session_info["status"] = "error"
                session_info["error"] = "Objection is not installed"
                return session_info

            session_info["status"] = "active"
            return session_info

        except Exception as e:
            logger.error(f"Failed to start Objection session: {e}")
            session_info["status"] = "error"
            session_info["error"] = "Failed to start session"
            return session_info

    async def execute_command(
        self,
        device_id: str,
        package_name: str,
        platform: str,
        command: str,
        args: list[str] | None = None,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Execute an Objection command."""
        if not _validate_package_name(package_name):
            return {
                "command": command,
                "error": "Invalid package name format",
                "result_type": "error",
            }

        result = {
            "command": command,
            "args": args or [],
            "executed_at": datetime.utcnow().isoformat(),
        }

        try:
            # Build command parts safely
            full_args = args or []

            # Build the startup command string
            startup_cmd = command
            if full_args:
                startup_cmd = f"{command} {' '.join(full_args)}"

            # Execute objection with explicit argument list (no shell)
            cmd = [
                "objection",
                "--gadget", package_name,
                "explore", "--startup-command", startup_cmd
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                result["error"] = "Command timed out"
                result["result_type"] = "error"
                return result

            output = stdout.decode("utf-8", errors="ignore")

            if proc.returncode != 0 and not output:
                result["error"] = "Command failed"
                result["result_type"] = "error"
                return result

            result["output"] = output
            result["result_type"] = "success"
            result["data"] = self._parse_output(command, output)

        except FileNotFoundError:
            result["error"] = "Objection is not installed"
            result["result_type"] = "error"
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            result["error"] = "Command execution failed"
            result["result_type"] = "error"

        return result

    def _parse_output(self, command: str, output: str) -> dict[str, Any]:
        """Parse command output into structured data."""
        data: dict[str, Any] = {"raw": output}

        if "list modules" in command:
            modules = []
            for line in output.split("\n"):
                line = line.strip()
                if line and not line.startswith("["):
                    parts = line.split()
                    if len(parts) >= 2:
                        modules.append({
                            "name": parts[0],
                            "base": parts[1] if len(parts) > 1 else None,
                        })
            data["modules"] = modules
            data["count"] = len(modules)

        elif "list classes" in command:
            classes = []
            for line in output.split("\n"):
                line = line.strip()
                if line and not line.startswith("["):
                    classes.append(line)
            data["classes"] = classes[:100]
            data["count"] = len(classes)

        elif "keychain dump" in command or "keystore list" in command:
            items = []
            current_item: dict[str, Any] = {}
            for line in output.split("\n"):
                line = line.strip()
                if line.startswith("---"):
                    if current_item:
                        items.append(current_item)
                    current_item = {}
                elif ":" in line:
                    key, value = line.split(":", 1)
                    current_item[key.strip().lower()] = value.strip()
            if current_item:
                items.append(current_item)
            data["items"] = items
            data["count"] = len(items)

        elif "sslpinning disable" in command:
            data["success"] = "pinning disabled" in output.lower() or "bypass" in output.lower()

        elif "root disable" in command or "jailbreak disable" in command:
            data["success"] = "disabled" in output.lower() or "bypass" in output.lower()

        return data

    async def disable_ssl_pinning(
        self,
        device_id: str,
        package_name: str,
        platform: str,
    ) -> dict[str, Any]:
        """Disable SSL pinning."""
        if platform == "android":
            return await self.execute_command(
                device_id, package_name, platform, "android sslpinning disable"
            )
        else:
            return await self.execute_command(
                device_id, package_name, platform, "ios sslpinning disable"
            )

    async def disable_root_detection(
        self,
        device_id: str,
        package_name: str,
        platform: str,
    ) -> dict[str, Any]:
        """Disable root/jailbreak detection."""
        if platform == "android":
            return await self.execute_command(
                device_id, package_name, platform, "android root disable"
            )
        else:
            return await self.execute_command(
                device_id, package_name, platform, "ios jailbreak disable"
            )

    async def dump_keychain(
        self,
        device_id: str,
        package_name: str,
        platform: str,
    ) -> dict[str, Any]:
        """Dump keychain/keystore."""
        if platform == "android":
            return await self.execute_command(
                device_id, package_name, platform, "android keystore list"
            )
        else:
            return await self.execute_command(
                device_id, package_name, platform, "ios keychain dump"
            )

    async def list_modules(
        self,
        device_id: str,
        package_name: str,
        platform: str,
    ) -> dict[str, Any]:
        """List loaded modules."""
        return await self.execute_command(
            device_id, package_name, platform, "memory list modules"
        )

    async def read_file(
        self,
        device_id: str,
        package_name: str,
        platform: str,
        path: str,
    ) -> dict[str, Any]:
        """Read a file from the device."""
        if not _validate_path(path):
            return {"error": "Invalid path", "result_type": "error"}
        return await self.execute_command(
            device_id, package_name, platform, "file cat", [path]
        )

    async def list_directory(
        self,
        device_id: str,
        package_name: str,
        platform: str,
        path: str,
    ) -> dict[str, Any]:
        """List directory contents."""
        if not _validate_path(path):
            return {"error": "Invalid path", "result_type": "error"}
        if platform == "android":
            return await self.execute_command(
                device_id, package_name, platform, "android filesystem ls", [path]
            )
        else:
            return await self.execute_command(
                device_id, package_name, platform, "file cat", [path]
            )

    async def execute_sql(
        self,
        device_id: str,
        package_name: str,
        platform: str,
        db_path: str,
        query: str,
    ) -> dict[str, Any]:
        """Execute SQL query on a database."""
        if not _validate_path(db_path):
            return {"error": "Invalid database path", "result_type": "error"}

        connect_result = await self.execute_command(
            device_id, package_name, platform, "sqlite connect", [db_path]
        )

        if connect_result.get("result_type") == "error":
            return connect_result

        return await self.execute_command(
            device_id, package_name, platform, "sqlite execute query", [query]
        )

    async def read_plist(
        self,
        device_id: str,
        package_name: str,
        path: str,
    ) -> dict[str, Any]:
        """Read iOS plist file."""
        if not _validate_path(path):
            return {"error": "Invalid path", "result_type": "error"}
        return await self.execute_command(
            device_id, package_name, "ios", "ios plist cat", [path]
        )

    async def stop_session(self, session_id: str) -> dict[str, Any]:
        """Stop an Objection session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
        return {"status": "stopped"}
