"""Drozer service for dynamic Android testing."""

import asyncio
import logging
import re
import subprocess
from datetime import datetime
from typing import Any
from uuid import UUID

from api.services.device_manager import _validate_device_id

logger = logging.getLogger(__name__)


# Built-in Drozer modules for common security tests
BUILTIN_MODULES = {
    "app.package.info": {
        "description": "Get information about installed packages",
        "category": "Package Analysis",
        "args": ["package"],
    },
    "app.package.list": {
        "description": "List packages with optional filter",
        "category": "Package Analysis",
        "args": ["filter"],
    },
    "app.package.attacksurface": {
        "description": "Get attack surface of a package",
        "category": "Attack Surface",
        "args": ["package"],
    },
    "app.package.manifest": {
        "description": "Get AndroidManifest.xml of a package",
        "category": "Package Analysis",
        "args": ["package"],
    },
    "app.activity.info": {
        "description": "Get information about exported activities",
        "category": "Components",
        "args": ["package"],
    },
    "app.activity.start": {
        "description": "Start an activity",
        "category": "Components",
        "args": ["component", "action", "category", "data_uri", "extras"],
    },
    "app.service.info": {
        "description": "Get information about exported services",
        "category": "Components",
        "args": ["package"],
    },
    "app.service.start": {
        "description": "Start a service",
        "category": "Components",
        "args": ["component", "action"],
    },
    "app.broadcast.info": {
        "description": "Get information about broadcast receivers",
        "category": "Components",
        "args": ["package"],
    },
    "app.broadcast.send": {
        "description": "Send a broadcast intent",
        "category": "Components",
        "args": ["action", "component", "extras"],
    },
    "app.provider.info": {
        "description": "Get information about exported content providers",
        "category": "Content Providers",
        "args": ["package"],
    },
    "app.provider.query": {
        "description": "Query a content provider",
        "category": "Content Providers",
        "args": ["uri", "projection", "selection", "selection_args"],
    },
    "app.provider.insert": {
        "description": "Insert into a content provider",
        "category": "Content Providers",
        "args": ["uri", "values"],
    },
    "app.provider.update": {
        "description": "Update a content provider",
        "category": "Content Providers",
        "args": ["uri", "values", "selection", "selection_args"],
    },
    "app.provider.delete": {
        "description": "Delete from a content provider",
        "category": "Content Providers",
        "args": ["uri", "selection", "selection_args"],
    },
    "app.provider.finduri": {
        "description": "Find content URIs in a package",
        "category": "Content Providers",
        "args": ["package"],
    },
    "scanner.provider.injection": {
        "description": "Scan for SQL injection in content providers",
        "category": "Vulnerability Scanning",
        "args": ["package"],
    },
    "scanner.provider.sqltables": {
        "description": "Find tables accessible through SQL injection",
        "category": "Vulnerability Scanning",
        "args": ["uri"],
    },
    "scanner.provider.traversal": {
        "description": "Scan for path traversal in content providers",
        "category": "Vulnerability Scanning",
        "args": ["package"],
    },
    "scanner.activity.browsable": {
        "description": "Get browsable activities that accept web URIs",
        "category": "Vulnerability Scanning",
        "args": ["package"],
    },
    "scanner.misc.native": {
        "description": "Find native libraries with potentially insecure permissions",
        "category": "Vulnerability Scanning",
        "args": ["package"],
    },
    "scanner.misc.readablefiles": {
        "description": "Find world-readable files in app directories",
        "category": "Vulnerability Scanning",
        "args": ["package"],
    },
    "scanner.misc.writablefiles": {
        "description": "Find world-writable files in app directories",
        "category": "Vulnerability Scanning",
        "args": ["package"],
    },
    "scanner.misc.secretcodes": {
        "description": "Scan for secret codes handled by the package",
        "category": "Vulnerability Scanning",
        "args": ["package"],
    },
    "shell.start": {
        "description": "Start an interactive shell",
        "category": "Shell",
        "args": [],
    },
    "tools.file.download": {
        "description": "Download a file from the device",
        "category": "File Operations",
        "args": ["source", "destination"],
    },
    "tools.file.upload": {
        "description": "Upload a file to the device",
        "category": "File Operations",
        "args": ["source", "destination"],
    },
    "tools.file.size": {
        "description": "Get the size of a file",
        "category": "File Operations",
        "args": ["path"],
    },
    "tools.setup.busybox": {
        "description": "Install busybox on the agent",
        "category": "Setup",
        "args": [],
    },
}

# Allowed characters for package names (prevent command injection)
PACKAGE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._]+$')


def _validate_package_name(package: str) -> bool:
    """Validate package name to prevent command injection."""
    if not package or len(package) > 256:
        return False
    return bool(PACKAGE_NAME_PATTERN.match(package))


def _validate_module_name(module: str) -> bool:
    """Validate module name against allowed list."""
    return module in BUILTIN_MODULES


DROZER_AGENT_APK_PATH = "/app/tools/drozer-agent.apk"


class DrozerService:
    """Service for interacting with Drozer."""

    def __init__(self):
        self.active_sessions: dict[str, dict] = {}

    async def install_agent(self, device_id: str) -> dict[str, Any]:
        """Install drozer agent APK on a device via ADB."""
        device_id = _validate_device_id(device_id)

        import os
        if not os.path.exists(DROZER_AGENT_APK_PATH):
            return {
                "status": "error",
                "error": f"Drozer agent APK not found at {DROZER_AGENT_APK_PATH}",
            }

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    subprocess.run,
                    ["adb", "-s", device_id, "install", "-r", DROZER_AGENT_APK_PATH],
                    capture_output=True,
                    text=True,
                ),
                timeout=120,
            )

            if result.returncode != 0:
                return {
                    "status": "error",
                    "error": f"ADB install failed: {result.stderr}",
                }

            return {
                "status": "installed",
                "message": "Drozer agent installed successfully",
                "device_id": device_id,
            }
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Install timed out"}
        except FileNotFoundError:
            return {"status": "error", "error": "ADB not found"}
        except Exception as e:
            logger.error(f"Failed to install drozer agent: {e}")
            return {"status": "error", "error": "Installation failed"}

    async def check_drozer_installed(self) -> bool:
        """Check if Drozer is installed and available."""
        try:
            result = subprocess.run(
                ["drozer", "version"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    async def list_modules(self) -> dict[str, list[dict]]:
        """List available Drozer modules grouped by category."""
        modules_by_category: dict[str, list[dict]] = {}

        for module_name, config in BUILTIN_MODULES.items():
            category = config["category"]
            if category not in modules_by_category:
                modules_by_category[category] = []

            modules_by_category[category].append({
                "name": module_name,
                "description": config["description"],
                "args": config.get("args", []),
            })

        return modules_by_category

    async def start_session(
        self,
        device_id: str,
        package_name: str,
    ) -> dict[str, Any]:
        """
        Start a Drozer session on a device.

        Note: This requires drozer agent to be installed on the device
        and port forwarding to be set up.
        """
        # Validate inputs
        device_id = _validate_device_id(device_id)
        if not _validate_package_name(package_name):
            return {
                "status": "error",
                "error": "Invalid package name format",
            }

        session_info = {
            "device_id": device_id,
            "package_name": package_name,
            "status": "starting",
            "started_at": datetime.utcnow().isoformat(),
        }

        try:
            # Check if drozer is available
            if not await self.check_drozer_installed():
                session_info["status"] = "error"
                session_info["error"] = "Drozer is not installed on this system"
                return session_info

            # Set up ADB port forwarding for drozer
            # Using subprocess.run with explicit args list (no shell)
            forward_result = subprocess.run(
                ["adb", "-s", device_id, "forward", "tcp:31415", "tcp:31415"],
                capture_output=True,
                timeout=10,
            )

            if forward_result.returncode != 0:
                session_info["status"] = "error"
                session_info["error"] = "Failed to set up port forwarding"
                return session_info

            # Test drozer connection
            test_result = await self._run_module(
                device_id=device_id,
                module_name="app.package.list",
                args={},
                timeout=15,
            )

            if test_result.get("error"):
                session_info["status"] = "error"
                session_info["error"] = "Drozer connection failed"
                return session_info

            session_info["status"] = "active"
            session_info["drozer_port"] = 31415

            return session_info

        except subprocess.TimeoutExpired:
            session_info["status"] = "error"
            session_info["error"] = "Connection timeout"
            return session_info
        except Exception as e:
            logger.error(f"Failed to start Drozer session: {e}")
            session_info["status"] = "error"
            session_info["error"] = "Failed to start session"
            return session_info

    async def run_module(
        self,
        session_id: UUID,
        device_id: str,
        module_name: str,
        args: dict[str, Any],
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Execute a Drozer module."""
        # Validate module name
        if not _validate_module_name(module_name):
            return {
                "module": module_name,
                "error": "Unknown or disallowed module",
                "result_type": "error",
            }

        # Validate package name if provided
        if "package" in args and args["package"]:
            if not _validate_package_name(args["package"]):
                return {
                    "module": module_name,
                    "error": "Invalid package name format",
                    "result_type": "error",
                }

        return await self._run_module(
            device_id=device_id,
            module_name=module_name,
            args=args,
            timeout=timeout,
        )

    async def _run_module(
        self,
        device_id: str,
        module_name: str,
        args: dict[str, Any],
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Internal method to execute a Drozer module."""
        device_id = _validate_device_id(device_id)
        result = {
            "module": module_name,
            "args": args,
            "executed_at": datetime.utcnow().isoformat(),
        }

        try:
            # Build drozer command arguments (no shell, explicit args)
            cmd = ["drozer", "console", "connect"]

            # Build module command with args
            module_cmd_parts = [f"run {module_name}"]

            # Add arguments based on module type
            # Arguments are validated above, so they're safe to use
            if "package" in args and args["package"]:
                module_cmd_parts.append(f"-a {args['package']}")
            if "uri" in args and args["uri"]:
                # Validate URI format
                uri = args["uri"]
                if uri.startswith("content://"):
                    module_cmd_parts.append(f"--uri {uri}")
            if "projection" in args and args["projection"]:
                module_cmd_parts.append(f"--projection {args['projection']}")

            module_cmd = " ".join(module_cmd_parts)

            # Execute via drozer console using subprocess with explicit args
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Send command and exit
            input_cmd = f"{module_cmd}\nexit\n".encode()

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=input_cmd),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                result["error"] = "Command timed out"
                result["result_type"] = "error"
                return result

            output = stdout.decode("utf-8", errors="ignore")

            if proc.returncode != 0 and not output:
                result["error"] = "Module execution failed"
                result["result_type"] = "error"
                return result

            # Parse output based on module type
            result["raw_output"] = output
            result["result_type"] = "info"
            result["data"] = self._parse_module_output(module_name, output)

            # Check for security findings
            findings = self._extract_findings(module_name, output, args)
            if findings:
                result["result_type"] = "finding"
                result["findings"] = findings

        except FileNotFoundError:
            result["error"] = "Drozer is not installed"
            result["result_type"] = "error"
        except Exception as e:
            logger.error(f"Module execution failed: {e}")
            result["error"] = "Module execution failed"
            result["result_type"] = "error"

        return result

    def _parse_module_output(
        self, module_name: str, output: str
    ) -> dict[str, Any]:
        """Parse Drozer module output into structured data."""
        data: dict[str, Any] = {}

        # Remove ANSI escape codes
        output = re.sub(r"\x1b\[[0-9;]*m", "", output)

        # Parse based on module type
        if "app.package.info" in module_name:
            data = self._parse_package_info(output)
        elif "app.package.attacksurface" in module_name:
            data = self._parse_attack_surface(output)
        elif "provider.info" in module_name:
            data = self._parse_provider_info(output)
        elif "activity.info" in module_name:
            data = self._parse_activity_info(output)
        elif "service.info" in module_name:
            data = self._parse_service_info(output)
        elif "scanner." in module_name:
            data = self._parse_scanner_output(output)
        else:
            # Generic parsing
            data["lines"] = [
                line.strip() for line in output.split("\n")
                if line.strip() and not line.startswith("dz>")
            ]

        return data

    def _parse_package_info(self, output: str) -> dict[str, Any]:
        """Parse app.package.info output."""
        info: dict[str, Any] = {}
        current_key = None

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("dz>"):
                continue

            if ":" in line and not line.startswith(" "):
                key, value = line.split(":", 1)
                current_key = key.strip().lower().replace(" ", "_")
                info[current_key] = value.strip()
            elif current_key and line.startswith(" "):
                # Multi-line value
                if isinstance(info.get(current_key), list):
                    info[current_key].append(line.strip())
                elif info.get(current_key):
                    info[current_key] = [info[current_key], line.strip()]

        return info

    def _parse_attack_surface(self, output: str) -> dict[str, Any]:
        """Parse app.package.attacksurface output."""
        surface = {
            "exported_activities": 0,
            "exported_services": 0,
            "exported_receivers": 0,
            "exported_providers": 0,
            "is_debuggable": False,
        }

        for line in output.split("\n"):
            line = line.lower()
            if "activities exported" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    surface["exported_activities"] = int(match.group(1))
            elif "services exported" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    surface["exported_services"] = int(match.group(1))
            elif "receivers exported" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    surface["exported_receivers"] = int(match.group(1))
            elif "providers exported" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    surface["exported_providers"] = int(match.group(1))
            elif "is debuggable" in line:
                surface["is_debuggable"] = True

        return surface

    def _parse_provider_info(self, output: str) -> dict[str, Any]:
        """Parse app.provider.info output."""
        providers = []
        current_provider: dict[str, Any] | None = None

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("dz>"):
                continue

            if "Authority:" in line:
                if current_provider:
                    providers.append(current_provider)
                current_provider = {"authority": line.split(":", 1)[1].strip()}
            elif current_provider:
                if "Read Permission:" in line:
                    current_provider["read_permission"] = line.split(":", 1)[1].strip()
                elif "Write Permission:" in line:
                    current_provider["write_permission"] = line.split(":", 1)[1].strip()
                elif "Grant Uri Permissions:" in line:
                    current_provider["grant_uri_permissions"] = line.split(":", 1)[1].strip()

        if current_provider:
            providers.append(current_provider)

        return {"providers": providers, "count": len(providers)}

    def _parse_activity_info(self, output: str) -> dict[str, Any]:
        """Parse app.activity.info output."""
        activities = []

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("dz>") or line.startswith("Package:"):
                continue

            if "/" in line:
                activities.append({
                    "name": line,
                    "exported": True,
                })

        return {"activities": activities, "count": len(activities)}

    def _parse_service_info(self, output: str) -> dict[str, Any]:
        """Parse app.service.info output."""
        services = []

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("dz>") or line.startswith("Package:"):
                continue

            if "/" in line:
                services.append({
                    "name": line,
                    "exported": True,
                })

        return {"services": services, "count": len(services)}

    def _parse_scanner_output(self, output: str) -> dict[str, Any]:
        """Parse scanner module output."""
        findings = []
        vulnerabilities = []

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("dz>"):
                continue

            if "vulnerable" in line.lower() or "injection" in line.lower():
                vulnerabilities.append(line)
            elif "content://" in line:
                findings.append({"uri": line})
            elif line and not line.startswith("-"):
                findings.append({"info": line})

        return {
            "findings": findings,
            "vulnerabilities": vulnerabilities,
            "has_vulnerabilities": len(vulnerabilities) > 0,
        }

    def _extract_findings(
        self, module_name: str, output: str, args: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract security findings from module output."""
        findings = []

        output_lower = output.lower()
        package = args.get("package", "unknown")

        # SQL Injection findings
        if "injection" in module_name:
            if "vulnerable" in output_lower or "injection possible" in output_lower:
                uris = re.findall(r"content://[^\s]+", output)
                for uri in uris:
                    findings.append({
                        "title": "SQL Injection in Content Provider",
                        "severity": "high",
                        "category": "SQL Injection",
                        "description": f"Content provider URI {uri} is vulnerable to SQL injection",
                        "affected_component": uri,
                        "package": package,
                        "cwe_id": "CWE-89",
                    })

        # Path Traversal findings
        if "traversal" in module_name:
            if "vulnerable" in output_lower or "traversal possible" in output_lower:
                uris = re.findall(r"content://[^\s]+", output)
                for uri in uris:
                    findings.append({
                        "title": "Path Traversal in Content Provider",
                        "severity": "high",
                        "category": "Path Traversal",
                        "description": f"Content provider URI {uri} is vulnerable to path traversal",
                        "affected_component": uri,
                        "package": package,
                        "cwe_id": "CWE-22",
                    })

        # World-readable/writable files
        if "readable" in module_name or "writable" in module_name:
            files = re.findall(r"/[^\s]+", output)
            perm_type = "readable" if "readable" in module_name else "writable"
            for file_path in files:
                if file_path.startswith("/data/") or file_path.startswith("/sdcard/"):
                    findings.append({
                        "title": f"World-{perm_type.title()} File",
                        "severity": "medium",
                        "category": "File Permissions",
                        "description": f"File {file_path} is world-{perm_type}",
                        "affected_component": file_path,
                        "package": package,
                        "cwe_id": "CWE-732",
                    })

        # Debuggable application
        if "attacksurface" in module_name:
            if "is debuggable" in output_lower:
                findings.append({
                    "title": "Application is Debuggable",
                    "severity": "high",
                    "category": "Configuration",
                    "description": f"Package {package} has android:debuggable=true",
                    "affected_component": package,
                    "package": package,
                    "cwe_id": "CWE-489",
                })

        return findings

    async def stop_session(self, device_id: str) -> dict[str, Any]:
        """Stop a Drozer session and clean up."""
        device_id = _validate_device_id(device_id)
        try:
            subprocess.run(
                ["adb", "-s", device_id, "forward", "--remove", "tcp:31415"],
                capture_output=True,
                timeout=10,
            )
            return {"status": "stopped"}
        except Exception as e:
            logger.error(f"Failed to stop session: {e}")
            return {"status": "error", "error": "Failed to stop session"}

    async def enumerate_packages(
        self, device_id: str, filter_term: str | None = None
    ) -> dict[str, Any]:
        """Enumerate packages on the device."""
        args = {"filter": filter_term} if filter_term else {}
        return await self._run_module(device_id, "app.package.list", args)

    async def get_attack_surface(
        self, device_id: str, package_name: str
    ) -> dict[str, Any]:
        """Get attack surface for a package."""
        if not _validate_package_name(package_name):
            return {"error": "Invalid package name"}
        return await self._run_module(
            device_id, "app.package.attacksurface", {"package": package_name}
        )

    async def enumerate_providers(
        self, device_id: str, package_name: str
    ) -> dict[str, Any]:
        """Enumerate content providers for a package."""
        if not _validate_package_name(package_name):
            return {"error": "Invalid package name"}
        return await self._run_module(
            device_id, "app.provider.info", {"package": package_name}
        )

    async def test_sql_injection(
        self, device_id: str, package_name: str
    ) -> dict[str, Any]:
        """Test for SQL injection in content providers."""
        if not _validate_package_name(package_name):
            return {"error": "Invalid package name"}
        return await self._run_module(
            device_id, "scanner.provider.injection", {"package": package_name}
        )

    async def test_path_traversal(
        self, device_id: str, package_name: str
    ) -> dict[str, Any]:
        """Test for path traversal in content providers."""
        if not _validate_package_name(package_name):
            return {"error": "Invalid package name"}
        return await self._run_module(
            device_id, "scanner.provider.traversal", {"package": package_name}
        )
