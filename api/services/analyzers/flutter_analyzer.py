"""Flutter/Dart analyzer using Blutter for AOT snapshots."""

import asyncio
import json
import logging
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer
from api.services.docker_executor import DockerExecutor

logger = logging.getLogger(__name__)


class FlutterAnalyzer(BaseAnalyzer):
    """Analyzes Flutter applications using Blutter."""

    name = "flutter_analyzer"
    platform = "cross-platform"

    def __init__(self):
        self.docker = DockerExecutor()

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze a Flutter application."""
        findings: list[Finding] = []

        if not app.file_path or app.framework != "flutter":
            return findings

        try:
            # Extract libapp.so for Blutter analysis
            libapp_path = await self._extract_libapp(Path(app.file_path), app.platform)

            if libapp_path:
                # Run Blutter analysis
                blutter_output = await self._run_blutter(libapp_path)

                if blutter_output:
                    # Parse Blutter output for security issues
                    findings.extend(
                        await self._analyze_blutter_output(app, blutter_output)
                    )

            # Also check for common Flutter security issues
            findings.extend(await self._check_flutter_config(app))

        except Exception as e:
            logger.error(f"Flutter analysis failed: {e}")

        return findings

    async def _extract_libapp(
        self,
        archive_path: Path,
        platform: str,
    ) -> Path | None:
        """Extract libapp.so (Android) or App.framework (iOS)."""
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                if platform == "android":
                    # Find libapp.so (prefer arm64)
                    libapp_files = [n for n in archive.namelist() if n.endswith("libapp.so")]
                    # Prefer arm64-v8a
                    target_file = None
                    for f in libapp_files:
                        if "arm64-v8a" in f:
                            target_file = f
                            break
                    if not target_file and libapp_files:
                        target_file = libapp_files[0]

                    if target_file:
                        # Extract to shared analyzer temp directory (accessible by sibling containers)
                        import hashlib
                        import os
                        archive_hash = hashlib.md5(str(archive_path).encode()).hexdigest()[:8]
                        analyzer_temp = os.environ.get("ANALYZER_TEMP_PATH", "/tmp/mobilicustos_analyzer")
                        extract_dir = Path(analyzer_temp) / f"blutter_extract_{archive_hash}"
                        extract_dir.mkdir(parents=True, exist_ok=True)
                        archive.extract(target_file, extract_dir)
                        return extract_dir / target_file

                elif platform == "ios":
                    # Find App.framework/App
                    for name in archive.namelist():
                        if "App.framework/App" in name:
                            import hashlib
                            import os
                            archive_hash = hashlib.md5(str(archive_path).encode()).hexdigest()[:8]
                            analyzer_temp = os.environ.get("ANALYZER_TEMP_PATH", "/tmp/mobilicustos_analyzer")
                            extract_dir = Path(analyzer_temp) / f"blutter_extract_{archive_hash}"
                            extract_dir.mkdir(parents=True, exist_ok=True)
                            archive.extract(name, extract_dir)
                            return extract_dir / name

        except Exception as e:
            logger.error(f"Failed to extract Flutter binary: {e}")

        return None

    async def _run_blutter(self, libapp_path: Path) -> dict[str, Any] | None:
        """Run Blutter on the extracted binary."""
        try:
            output_dir = libapp_path.parent / "blutter_output"
            output_dir.mkdir(exist_ok=True)

            result = await self.docker.run_tool(
                tool_name="blutter",
                input_path=libapp_path,
                output_path=output_dir,
            )

            if result["exit_code"] == 0:
                # Parse output files
                return await self._parse_blutter_output(output_dir)
            else:
                logger.warning(f"Blutter failed: {result['stderr']}")

        except Exception as e:
            logger.error(f"Blutter execution failed: {e}")

        return None

    async def _parse_blutter_output(
        self,
        output_dir: Path,
    ) -> dict[str, Any]:
        """Parse Blutter output files."""
        output: dict[str, Any] = {
            "classes": [],
            "functions": [],
            "strings": [],
        }

        try:
            # Parse pp.txt (function/class info)
            pp_file = output_dir / "pp.txt"
            if pp_file.exists():
                content = pp_file.read_text()
                # Extract class and function names
                for line in content.split("\n"):
                    if "class " in line.lower():
                        output["classes"].append(line.strip())
                    elif "function " in line.lower() or "(" in line:
                        output["functions"].append(line.strip())

            # Parse strings if available
            strings_file = output_dir / "strings.txt"
            if strings_file.exists():
                output["strings"] = strings_file.read_text().split("\n")

        except Exception as e:
            logger.error(f"Failed to parse Blutter output: {e}")

        return output

    async def _analyze_blutter_output(
        self,
        app: MobileApp,
        output: dict[str, Any],
    ) -> list[Finding]:
        """Analyze Blutter output for security issues."""
        findings: list[Finding] = []

        # Check for sensitive function names
        sensitive_patterns = [
            ("password", "Password handling function"),
            ("encrypt", "Encryption function"),
            ("decrypt", "Decryption function"),
            ("token", "Token handling function"),
            ("auth", "Authentication function"),
            ("api_key", "API key handling"),
            ("secret", "Secret handling function"),
            ("biometric", "Biometric authentication"),
        ]

        for func in output.get("functions", []):
            func_lower = func.lower()
            for pattern, desc in sensitive_patterns:
                if pattern in func_lower:
                    lib_file = "libapp.so" if app.platform == "android" else "App.framework/App"
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Sensitive Function Detected: {func[:50]}",
                        severity="info",
                        category="Code Analysis",
                        description=(
                            f"A {desc} was found in the Dart code: {func}\n\n"
                            f"This function should be reviewed for proper security implementation."
                        ),
                        impact="Improper implementation could lead to security vulnerabilities such as credential leakage or authentication bypass.",
                        remediation="Review the function implementation for security best practices. Ensure sensitive data is encrypted and properly protected.",
                        file_path=lib_file,
                        code_snippet=f"// Dart function detected:\n{func}",
                        poc_evidence=f"Found via Blutter analysis: {func}",
                        poc_verification=f"1. Extract {'APK' if app.platform == 'android' else 'IPA'}\n2. Run Blutter on {lib_file}\n3. Search for function: {pattern}",
                        poc_commands=[
                            {"type": "bash", "command": f"unzip {app.file_path} -d /tmp/extracted", "description": "Extract application archive"},
                            {"type": "bash", "command": f"blutter /tmp/extracted/{'lib/arm64-v8a/libapp.so' if app.platform == 'android' else 'Payload/*.app/Frameworks/App.framework/App'} /tmp/blutter_out", "description": "Run Blutter on Flutter binary"},
                            {"type": "bash", "command": f"grep -rn '{pattern}' /tmp/blutter_out/", "description": "Search for sensitive pattern in Blutter output"},
                        ],
                        owasp_masvs_category="MASVS-CODE",
                    ))
                    break

        # Check strings for secrets
        secret_patterns = [
            (r"[A-Za-z0-9+/=]{40,}", "Possible base64-encoded secret"),
            (r"https?://[^\s]+/api/", "API endpoint"),
            (r"firebase\.com", "Firebase URL"),
        ]

        import re
        for string in output.get("strings", []):
            for pattern, desc in secret_patterns:
                if re.search(pattern, string):
                    lib_file = "libapp.so" if app.platform == "android" else "App.framework/App"
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Sensitive String in Dart Code",
                        severity="low",
                        category="Secrets",
                        description=(
                            f"{desc} found in compiled Dart code:\n{string[:100]}..."
                        ),
                        impact="Hardcoded values can be extracted from the app binary using string extraction or decompilation.",
                        remediation="Use secure storage or environment configuration. For API endpoints, use certificate pinning.",
                        file_path=lib_file,
                        code_snippet=f"// Extracted string:\n\"{string[:200]}\"",
                        poc_evidence=f"String: {string[:50]}...",
                        poc_verification="1. Extract app binary\n2. Run strings or Blutter\n3. Search for sensitive patterns",
                        poc_commands=[
                            {"type": "bash", "command": f"strings /tmp/extracted/{'lib/arm64-v8a/libapp.so' if app.platform == 'android' else 'Payload/*.app/Frameworks/App.framework/App'} | grep -i api", "description": "Extract and search strings for API references"},
                            {"type": "bash", "command": "strings /tmp/extracted/libapp.so | grep -E 'http|api_key|token'", "description": "Search for sensitive patterns in strings"},
                        ],
                        owasp_masvs_category="MASVS-STORAGE",
                    ))
                    break

        return findings

    async def _check_flutter_config(self, app: MobileApp) -> list[Finding]:
        """Check Flutter-specific configuration issues."""
        findings: list[Finding] = []

        try:
            with zipfile.ZipFile(app.file_path, "r") as archive:
                file_list = archive.namelist()

                # Check for debug mode indicators
                if any("vm_snapshot_data" in f for f in file_list):
                    # Non-AOT build (debug/profile mode)
                    findings.append(self.create_finding(
                        app=app,
                        title="Flutter App May Be Debug/Profile Build",
                        severity="medium",
                        category="Build Configuration",
                        description=(
                            "The Flutter app appears to be built in debug or profile mode "
                            "(contains vm_snapshot_data). This includes additional debugging "
                            "capabilities and may have reduced obfuscation."
                        ),
                        impact=(
                            "Debug builds are easier to reverse engineer and may include "
                            "debug logging, assertions, and development features."
                        ),
                        remediation=(
                            "Build release versions with: flutter build apk --release\n"
                            "Enable obfuscation with: --obfuscate --split-debug-info"
                        ),
                        file_path="assets/flutter_assets/vm_snapshot_data",
                        code_snippet="# Build command for release:\nflutter build apk --release --obfuscate --split-debug-info=build/symbols",
                        poc_evidence="vm_snapshot_data file found - indicates debug/profile build",
                        poc_verification="1. Unzip APK/IPA\n2. Check for vm_snapshot_data file\n3. Debug builds contain Dart VM",
                        poc_commands=[
                            {"type": "bash", "command": f"unzip -l {app.file_path} | grep vm_snapshot", "description": "Check for VM snapshot file (debug mode indicator)"},
                            {"type": "bash", "command": "unzip -l app.apk | grep flutter_assets", "description": "List flutter assets in archive"},
                        ],
                        owasp_masvs_category="MASVS-RESILIENCE",
                        owasp_masvs_control="MASVS-RESILIENCE-1",
                    ))

                # Check for flutter_assets without obfuscation
                assets_count = sum(1 for f in file_list if "flutter_assets" in f)
                if assets_count > 0:
                    # Check if obfuscation was used
                    # Obfuscated apps typically have shorter asset names
                    findings.append(self.create_finding(
                        app=app,
                        title="Flutter Assets Present",
                        severity="info",
                        category="Build Configuration",
                        description=(
                            f"Found {assets_count} files in flutter_assets. "
                            "Review for sensitive data and consider obfuscation."
                        ),
                        impact="Assets may contain configuration files, strings, or sensitive data that can be extracted.",
                        remediation="Use --obfuscate flag and review asset contents. Don't store secrets in assets.",
                        file_path="assets/flutter_assets/",
                        poc_evidence=f"{assets_count} flutter_assets files found",
                        poc_verification="1. Unzip APK/IPA\n2. Browse flutter_assets directory\n3. Check for config files, JSON, strings",
                        poc_commands=[
                            {"type": "bash", "command": f"unzip {app.file_path} -d /tmp/extracted", "description": "Extract application archive"},
                            {"type": "bash", "command": "ls -la /tmp/extracted/assets/flutter_assets/", "description": "List flutter assets directory"},
                            {"type": "bash", "command": "cat /tmp/extracted/assets/flutter_assets/*.json 2>/dev/null || true", "description": "Check for config files in flutter assets"},
                        ],
                        owasp_masvs_category="MASVS-RESILIENCE",
                    ))

        except Exception as e:
            logger.error(f"Flutter config check failed: {e}")

        return findings
