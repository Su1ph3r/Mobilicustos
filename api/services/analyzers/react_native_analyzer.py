"""React Native analyzer using hermes-dec for Hermes bytecode."""

import asyncio
import json
import logging
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer
from api.services.docker_executor import DockerExecutor

logger = logging.getLogger(__name__)


class ReactNativeAnalyzer(BaseAnalyzer):
    """Analyzes React Native applications."""

    name = "react_native_analyzer"
    platform = "cross-platform"

    def __init__(self):
        self.docker = DockerExecutor()

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze a React Native application."""
        findings: list[Finding] = []

        if not app.file_path or app.framework != "react_native":
            return findings

        try:
            bundle_path, is_hermes = await self._extract_bundle(
                Path(app.file_path), app.platform
            )

            if bundle_path:
                if is_hermes:
                    js_content = await self._decompile_hermes(bundle_path)
                else:
                    js_content = bundle_path.read_text(errors="ignore")

                if js_content:
                    findings.extend(await self._analyze_js_bundle(app, js_content))

            findings.extend(await self._check_rn_config(app))

        except Exception as e:
            logger.error(f"React Native analysis failed: {e}")

        return findings

    async def _extract_bundle(
        self,
        archive_path: Path,
        platform: str,
    ) -> tuple[Path | None, bool]:
        """Extract JS bundle from APK/IPA."""
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                is_hermes = False

                if platform == "android":
                    bundle_names = [
                        "assets/index.android.bundle",
                        "assets/index.bundle",
                    ]
                else:
                    bundle_names = [
                        "main.jsbundle",
                        "Payload/*/main.jsbundle",
                    ]

                for name in archive.namelist():
                    for bundle_name in bundle_names:
                        if bundle_name in name or name.endswith(bundle_name.split("/")[-1]):
                            temp_dir = Path(tempfile.mkdtemp())
                            archive.extract(name, temp_dir)
                            extracted_path = temp_dir / name

                            with open(extracted_path, "rb") as f:
                                magic = f.read(8)
                                is_hermes = magic[:4] == b"\xc6\x1f\xbc\x03"

                            return extracted_path, is_hermes

        except Exception as e:
            logger.error(f"Failed to extract RN bundle: {e}")

        return None, False

    async def _decompile_hermes(self, bundle_path: Path) -> str | None:
        """Decompile Hermes bytecode using hermes-dec."""
        try:
            output_dir = bundle_path.parent / "hermes_output"
            output_dir.mkdir(exist_ok=True)

            result = await self.docker.run_tool(
                tool_name="hermes-dec",
                input_path=bundle_path,
                output_path=output_dir,
            )

            if result["exit_code"] == 0:
                output_file = output_dir / "output.js"
                if output_file.exists():
                    return output_file.read_text(errors="ignore")

                for f in output_dir.rglob("*.js"):
                    return f.read_text(errors="ignore")

            logger.warning(f"hermes-dec failed: {result['stderr']}")

        except Exception as e:
            logger.error(f"Hermes decompilation failed: {e}")

        return None

    async def _analyze_js_bundle(
        self,
        app: MobileApp,
        js_content: str,
    ) -> list[Finding]:
        """Analyze JS bundle for security issues."""
        findings: list[Finding] = []

        findings.extend(await self._check_js_secrets(app, js_content))
        findings.extend(await self._check_insecure_patterns(app, js_content))
        findings.extend(await self._check_debug_code(app, js_content))
        findings.extend(await self._check_api_endpoints(app, js_content))

        return findings

    async def _check_js_secrets(
        self,
        app: MobileApp,
        js_content: str,
    ) -> list[Finding]:
        """Check for secrets in JS code."""
        findings: list[Finding] = []

        secret_patterns = [
            (r"api[_-]?key[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9_-]{20,})", "API Key"),
            (r"api[_-]?secret[\"'\s]*[:=][\"'\s]*([a-zA-Z0-9_-]{20,})", "API Secret"),
            (r"bearer\s+([a-zA-Z0-9_.-]+)", "Bearer Token"),
            (r"password[\"'\s]*[:=][\"'\s]*([^\"']{8,})", "Password"),
        ]

        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 50)
                context = js_content[start:end]

                bundle_file = "assets/index.android.bundle" if app.platform == "android" else "main.jsbundle"
                findings.append(self.create_finding(
                    app=app,
                    title=f"Potential {secret_type} in JavaScript Bundle",
                    severity="high",
                    category="Secrets",
                    description=(
                        f"A potential {secret_type} was found in the React Native "
                        f"JavaScript bundle. This secret can be extracted by decompiling the app."
                    ),
                    impact="Attackers can extract the JS bundle and search for credentials, potentially compromising backend systems.",
                    remediation="Use environment variables or secure storage for secrets. Never hardcode API keys or passwords.",
                    file_path=bundle_file,
                    code_snippet=context,
                    poc_evidence=f"Potential {secret_type} found in JS bundle",
                    poc_verification=f"1. Extract {'APK' if app.platform == 'android' else 'IPA'}\n2. Locate {bundle_file}\n3. Search for credentials",
                    poc_commands=[
                        f"unzip {app.file_path} -d /tmp/extracted",
                        f"grep -n '{pattern[:20]}' /tmp/extracted/{bundle_file}",
                        f"strings /tmp/extracted/{bundle_file} | grep -i 'api\\|key\\|secret\\|token'",
                    ],
                    cwe_id="CWE-798",
                    owasp_masvs_category="MASVS-STORAGE",
                ))

        return findings

    async def _check_insecure_patterns(
        self,
        app: MobileApp,
        js_content: str,
    ) -> list[Finding]:
        """Check for insecure code patterns."""
        findings: list[Finding] = []

        # Patterns for security issues we want to detect
        insecure_pattern_checks = [
            ("dynamic_code_exec", r"eval\s*\(", "Dynamic Code Execution", "high", "CWE-95"),
            ("unsafe_html", r"dangerously" + r"SetInnerHTML", "Unsafe HTML Rendering", "medium", "CWE-79"),
            ("async_storage_password", r"AsyncStorage\.setItem\s*\([^)]*password", "Password in AsyncStorage", "high", "CWE-312"),
            ("http_request", r"fetch\s*\(\s*[\"']http://", "HTTP Request (Not HTTPS)", "medium", "CWE-319"),
        ]

        for name, pattern, title, severity, cwe in insecure_pattern_checks:
            match = re.search(pattern, js_content, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(js_content), match.end() + 30)
                context = js_content[start:end]
                bundle_file = "assets/index.android.bundle" if app.platform == "android" else "main.jsbundle"
                findings.append(self.create_finding(
                    app=app,
                    title=title,
                    severity=severity,
                    category="Insecure Patterns",
                    description=f"Detected {title.lower()} pattern in the JavaScript bundle.",
                    impact="Could lead to security vulnerabilities in the application such as XSS, data exposure, or code injection.",
                    remediation="Review and fix the identified pattern. Avoid dynamic code execution, use HTTPS, and use secure storage instead of AsyncStorage for sensitive data.",
                    file_path=bundle_file,
                    code_snippet=f"// Pattern found:\n{context}",
                    poc_evidence=f"Insecure pattern '{name}' found",
                    poc_verification=f"1. Extract JS bundle\n2. Search for the insecure pattern",
                    poc_commands=[
                        f"unzip {app.file_path} -d /tmp/extracted",
                        f"grep -n '{name}' /tmp/extracted/{bundle_file}",
                    ],
                    cwe_id=cwe,
                    owasp_masvs_category="MASVS-CODE",
                ))

        return findings

    async def _check_debug_code(
        self,
        app: MobileApp,
        js_content: str,
    ) -> list[Finding]:
        """Check for debug/development code."""
        findings: list[Finding] = []

        debug_indicators = ["__DEV__", "debugger;", "ReactNativeDebugger", "reactotron"]
        found_indicators = [ind for ind in debug_indicators if ind in js_content]

        if found_indicators:
            bundle_file = "assets/index.android.bundle" if app.platform == "android" else "main.jsbundle"
            findings.append(self.create_finding(
                app=app,
                title="Debug/Development Code Present",
                severity="medium",
                category="Build Configuration",
                description=f"Debug indicators found: {', '.join(found_indicators)}. This suggests the app was built in development mode.",
                impact="Debug builds may include additional logging, debugging capabilities, and development tools that expose app internals.",
                remediation="Build production releases without debug code. Set __DEV__ to false and remove debugger statements.",
                file_path=bundle_file,
                code_snippet=f"// Debug indicators found:\n{chr(10).join(found_indicators)}",
                poc_evidence=f"Found debug indicators: {', '.join(found_indicators)}",
                poc_verification="1. Extract JS bundle\n2. Search for __DEV__, debugger, or debug tools",
                poc_commands=[
                    f"unzip {app.file_path} -d /tmp/extracted",
                    f"grep -n '__DEV__\\|debugger' /tmp/extracted/{bundle_file}",
                ],
                owasp_masvs_category="MASVS-RESILIENCE",
            ))

        return findings

    async def _check_api_endpoints(
        self,
        app: MobileApp,
        js_content: str,
    ) -> list[Finding]:
        """Extract and analyze API endpoints."""
        findings: list[Finding] = []

        url_pattern = r'["\']https?://[^"\']+["\']'
        urls = re.findall(url_pattern, js_content)

        api_urls = set()
        for url in urls:
            url = url.strip("\"'")
            if any(x in url.lower() for x in ["/api/", "/v1/", "/v2/", "graphql"]):
                api_urls.add(url)

        if api_urls:
            url_list = "\n".join(f"- {url}" for url in list(api_urls)[:20])
            bundle_file = "assets/index.android.bundle" if app.platform == "android" else "main.jsbundle"
            findings.append(self.create_finding(
                app=app,
                title=f"API Endpoints Discovered ({len(api_urls)})",
                severity="info",
                category="API Discovery",
                description=f"Found API endpoints:\n\n{url_list}",
                impact="Attackers can map the API surface for further testing and identify potential attack vectors.",
                remediation="Ensure all API endpoints are properly authenticated and rate-limited. Implement certificate pinning.",
                file_path=bundle_file,
                code_snippet=f"// Discovered endpoints:\n{url_list}",
                poc_evidence=f"Found {len(api_urls)} API endpoints",
                poc_verification="1. Extract JS bundle\n2. Search for API URLs\n3. Test each endpoint for authentication",
                poc_commands=[
                    f"unzip {app.file_path} -d /tmp/extracted",
                    f"grep -oE 'https?://[^\"]+' /tmp/extracted/{bundle_file} | sort -u",
                ],
                owasp_masvs_category="MASVS-NETWORK",
            ))

        return findings

    async def _check_rn_config(self, app: MobileApp) -> list[Finding]:
        """Check React Native specific configurations."""
        findings: list[Finding] = []

        try:
            with zipfile.ZipFile(app.file_path, "r") as archive:
                file_list = archive.namelist()

                has_hermes = any("libhermes.so" in f for f in file_list)

                if not has_hermes and app.platform == "android":
                    findings.append(self.create_finding(
                        app=app,
                        title="Hermes Engine Not Enabled",
                        severity="info",
                        category="Build Configuration",
                        description="The app is not using the Hermes JavaScript engine. The JS bundle is in plain text format.",
                        impact="Plain JavaScript bundle is easier to analyze than Hermes bytecode. Code can be read directly without decompilation.",
                        remediation="Enable Hermes in android/app/build.gradle by setting enableHermes: true.",
                        file_path="assets/index.android.bundle",
                        code_snippet='// In android/app/build.gradle:\nproject.ext.react = [\n    enableHermes: true  // Enable this\n]',
                        poc_evidence="No libhermes.so found - using plain JS bundle",
                        poc_verification="1. Unzip APK\n2. Check for libhermes.so\n3. Check if bundle starts with Hermes magic bytes",
                        poc_commands=[
                            f"unzip -l {app.file_path} | grep hermes",
                            "xxd -l 8 /tmp/extracted/assets/index.android.bundle",
                        ],
                        owasp_masvs_category="MASVS-RESILIENCE",
                    ))

        except Exception as e:
            logger.error(f"RN config check failed: {e}")

        return findings
