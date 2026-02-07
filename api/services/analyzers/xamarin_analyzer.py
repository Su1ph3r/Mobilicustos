"""Xamarin/MAUI cross-platform security analyzer.

Analyzes Xamarin and .NET MAUI mobile applications for security issues
including assembly inspection, Mono runtime configuration, .NET security
patterns, and NuGet dependency vulnerabilities.
"""

import json
import logging
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class XamarinAnalyzer(BaseAnalyzer):
    """Security analyzer for Xamarin and .NET MAUI applications."""

    name = "xamarin_analyzer"
    platform = "cross-platform"

    # Paths where Xamarin/MAUI assemblies are typically found
    ASSEMBLY_PATHS = [
        "assemblies/",
        "Frameworks/Xamarin.iOS.dll",
        "lib/",
    ]

    # MAUI-specific assembly markers
    MAUI_MARKERS = [
        "Microsoft.Maui.dll",
        "Microsoft.Maui.Controls.dll",
        "Microsoft.Maui.Essentials.dll",
    ]

    # Xamarin-specific assembly markers
    XAMARIN_MARKERS = [
        "Xamarin.Forms.dll",
        "Xamarin.Forms.Core.dll",
        "Xamarin.Essentials.dll",
        "Mono.Android.dll",
        "Xamarin.iOS.dll",
    ]

    # Dangerous .NET patterns to scan for in assemblies
    INSECURE_PATTERNS = {
        "hardcoded_connection_string": {
            "patterns": [
                rb"Server\s*=\s*[^;]+;\s*Database\s*=",
                rb"Data Source\s*=\s*[^;]+;\s*Initial Catalog",
                rb"mongodb://[^\s\"']+",
                rb"postgres://[^\s\"']+",
            ],
            "title": "Hardcoded Connection String",
            "severity": "high",
            "description": "Database connection string found embedded in assembly. Attackers can extract credentials by decompiling the application.",
            "cwe_id": "CWE-798",
        },
        "ssl_validation_bypass": {
            "patterns": [
                rb"ServerCertificateValidationCallback",
                rb"ServicePointManager\.ServerCertificateValidationCallback\s*=",
                rb"return\s+true;\s*//.*certificate",
                rb"ServerCertificateCustomValidationCallback",
            ],
            "title": "SSL Certificate Validation Bypass",
            "severity": "critical",
            "description": "SSL/TLS certificate validation appears to be bypassed. This allows man-in-the-middle attacks.",
            "cwe_id": "CWE-295",
        },
        "insecure_storage": {
            "patterns": [
                rb"Preferences\.Set\(",
                rb"Application\.Current\.Properties\[",
                rb"NSUserDefaults",
            ],
            "title": "Insecure Data Storage via Preferences",
            "severity": "medium",
            "description": "Sensitive data may be stored in platform preferences instead of SecureStorage. Preferences are not encrypted on all platforms.",
            "cwe_id": "CWE-922",
        },
        "debug_attributes": {
            "patterns": [
                rb"\[Debuggable\(",
                rb"DebuggableAttribute",
                rb"\[assembly:\s*Debuggable\(true",
            ],
            "title": "Debug Attributes Enabled",
            "severity": "medium",
            "description": "Assembly contains debug attributes that allow attaching debuggers and inspecting memory in production builds.",
            "cwe_id": "CWE-489",
        },
        "embedded_secrets": {
            "patterns": [
                rb"['\"]AIza[0-9A-Za-z_-]{35}['\"]",
                rb"['\"]sk_live_[0-9A-Za-z]{24,}['\"]",
                rb"['\"]AKIA[0-9A-Z]{16}['\"]",
                rb"api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_-]{20,}['\"]",
            ],
            "title": "Embedded API Key or Secret",
            "severity": "high",
            "description": "API key or secret found embedded in assembly. These can be extracted by decompiling the application.",
            "cwe_id": "CWE-798",
        },
        "http_client_insecure": {
            "patterns": [
                rb"http://[^\s\"']+/api",
                rb"new\s+HttpClient\(\)\s*{[^}]*BaseAddress\s*=\s*new\s+Uri\s*\(\s*\"http://",
            ],
            "title": "Insecure HTTP API Communication",
            "severity": "medium",
            "description": "HTTP (not HTTPS) is used for API communication. Data is transmitted in cleartext.",
            "cwe_id": "CWE-319",
        },
    }

    # Known vulnerable NuGet packages (name -> min safe version)
    KNOWN_VULNERABLE_PACKAGES = {
        "Newtonsoft.Json": {"safe": "13.0.1", "cve": "CVE-2024-21907"},
        "System.Text.Json": {"safe": "8.0.1", "cve": "CVE-2024-21319"},
        "Microsoft.Data.SqlClient": {"safe": "5.1.4", "cve": "CVE-2024-0056"},
        "BouncyCastle": {"safe": "2.3.0", "cve": "CVE-2023-33201"},
        "log4net": {"safe": "2.0.16", "cve": "CVE-2018-1285"},
    }

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze a Xamarin/MAUI application for security issues."""
        findings: list[Finding] = []

        if not app.file_path or not os.path.exists(app.file_path):
            return findings

        tmp_dir = tempfile.mkdtemp(prefix="xamarin_")
        try:
            # Extract archive (with Zip Slip protection)
            try:
                with zipfile.ZipFile(app.file_path, "r") as zf:
                    for member in zf.infolist():
                        target = Path(tmp_dir).joinpath(member.filename).resolve()
                        if not target.is_relative_to(tmp_dir):
                            logger.warning(f"Skipping path traversal entry: {member.filename}")
                            continue
                        zf.extract(member, tmp_dir)
            except (zipfile.BadZipFile, Exception) as e:
                logger.warning(f"Failed to extract archive: {e}")
                return findings

            extracted = Path(tmp_dir)

            # Stage 1: Detect Xamarin/MAUI and extract assemblies
            assemblies = self._find_assemblies(extracted)
            if not assemblies:
                return findings

            framework = self._detect_framework(assemblies)

            # Stage 2: Mono runtime checks
            findings.extend(self._check_mono_runtime(app, extracted, assemblies))

            # Stage 3: .NET configuration analysis
            findings.extend(self._check_dotnet_config(app, extracted))

            # Stage 4: Security pattern scanning
            findings.extend(self._scan_security_patterns(app, extracted, assemblies))

            # Stage 5: NuGet dependency analysis
            findings.extend(self._check_nuget_dependencies(app, extracted))

            # Add framework detection info finding
            if findings or assemblies:
                findings.append(self.create_finding(
                    app=app,
                    title=f"{framework} Application Detected",
                    description=(
                        f"This application is built with {framework}. "
                        f"Found {len(assemblies)} .NET assemblies."
                    ),
                    severity="info",
                    impact="Framework identification aids targeted security analysis.",
                    remediation="No action required. This is an informational finding.",
                    category="Framework Detection",
                ))

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return findings

    def _find_assemblies(self, extracted: Path) -> list[Path]:
        """Find .NET assemblies in the extracted archive."""
        assemblies: list[Path] = []
        for dll in extracted.rglob("*.dll"):
            assemblies.append(dll)
        return assemblies

    def _detect_framework(self, assemblies: list[Path]) -> str:
        """Detect whether the app uses Xamarin.Forms or .NET MAUI."""
        names = {a.name for a in assemblies}
        if any(m in names for m in self.MAUI_MARKERS):
            return ".NET MAUI"
        if any(m in names for m in self.XAMARIN_MARKERS):
            return "Xamarin.Forms"
        return "Xamarin/MAUI"

    def _check_mono_runtime(
        self, app: MobileApp, extracted: Path, assemblies: list[Path]
    ) -> list[Finding]:
        """Check Mono runtime configuration for security issues."""
        findings: list[Finding] = []

        # Check for debug symbols (.pdb files)
        pdb_files = list(extracted.rglob("*.pdb"))
        if pdb_files:
            findings.append(self.create_finding(
                app=app,
                title="Debug Symbols Included in Release",
                description=(
                    f"Found {len(pdb_files)} .pdb debug symbol files in the application "
                    f"package. Debug symbols help attackers understand code structure."
                ),
                severity="medium",
                impact="Debug symbols expose class names, method names, and source file paths, easing reverse engineering.",
                remediation="Remove .pdb files from release builds. In .csproj, set DebugType to 'none' for Release configuration.",
                category="Build Configuration",
                cwe_id="CWE-489",
                owasp_masvs_category="MASVS-RESILIENCE",
                file_path=str(pdb_files[0].relative_to(extracted)),
            ))

        # Check for Mono debugger agent configuration
        for f in extracted.rglob("*"):
            if f.is_file() and f.suffix in (".config", ".xml"):
                try:
                    content = f.read_text(errors="ignore")
                    if "debugger-agent" in content.lower() or "mono-debug" in content.lower():
                        findings.append(self.create_finding(
                            app=app,
                            title="Mono Debugger Agent Configuration Found",
                            description="Mono debugger agent configuration detected, allowing remote debugging.",
                            severity="high",
                            impact="Attackers can attach a debugger to inspect memory, modify variables, and bypass security checks.",
                            remediation="Remove debugger agent configuration from release builds.",
                            category="Build Configuration",
                            cwe_id="CWE-489",
                            file_path=str(f.relative_to(extracted)),
                        ))
                        break
                except Exception:
                    pass

        return findings

    def _check_dotnet_config(self, app: MobileApp, extracted: Path) -> list[Finding]:
        """Check .NET configuration files for security issues."""
        findings: list[Finding] = []

        config_files = list(extracted.rglob("*.config")) + list(extracted.rglob("appsettings*.json"))

        for config_file in config_files:
            try:
                content = config_file.read_text(errors="ignore")
            except Exception:
                continue

            rel_path = str(config_file.relative_to(extracted))

            # Check for connection strings
            if re.search(r"connectionString|Data Source|Server=", content, re.IGNORECASE):
                findings.append(self.create_finding(
                    app=app,
                    title="Connection String in Configuration File",
                    description="Database connection string found in a configuration file bundled with the app.",
                    severity="high",
                    impact="Database credentials are exposed and can be extracted by decompiling the application.",
                    remediation="Move connection strings to a secure backend service. Do not embed database credentials in mobile apps.",
                    category="Insecure Configuration",
                    cwe_id="CWE-798",
                    file_path=rel_path,
                ))

            # Check for HTTP endpoints
            http_urls = re.findall(r'http://[^\s"\'<>]+', content)
            if http_urls:
                findings.append(self.create_finding(
                    app=app,
                    title="HTTP Endpoints in Configuration",
                    description=f"Found {len(http_urls)} HTTP (non-HTTPS) endpoint(s) in configuration.",
                    severity="medium",
                    impact="Data transmitted over HTTP is vulnerable to interception.",
                    remediation="Use HTTPS for all API endpoints.",
                    category="Network Security",
                    cwe_id="CWE-319",
                    file_path=rel_path,
                ))

        return findings

    def _scan_security_patterns(
        self, app: MobileApp, extracted: Path, assemblies: list[Path]
    ) -> list[Finding]:
        """Scan assemblies and source files for insecure patterns."""
        findings: list[Finding] = []

        # Scan all assemblies and source files
        scan_files = list(assemblies)
        scan_files.extend(extracted.rglob("*.cs"))
        scan_files.extend(extracted.rglob("*.xaml"))

        for scan_file in scan_files:
            try:
                content = scan_file.read_bytes()
            except Exception:
                continue

            rel_path = str(scan_file.relative_to(extracted))

            for check_name, check_info in self.INSECURE_PATTERNS.items():
                for pattern in check_info["patterns"]:
                    match = re.search(pattern, content)
                    if match:
                        snippet = content[max(0, match.start() - 20):match.end() + 20]
                        try:
                            snippet_text = snippet.decode("utf-8", errors="replace")
                        except Exception:
                            snippet_text = repr(snippet)

                        findings.append(self.create_finding(
                            app=app,
                            title=check_info["title"],
                            description=check_info["description"],
                            severity=check_info["severity"],
                            impact=f"This issue was found in {rel_path}.",
                            remediation=self._get_remediation(check_name),
                            category="Xamarin Security",
                            cwe_id=check_info.get("cwe_id"),
                            file_path=rel_path,
                            code_snippet=snippet_text[:500],
                        ))
                        break  # One finding per pattern type per file

        return findings

    def _check_nuget_dependencies(self, app: MobileApp, extracted: Path) -> list[Finding]:
        """Check NuGet dependencies for known vulnerabilities."""
        findings: list[Finding] = []

        # Parse packages.config
        for pkg_config in extracted.rglob("packages.config"):
            findings.extend(self._parse_packages_config(app, pkg_config, extracted))

        # Parse *.deps.json
        for deps_json in extracted.rglob("*.deps.json"):
            findings.extend(self._parse_deps_json(app, deps_json, extracted))

        return findings

    def _parse_packages_config(
        self, app: MobileApp, pkg_file: Path, extracted: Path
    ) -> list[Finding]:
        """Parse packages.config for vulnerable packages."""
        findings: list[Finding] = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(pkg_file)
            for pkg in tree.findall(".//package"):
                name = pkg.get("id", "")
                version = pkg.get("version", "")
                vuln = self._check_package_vulnerability(name, version)
                if vuln:
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Vulnerable NuGet Package: {name} {version}",
                        description=f"{name} version {version} has known vulnerability {vuln['cve']}.",
                        severity="high",
                        impact=f"Using {name} {version} exposes the app to {vuln['cve']}.",
                        remediation=f"Update {name} to version {vuln['safe']} or later.",
                        category="Dependency Vulnerability",
                        cwe_id="CWE-1395",
                        file_path=str(pkg_file.relative_to(extracted)),
                    ))
        except Exception as e:
            logger.debug(f"Failed to parse packages.config: {e}")
        return findings

    def _parse_deps_json(
        self, app: MobileApp, deps_file: Path, extracted: Path
    ) -> list[Finding]:
        """Parse .deps.json for vulnerable dependencies."""
        findings: list[Finding] = []
        try:
            data = json.loads(deps_file.read_text(errors="ignore"))
            libraries = data.get("libraries", {})
            for lib_key, lib_info in libraries.items():
                parts = lib_key.rsplit("/", 1)
                if len(parts) == 2:
                    name, version = parts
                    vuln = self._check_package_vulnerability(name, version)
                    if vuln:
                        findings.append(self.create_finding(
                            app=app,
                            title=f"Vulnerable NuGet Package: {name} {version}",
                            description=f"{name} version {version} has known vulnerability {vuln['cve']}.",
                            severity="high",
                            impact=f"Using {name} {version} exposes the app to {vuln['cve']}.",
                            remediation=f"Update {name} to version {vuln['safe']} or later.",
                            category="Dependency Vulnerability",
                            cwe_id="CWE-1395",
                            file_path=str(deps_file.relative_to(extracted)),
                        ))
        except Exception as e:
            logger.debug(f"Failed to parse deps.json: {e}")
        return findings

    def _check_package_vulnerability(self, name: str, version: str) -> dict | None:
        """Check if a package version is known to be vulnerable."""
        vuln_info = self.KNOWN_VULNERABLE_PACKAGES.get(name)
        if not vuln_info:
            return None
        try:
            from packaging.version import Version
            if Version(version) < Version(vuln_info["safe"]):
                return vuln_info
        except Exception:
            # If we can't parse version, do a simple string comparison
            if version < vuln_info["safe"]:
                return vuln_info
        return None

    def _get_remediation(self, check_name: str) -> str:
        """Get remediation advice for a specific check."""
        remediations = {
            "hardcoded_connection_string": (
                "Move database credentials to a secure backend service. "
                "Use token-based authentication for mobile-to-server communication."
            ),
            "ssl_validation_bypass": (
                "Remove custom certificate validation callbacks. "
                "Use platform-provided certificate validation with proper pinning."
            ),
            "insecure_storage": (
                "Use Xamarin.Essentials SecureStorage or MAUI SecureStorage "
                "instead of Preferences for sensitive data."
            ),
            "debug_attributes": (
                "Ensure release builds use Release configuration with "
                "debugging disabled. Check .csproj DebugType settings."
            ),
            "embedded_secrets": (
                "Move API keys to a backend service. Use environment-specific "
                "configuration that is not compiled into the app binary."
            ),
            "http_client_insecure": (
                "Use HTTPS for all API communication. Configure App Transport "
                "Security on iOS and Network Security Config on Android."
            ),
        }
        return remediations.get(check_name, "Review and fix the identified security issue.")
