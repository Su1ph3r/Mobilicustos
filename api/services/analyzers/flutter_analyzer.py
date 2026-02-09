"""Flutter/Dart analyzer for AOT-compiled mobile applications.

Performs specialized analysis of Flutter applications by extracting the
compiled Dart binary (libapp.so for Android, App.framework/App for iOS)
and running Blutter decompilation via Docker container to recover class
names, function signatures, and embedded strings.

Analysis pipeline:
    1. **Binary Extraction**: Locates and extracts libapp.so (preferring
       arm64-v8a) or App.framework/App from the application archive.
    2. **Blutter Decompilation**: Runs Blutter on the extracted binary
       via a Docker sibling container to produce function/class lists
       and string tables.
    3. **Security Analysis**: Scans Blutter output for sensitive function
       names (password, encrypt, auth, token, biometric) and embedded
       secrets (base64 strings, API URLs, Firebase URLs).
    4. **Configuration Checks**: Detects Flutter debug/profile builds
       (vm_snapshot_data presence) and reviews flutter_assets content.

Note:
    Flutter apps use Dart/native networking and crypto, so standard
    Java-level Frida hooks will not trigger. This analyzer works at the
    Dart AOT binary level instead.

OWASP references:
    - MASVS-CODE: Code Quality
    - MASVS-STORAGE: Data Storage (secrets in binary)
    - MASVS-RESILIENCE: Resiliency Against Reverse Engineering
"""

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
    """Analyzes Flutter applications using Blutter AOT decompilation.

    Extracts the compiled Dart binary, runs Blutter via Docker, and
    scans the output for sensitive functions, embedded secrets, and
    build configuration issues.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform ("cross-platform").
        docker: DockerExecutor instance for running Blutter containers.
    """

    name = "flutter_analyzer"
    platform = "cross-platform"

    def __init__(self):
        self.docker = DockerExecutor()

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze a Flutter application for security issues.

        Skips non-Flutter apps. Extracts the Dart binary, runs Blutter,
        analyzes the output, and checks Flutter-specific configuration.

        Args:
            app: The mobile application to analyze. Must have
                framework="flutter" for Blutter analysis to proceed.

        Returns:
            A list of Finding objects from Blutter analysis and
            Flutter configuration checks.
        """
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

            # Dart-specific SAST patterns + pub.dev deps share a single extraction
            import shutil
            import tempfile

            shared_extract = Path(tempfile.mkdtemp(prefix="flutter_shared_"))
            try:
                with zipfile.ZipFile(app.file_path, "r") as archive:
                    archive.extractall(shared_extract)

                findings.extend(await self._check_dart_patterns(app, shared_extract))
                findings.extend(await self._scan_pubdev_deps(app, shared_extract))
            finally:
                if shared_extract.exists():
                    shutil.rmtree(shared_extract, ignore_errors=True)

        except Exception as e:
            logger.error(f"Flutter analysis failed: {e}")

        return findings

    async def _extract_libapp(
        self,
        archive_path: Path,
        platform: str,
    ) -> Path | None:
        """Extract the compiled Dart binary from the application archive.

        For Android, extracts libapp.so (preferring arm64-v8a architecture).
        For iOS, extracts App.framework/App from the Payload directory.
        Files are extracted to the shared ANALYZER_TEMP_PATH for access
        by Docker sibling containers.

        Args:
            archive_path: Path to the APK or IPA archive file.
            platform: Either "android" or "ios".

        Returns:
            Path to the extracted binary, or None if not found.
        """
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
        """Run Blutter decompiler on the extracted Dart binary.

        Executes the Blutter Docker tool with the binary as input and
        parses the output directory for recovered information.

        Args:
            libapp_path: Path to the extracted libapp.so or App binary.

        Returns:
            A dict with 'classes', 'functions', and 'strings' lists
            from the Blutter output, or None if execution failed.
        """
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
        """Parse Blutter output files into structured data.

        Reads pp.txt for class and function names, and strings.txt
        for extracted string literals.

        Args:
            output_dir: Directory containing Blutter output files.

        Returns:
            A dict with 'classes', 'functions', and 'strings' lists.
        """
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
        """Analyze Blutter output for security-relevant patterns.

        Scans function names for sensitive operations (password, encrypt,
        auth, token, biometric) and string literals for embedded secrets
        (base64 encoded values, API endpoints, Firebase URLs).

        Args:
            app: The mobile application being analyzed.
            output: Parsed Blutter output dict with 'functions' and
                'strings' lists.

        Returns:
            A list of Finding objects for sensitive functions and strings.
        """
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
        """Check Flutter-specific build configuration issues.

        Detects debug/profile builds (vm_snapshot_data presence) and
        reviews flutter_assets content for potential configuration
        or data exposure.

        Args:
            app: The mobile application being analyzed.

        Returns:
            A list of Finding objects for Flutter configuration issues.
        """
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

    async def _check_dart_patterns(self, app: MobileApp, extracted_path: Path) -> list[Finding]:
        """Check for Dart-specific security anti-patterns in decompiled output.

        Scans extracted text/source for insecure Dart patterns:
            - SharedPreferences without encryption
            - http.Client without TLS
            - dart:developer imports in release
            - Debug mode indicators

        Args:
            app: The mobile application being analyzed.
            extracted_path: Pre-extracted archive directory.
        """
        findings: list[Finding] = []
        import re

        try:
            # Scan all text-like files for Dart patterns
            dart_patterns = [
                {
                    "pattern": r"SharedPreferences\b",
                    "negative": r"flutter_secure_storage|encrypted_shared_preferences",
                    "title": "SharedPreferences used without encryption",
                    "severity": "medium",
                    "desc": "App uses SharedPreferences (plaintext on disk) without flutter_secure_storage.",
                    "owasp": "MASVS-STORAGE",
                    "cwe": "CWE-922",
                },
                {
                    "pattern": r"http\.Client\(\)|HttpClient\(\)",
                    "negative": r"https://",
                    "title": "HTTP client without enforced TLS",
                    "severity": "medium",
                    "desc": "App creates HTTP client instances. Verify all connections use HTTPS.",
                    "owasp": "MASVS-NETWORK",
                    "cwe": "CWE-319",
                },
                {
                    "pattern": r"dart:developer",
                    "negative": None,
                    "title": "dart:developer import detected",
                    "severity": "low",
                    "desc": "The dart:developer library is imported, which provides debugging tools. Should be removed in release builds.",
                    "owasp": "MASVS-CODE",
                    "cwe": "CWE-489",
                },
                {
                    "pattern": r"kDebugMode\s*==?\s*true|kDebugMode\)",
                    "negative": None,
                    "title": "Debug mode check detected",
                    "severity": "info",
                    "desc": "App checks kDebugMode — verify debug-only code paths are not reachable in release.",
                    "owasp": "MASVS-CODE",
                    "cwe": None,
                },
                {
                    "pattern": r"print\(|debugPrint\(",
                    "negative": None,
                    "title": "Debug print statements detected",
                    "severity": "low",
                    "desc": "Debug print statements may leak sensitive data to the device console in release builds.",
                    "owasp": "MASVS-STORAGE",
                    "cwe": "CWE-532",
                },
            ]

            scannable_ext = {".dart", ".js", ".json", ".yaml", ".txt"}
            seen_titles: set[str] = set()

            for fpath in extracted_path.rglob("*"):
                if fpath.suffix.lower() not in scannable_ext:
                    continue
                if fpath.stat().st_size > 5 * 1024 * 1024:
                    continue

                try:
                    content = fpath.read_text(errors="ignore")
                except Exception:
                    continue

                for pat in dart_patterns:
                    if pat["title"] in seen_titles:
                        continue
                    if re.search(pat["pattern"], content):
                        # Check negative pattern (if present, skip — it means the secure alternative is used)
                        if pat["negative"] and re.search(pat["negative"], content):
                            continue
                        seen_titles.add(pat["title"])
                        findings.append(self.create_finding(
                            app=app,
                            title=pat["title"],
                            severity=pat["severity"],
                            category="Dart Security",
                            description=pat["desc"],
                            impact="Insecure Dart patterns can lead to data leakage or runtime security issues.",
                            remediation="Use flutter_secure_storage instead of SharedPreferences for sensitive data. Enforce HTTPS. Remove debug imports.",
                            file_path=str(fpath.relative_to(extracted_path)),
                            owasp_masvs_category=pat["owasp"],
                            cwe_id=pat.get("cwe"),
                        ))

        except Exception as e:
            logger.error(f"Dart pattern check failed: {e}")

        return findings

    async def _scan_pubdev_deps(self, app: MobileApp, extracted_path: Path) -> list[Finding]:
        """Scan pub.dev dependencies from pubspec.lock for known vulnerabilities.

        Checks each dependency against the OSV advisory database for known CVEs.

        Args:
            app: The mobile application being analyzed.
            extracted_path: Pre-extracted archive directory.
        """
        findings: list[Finding] = []

        try:
            # Find pubspec.lock
            pubspec_lock = None
            for candidate in extracted_path.rglob("pubspec.lock"):
                pubspec_lock = candidate
                break

            if not pubspec_lock:
                return findings

            content = pubspec_lock.read_text(errors="ignore")

            # Parse packages from pubspec.lock
            packages: list[tuple[str, str]] = []
            current_pkg = None
            for line in content.split("\n"):
                if line.startswith("  ") and ":" in line and not line.startswith("    "):
                    current_pkg = line.strip().rstrip(":")
                elif "version:" in line and current_pkg:
                    version = line.split("version:")[1].strip().strip("'\"")
                    packages.append((current_pkg, version))
                    current_pkg = None

            if not packages:
                return findings

            logger.info(f"Checking {len(packages)} pub.dev dependencies for vulnerabilities")

            # Check each package against OSV
            import httpx

            vulnerable_pkgs: list[tuple[str, str, list[dict]]] = []
            async with httpx.AsyncClient(timeout=10) as client:
                for pkg_name, pkg_version in packages[:50]:  # Limit to avoid rate limits
                    try:
                        resp = await client.post(
                            "https://api.osv.dev/v1/query",
                            json={
                                "package": {"name": pkg_name, "ecosystem": "Pub"},
                                "version": pkg_version,
                            },
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            vulns = data.get("vulns", [])
                            if vulns:
                                vulnerable_pkgs.append((pkg_name, pkg_version, vulns))
                    except Exception as e:
                        logger.warning(f"OSV vulnerability check failed for {pkg_name} {pkg_version}: {e}")

            for pkg_name, pkg_version, vulns in vulnerable_pkgs:
                vuln_ids = [v.get("id", "?") for v in vulns[:5]]
                summaries = [v.get("summary", "") for v in vulns[:3]]
                findings.append(self.create_finding(
                    app=app,
                    title=f"Vulnerable pub.dev dependency: {pkg_name} {pkg_version}",
                    severity="high" if len(vulns) > 1 else "medium",
                    category="Vulnerable Dependencies",
                    description=(
                        f"The Flutter dependency '{pkg_name}' version {pkg_version} has "
                        f"{len(vulns)} known vulnerabilities:\n"
                        + "\n".join(f"- {vid}: {summ}" for vid, summ in zip(vuln_ids, summaries))
                    ),
                    impact=f"Using vulnerable dependencies exposes the app to known exploits ({len(vulns)} CVEs).",
                    remediation=f"Update {pkg_name} to the latest version. Run: flutter pub upgrade {pkg_name}",
                    file_path="pubspec.lock",
                    poc_evidence=f"Advisory IDs: {', '.join(vuln_ids)}",
                    cwe_id="CWE-1395",
                    owasp_masvs_category="MASVS-CODE",
                ))

        except Exception as e:
            logger.error(f"Pub.dev dependency scan failed: {e}")

        return findings
