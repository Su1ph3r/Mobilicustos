"""Logging and debug configuration analyzer for Android applications.

Evaluates the application's logging practices and debug configuration to
detect information leakage through system logs and active debug code in
production builds.

Security checks performed:
    - **Debuggable Flag**: Detects android:debuggable="true" in the
      AndroidManifest.xml which allows debugger attachment, memory
      inspection, and run-as access to the app's private data directory.
    - **Verbose/Debug Logging**: Counts Log.v, Log.d, System.out.println,
      and printStackTrace calls in source code; flags excessive logging
      (> 20 verbose/debug statements) as a data leakage risk.
    - **Sensitive Data in Logs**: Scans log statements for references to
      passwords, tokens, secrets, credentials, API keys, credit cards,
      and SSNs that could be exposed via logcat.
    - **Debug Flags**: Detects hardcoded debug flag constants set to
      true (DEBUG_MODE, ENABLE_LOGGING, isDebuggable) that may enable
      debug-only code paths in production.

OWASP references:
    - MASVS-CODE: Code Quality
    - MASVS-CODE-2: Debug Configuration
    - MASVS-STORAGE: Data Storage (log leakage)
    - MASTG-TEST-0039: Testing for Debugging Symbols
    - MASTG-TEST-0001: Testing Local Storage for Sensitive Data
    - CWE-489: Active Debug Code
    - CWE-532: Insertion of Sensitive Information into Log File
"""

import logging
import re
import shutil
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

# Android namespace
NS = {"android": "http://schemas.android.com/apk/res/android"}

# Android Log methods by severity
LOG_PATTERNS = {
    "verbose": [
        r'\bLog\.v\s*\(',
        r'\bLog\.VERBOSE\b',
        r'\blogger\.trace\s*\(',
    ],
    "debug": [
        r'\bLog\.d\s*\(',
        r'\bLog\.DEBUG\b',
        r'\blogger\.debug\s*\(',
    ],
    "info": [
        r'\bLog\.i\s*\(',
        r'\bLog\.INFO\b',
    ],
    "warning": [
        r'\bLog\.w\s*\(',
        r'\bLog\.WARN\b',
    ],
    "error": [
        r'\bLog\.e\s*\(',
        r'\bLog\.ERROR\b',
    ],
    "println": [
        r'System\.out\.println\s*\(',
        r'System\.err\.println\s*\(',
        r'printStackTrace\s*\(\s*\)',
    ],
}

# Sensitive data in log statements
SENSITIVE_LOG_PATTERNS = [
    r'Log\.\w\s*\([^)]*(?:password|passwd|pwd|token|secret|key|auth|credential|session|cookie)',
    r'Log\.\w\s*\([^)]*(?:credit.?card|ssn|social.?security|pin)',
    r'Log\.\w\s*\([^)]*(?:bearer|api.?key|apikey|access.?token)',
    r'println\s*\([^)]*(?:password|token|secret|key|auth|credential)',
]

# Debug flag patterns
DEBUG_FLAG_PATTERNS = [
    r'BuildConfig\.DEBUG',
    r'isDebuggable',
    r'DEBUG_MODE\s*=\s*true',
    r'ENABLE_LOGGING\s*=\s*true',
    r'\.setDebuggable\s*\(\s*true\s*\)',
]


class LoggingAnalyzer(BaseAnalyzer):
    """Analyzes logging and debug configuration for information leakage.

    Parses AndroidManifest.xml for debuggable flags, scans source code
    for verbose logging and sensitive data in log statements, and
    detects hardcoded debug flag constants.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform ("android").
    """

    name = "logging_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze logging and debug configuration for security issues.

        Args:
            app: The mobile application to analyze.

        Returns:
            A list of Finding objects covering debuggable flag, verbose
            logging, sensitive data in logs, and debug flags.
        """
        if not app.file_path:
            return []

        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="logging_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            findings = []

            # Check AndroidManifest for debuggable flag
            manifest_findings = await self._check_manifest_debuggable(extracted_path, app)
            findings.extend(manifest_findings)

            # Analyze log statements in source code
            log_findings = await self._analyze_log_statements(extracted_path, app)
            findings.extend(log_findings)

            # Check for sensitive data in logs
            sensitive_findings = await self._check_sensitive_logging(extracted_path, app)
            findings.extend(sensitive_findings)

            # Check for debug flags
            debug_findings = await self._check_debug_flags(extracted_path, app)
            findings.extend(debug_findings)

            return findings

        except Exception as e:
            logger.error(f"Logging analysis failed: {e}")
            return []
        finally:
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    async def _check_manifest_debuggable(self, extracted_path: Path, app: MobileApp) -> list[Finding]:
        """Check if android:debuggable is true in manifest.

        Args:
            extracted_path: Root directory of the extracted APK.
            app: The mobile application being analyzed.

        Returns:
            A list containing a high-severity Finding if debuggable
            is true, or an empty list otherwise.
        """
        findings = []

        manifest_xml = None
        manifest_path = extracted_path / "AndroidManifest.xml"

        if manifest_path.exists():
            try:
                manifest_xml = manifest_path.read_text(errors='ignore')
            except Exception:
                pass

        if not manifest_xml:
            try:
                from androguard.core.axml import AXMLPrinter
                with zipfile.ZipFile(app.file_path, "r") as apk:
                    manifest_data = apk.read("AndroidManifest.xml")
                    axml = AXMLPrinter(manifest_data)
                    manifest_xml = axml.get_xml()
            except Exception:
                pass

        if not manifest_xml:
            return findings

        try:
            root = ET.fromstring(manifest_xml)
        except ET.ParseError:
            return findings

        application = root.find("application")
        if application is not None:
            debuggable = application.get(f"{{{NS['android']}}}debuggable")
            if debuggable == "true":
                findings.append(self.create_finding(
                    app=app,
                    title="Application is Debuggable (android:debuggable=true)",
                    description=(
                        "The application has android:debuggable set to true in the manifest. "
                        "This flag should only be set in debug builds. In production, it allows "
                        "attackers to attach debuggers, inspect memory, and modify runtime behavior."
                    ),
                    severity="high",
                    category="Debug Configuration",
                    impact=(
                        "An attacker can: attach a debugger to inspect variables and memory, "
                        "modify application behavior at runtime, bypass security checks, "
                        "access the app's private data directory via run-as."
                    ),
                    remediation=(
                        "Remove android:debuggable=\"true\" from AndroidManifest.xml. "
                        "Use build variants to control debug settings:\n\n"
                        "  buildTypes {\n"
                        "      release {\n"
                        "          debuggable false\n"
                        "      }\n"
                        "  }"
                    ),
                    file_path="AndroidManifest.xml",
                    code_snippet='android:debuggable="true"',
                    cwe_id="CWE-489",
                    cwe_name="Active Debug Code",
                    cvss_score=7.2,
                    cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    owasp_masvs_category="MASVS-CODE",
                    owasp_masvs_control="MASVS-CODE-2",
                    owasp_mastg_test="MASTG-TEST-0039",
                    poc_commands=[
                        {
                            "type": "adb",
                            "command": "adb jdwp",
                            "description": "List debuggable processes",
                        },
                        {
                            "type": "adb",
                            "command": f"adb shell run-as {app.package_name} ls /data/data/{app.package_name}",
                            "description": "Access app's private directory (only works with debuggable)",
                        },
                    ],
                ))

        return findings

    async def _analyze_log_statements(self, extracted_path: Path, app: MobileApp) -> list[Finding]:
        """Analyze log statement volume and severity in source code.

        Counts occurrences of Log.v, Log.d, Log.i, Log.w, Log.e,
        System.out.println, and printStackTrace across all Java/Kotlin
        source files.

        Args:
            extracted_path: Root directory of the extracted APK.
            app: The mobile application being analyzed.

        Returns:
            A list containing a Finding if excessive verbose/debug
            logging is detected, or an info-level summary.
        """
        findings = []
        log_counts = {level: 0 for level in LOG_PATTERNS}
        log_files = set()

        for ext in [".java", ".kt"]:
            for source_file in extracted_path.rglob(f"*{ext}"):
                try:
                    content = source_file.read_text(errors='ignore')
                    rel_path = str(source_file.relative_to(extracted_path))

                    for level, patterns in LOG_PATTERNS.items():
                        for pattern in patterns:
                            count = len(re.findall(pattern, content))
                            if count > 0:
                                log_counts[level] += count
                                log_files.add(rel_path)

                except Exception:
                    pass

        total_logs = sum(log_counts.values())
        verbose_debug = log_counts["verbose"] + log_counts["debug"] + log_counts["println"]

        if verbose_debug > 20:
            level_summary = "\n".join(
                f"- {level.title()}: {count} statements"
                for level, count in log_counts.items()
                if count > 0
            )

            findings.append(self.create_finding(
                app=app,
                title=f"Excessive Verbose/Debug Logging ({verbose_debug} statements)",
                description=(
                    f"The application contains {verbose_debug} verbose/debug/println log statements "
                    f"across {len(log_files)} source files.\n\n"
                    f"**Log level breakdown:**\n{level_summary}\n\n"
                    "Verbose logging in production builds can leak sensitive information "
                    "through the system log (logcat), which is accessible to other apps "
                    "on older Android versions."
                ),
                severity="medium",
                category="Logging",
                impact=(
                    "Verbose logging can expose internal application state, user data, "
                    "API calls, and error details to other apps or ADB users. On Android < 4.1, "
                    "any app with READ_LOGS permission can access these logs."
                ),
                remediation=(
                    "1. Remove or disable verbose/debug logging in release builds\n"
                    "2. Use ProGuard/R8 to strip Log.d/Log.v calls:\n"
                    "   -assumenosideeffects class android.util.Log {\n"
                    "       public static int d(...);\n"
                    "       public static int v(...);\n"
                    "   }\n"
                    "3. Use Timber or similar library with configurable log levels\n"
                    "4. Wrap logging with BuildConfig.DEBUG checks"
                ),
                cwe_id="CWE-532",
                cwe_name="Insertion of Sensitive Information into Log File",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                owasp_masvs_category="MASVS-STORAGE",
                owasp_masvs_control="MASVS-CODE-2",
                owasp_mastg_test="MASTG-TEST-0001",
                poc_commands=[
                    {
                        "type": "adb",
                        "command": f"adb logcat | grep -i {app.package_name}",
                        "description": "Monitor application log output",
                    },
                    {
                        "type": "adb",
                        "command": "adb logcat -d | grep -iE 'password|token|key|secret'",
                        "description": "Search for sensitive data in logs",
                    },
                ],
                remediation_code={
                    "proguard": (
                        "# proguard-rules.pro - Strip debug logging in release\n"
                        "-assumenosideeffects class android.util.Log {\n"
                        "    public static int d(...);\n"
                        "    public static int v(...);\n"
                        "}"
                    ),
                    "kotlin": (
                        "// Use Timber with configurable levels\n"
                        "if (BuildConfig.DEBUG) {\n"
                        "    Timber.plant(Timber.DebugTree())\n"
                        "} else {\n"
                        "    Timber.plant(CrashReportingTree())\n"
                        "}"
                    ),
                },
            ))

        elif total_logs > 0:
            findings.append(self.create_finding(
                app=app,
                title=f"Logging Statements Present ({total_logs} total)",
                description=(
                    f"The application contains {total_logs} log statements. "
                    "Review to ensure no sensitive data is logged in production."
                ),
                severity="info",
                category="Logging",
                impact="Moderate logging levels are generally acceptable if no sensitive data is included.",
                remediation="Ensure sensitive data is never logged and consider stripping debug logs in release.",
                owasp_masvs_category="MASVS-STORAGE",
                owasp_masvs_control="MASVS-CODE-2",
            ))

        return findings

    async def _check_sensitive_logging(self, extracted_path: Path, app: MobileApp) -> list[Finding]:
        """Check for sensitive data references in log statements.

        Scans for log calls containing keywords like password, token,
        secret, credential, api_key, bearer, credit_card, and SSN.

        Args:
            extracted_path: Root directory of the extracted APK.
            app: The mobile application being analyzed.

        Returns:
            A list containing a high-severity Finding if sensitive
            data patterns are found in log statements.
        """
        findings = []
        sensitive_logs = []

        for ext in [".java", ".kt"]:
            for source_file in extracted_path.rglob(f"*{ext}"):
                try:
                    content = source_file.read_text(errors='ignore')
                    rel_path = str(source_file.relative_to(extracted_path))

                    for pattern in SENSITIVE_LOG_PATTERNS:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            line_num = content[:match.start()].count('\n') + 1
                            lines = content.split('\n')
                            snippet = lines[max(0, line_num - 1):min(len(lines), line_num + 1)]
                            sensitive_logs.append({
                                "file": rel_path,
                                "line": line_num,
                                "snippet": "\n".join(snippet),
                            })

                except Exception:
                    pass

        if sensitive_logs:
            location_list = "\n".join(
                f"- {l['file']}:{l['line']}"
                for l in sensitive_logs[:15]
            )

            findings.append(self.create_finding(
                app=app,
                title=f"Sensitive Data in Log Statements ({len(sensitive_logs)} instances)",
                description=(
                    "Log statements appear to contain sensitive data such as passwords, "
                    "tokens, or credentials:\n\n"
                    f"{location_list}"
                ),
                severity="high",
                category="Logging",
                impact=(
                    "Sensitive data written to system logs can be read by other applications, "
                    "captured via ADB, or included in bug reports, leading to credential theft."
                ),
                remediation=(
                    "1. Never log sensitive data (passwords, tokens, keys)\n"
                    "2. If debugging is needed, redact sensitive values before logging\n"
                    "3. Use ProGuard rules to strip log statements in release builds"
                ),
                file_path=sensitive_logs[0]["file"],
                line_number=sensitive_logs[0]["line"],
                code_snippet=sensitive_logs[0]["snippet"],
                cwe_id="CWE-532",
                cwe_name="Insertion of Sensitive Information into Log File",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                owasp_masvs_category="MASVS-STORAGE",
                owasp_masvs_control="MASVS-CODE-2",
                owasp_mastg_test="MASTG-TEST-0001",
            ))

        return findings

    async def _check_debug_flags(self, extracted_path: Path, app: MobileApp) -> list[Finding]:
        """Check for hardcoded debug flags enabled in source code.

        Detects BuildConfig.DEBUG, isDebuggable, DEBUG_MODE=true,
        ENABLE_LOGGING=true, and setDebuggable(true) patterns.

        Args:
            extracted_path: Root directory of the extracted APK.
            app: The mobile application being analyzed.

        Returns:
            A list containing a medium-severity Finding if debug
            flags set to true are detected.
        """
        findings = []
        debug_flags = []

        for ext in [".java", ".kt"]:
            for source_file in extracted_path.rglob(f"*{ext}"):
                try:
                    content = source_file.read_text(errors='ignore')
                    rel_path = str(source_file.relative_to(extracted_path))

                    for pattern in DEBUG_FLAG_PATTERNS:
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count('\n') + 1
                            # Check context -- is it a hardcoded true?
                            line = content.split('\n')[line_num - 1]
                            if '= true' in line.lower() or '=true' in line.lower():
                                debug_flags.append({
                                    "file": rel_path,
                                    "line": line_num,
                                    "flag": match.group(0),
                                    "line_content": line.strip(),
                                })

                except Exception:
                    pass

        if debug_flags:
            flag_list = "\n".join(
                f"- {f['file']}:{f['line']} -- {f['line_content']}"
                for f in debug_flags[:10]
            )

            findings.append(self.create_finding(
                app=app,
                title=f"Debug Flags Enabled in Code ({len(debug_flags)} instances)",
                description=(
                    "Debug flags or debug-mode constants are set to true in the source code:\n\n"
                    f"{flag_list}\n\n"
                    "These flags may enable additional logging, bypass security checks, "
                    "or expose debug functionality in production."
                ),
                severity="medium",
                category="Debug Configuration",
                impact=(
                    "Debug flags may disable security controls, enable verbose logging, "
                    "or expose test/admin functionality to end users."
                ),
                remediation=(
                    "1. Use BuildConfig.DEBUG instead of hardcoded flags\n"
                    "2. Ensure debug-only code paths are properly gated\n"
                    "3. Use build variants to control debug behavior"
                ),
                file_path=debug_flags[0]["file"],
                line_number=debug_flags[0]["line"],
                cwe_id="CWE-489",
                cwe_name="Active Debug Code",
                cvss_score=5.3,
                owasp_masvs_category="MASVS-CODE",
                owasp_masvs_control="MASVS-CODE-2",
            ))

        return findings
