"""DEX analyzer for Android bytecode analysis."""

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class DexAnalyzer(BaseAnalyzer):
    """Analyzes Android DEX bytecode for security issues."""

    name = "dex_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze DEX files in the APK."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            # androguard 4.x uses different import paths
            from androguard.core.apk import APK
            from androguard.core.dex import DEX
            from androguard.core.analysis.analysis import Analysis

            apk = APK(app.file_path)

            for dex_name in apk.get_all_dex():
                dex_data = apk.get_file(dex_name)
                dvm = DEX(dex_data)
                analysis = Analysis(dvm)
                analysis.create_xref()

                findings.extend(await self._check_crypto_issues(app, dvm, analysis))
                findings.extend(await self._check_logging(app, dvm, analysis))
                findings.extend(await self._check_webview_issues(app, dvm, analysis))
                findings.extend(await self._check_sql_issues(app, dvm, analysis))
                findings.extend(await self._check_file_operations(app, dvm, analysis))

        except ImportError as e:
            logger.warning(f"androguard not installed, using fallback analysis: {e}")
            findings.extend(await self._fallback_analysis(app))
        except Exception as e:
            logger.error(f"DEX analysis failed: {e}")
            findings.extend(await self._fallback_analysis(app))

        return findings

    async def _check_crypto_issues(
        self,
        app: MobileApp,
        dvm: Any,
        analysis: Any,
    ) -> list[Finding]:
        """Check for cryptographic issues."""
        findings: list[Finding] = []

        weak_algorithms = {
            "DES": "DES is obsolete and can be broken.",
            "DESede": "Triple DES is deprecated, use AES.",
            "RC4": "RC4 has known vulnerabilities.",
            "MD5": "MD5 is cryptographically broken.",
            "SHA1": "SHA1 is deprecated for security purposes.",
            "ECB": "ECB mode leaks patterns in encrypted data.",
        }

        for method in dvm.get_methods():
            code = method.get_code()
            if not code:
                continue

            instructions = code.get_bc().get_instructions()
            for inst in instructions:
                if inst.get_name() == "const-string":
                    string_value = inst.get_output().split(",")[-1].strip().strip('"')

                    for algo, issue in weak_algorithms.items():
                        if algo in string_value:
                            class_path = method.get_class_name().replace(".", "/") + ".java"
                            method_name = method.get_name()
                            findings.append(self.create_finding(
                                app=app,
                                title=f"Weak Cryptographic Algorithm: {algo}",
                                severity="high" if algo in ("DES", "RC4", "ECB") else "medium",
                                category="Cryptography",
                                description=f"{issue}\n\nFound in: {method.get_class_name()}.{method_name}()",
                                impact="Weak cryptography can be broken to expose sensitive data.",
                                remediation="Use AES-256 for symmetric encryption, SHA-256+ for hashing.",
                                file_path=class_path,
                                code_snippet=f'// {method.get_class_name()}.{method_name}()\nCipher.getInstance("{algo}");',
                                poc_evidence=f"Weak algorithm {algo} found in {method.get_class_name()}.{method_name}()",
                                poc_verification=f"1. Decompile APK: jadx -d output app.apk\n2. Open: output/{class_path}\n3. Search for: {algo}",
                                poc_commands=[
                                    f"jadx -d /tmp/out {app.file_path}",
                                    f"grep -rn '{algo}' /tmp/out/",
                                ],
                                cwe_id="CWE-327",
                                owasp_masvs_category="MASVS-CRYPTO",
                            ))

        return findings

    async def _check_logging(
        self,
        app: MobileApp,
        dvm: Any,
        analysis: Any,
    ) -> list[Finding]:
        """Check for sensitive data in logs."""
        findings: list[Finding] = []

        log_methods = ["Log;->v", "Log;->d", "Log;->i", "Log;->w", "Log;->e"]
        log_count = 0

        for method in dvm.get_methods():
            code = method.get_code()
            if not code:
                continue

            bytecode = code.get_bc()
            for inst in bytecode.get_instructions():
                inst_str = str(inst.get_output())

                for log_method in log_methods:
                    if log_method in inst_str:
                        log_count += 1

        if log_count > 0:
            findings.append(self.create_finding(
                app=app,
                title=f"Logging Detected ({log_count} Log Calls)",
                severity="low",
                category="Logging",
                description=f"Found {log_count} calls to Android Log class. Log messages may contain sensitive data that could be exposed.",
                impact="Log messages can be read by other apps with READ_LOGS permission or via ADB logcat.",
                remediation="Remove or disable logging in production builds. Use ProGuard rules to strip Log calls.",
                file_path="multiple files",
                code_snippet="Log.d(TAG, \"Debug message\");\nLog.e(TAG, \"Error: \" + sensitiveData);",
                poc_evidence=f"Found {log_count} Log.* calls across the application",
                poc_verification="1. Connect device via ADB\n2. Run: adb logcat | grep <package_name>\n3. Trigger app functionality\n4. Review logged data",
                poc_commands=[
                    "adb logcat -d | grep -i password",
                    "adb logcat -d | grep -i token",
                    "adb logcat -d | grep -i key",
                ],
                cwe_id="CWE-532",
                owasp_masvs_category="MASVS-STORAGE",
            ))

        return findings

    async def _check_webview_issues(
        self,
        app: MobileApp,
        dvm: Any,
        analysis: Any,
    ) -> list[Finding]:
        """Check for WebView security issues."""
        findings: list[Finding] = []

        webview_issues = {
            "setJavaScriptEnabled": ("JavaScript enabled in WebView", "medium"),
            "addJavascriptInterface": ("JavaScript interface exposed", "high"),
            "setAllowFileAccess": ("File access allowed in WebView", "medium"),
        }

        for method in dvm.get_methods():
            code = method.get_code()
            if not code:
                continue

            bytecode = code.get_bc()
            for inst in bytecode.get_instructions():
                inst_str = str(inst.get_output())

                for issue_method, (title, severity) in webview_issues.items():
                    if issue_method in inst_str:
                        class_path = method.get_class_name().replace(".", "/") + ".java"
                        findings.append(self.create_finding(
                            app=app,
                            title=f"WebView: {title}",
                            severity=severity,
                            category="WebView",
                            description=f"The app calls {issue_method}() on a WebView in {method.get_class_name()}.",
                            impact="May expose the app to XSS, JavaScript injection, or file exfiltration attacks.",
                            remediation="Review WebView configuration and disable unnecessary features. Use setJavaScriptEnabled(false) if JS is not required.",
                            file_path=class_path,
                            code_snippet=f"// {method.get_class_name()}\nwebView.getSettings().{issue_method}(true);",
                            poc_evidence=f"WebView {issue_method}() call found in {method.get_class_name()}",
                            poc_verification=f"1. Decompile APK: jadx -d output app.apk\n2. Search for WebView usage\n3. Verify {issue_method} configuration",
                            poc_commands=[
                                f"jadx -d /tmp/out {app.file_path}",
                                f"grep -rn '{issue_method}' /tmp/out/",
                                "grep -rn 'WebView' /tmp/out/",
                            ],
                            cwe_id="CWE-749",
                            owasp_masvs_category="MASVS-PLATFORM",
                        ))

        return findings

    async def _check_sql_issues(
        self,
        app: MobileApp,
        dvm: Any,
        analysis: Any,
    ) -> list[Finding]:
        """Check for SQL injection vulnerabilities."""
        findings: list[Finding] = []

        raw_query_methods = ["rawQuery", "execSQL"]

        for method in dvm.get_methods():
            code = method.get_code()
            if not code:
                continue

            bytecode = code.get_bc()
            for inst in bytecode.get_instructions():
                inst_str = str(inst.get_output())

                for raw_method in raw_query_methods:
                    if raw_method in inst_str:
                        class_path = method.get_class_name().replace(".", "/") + ".java"
                        findings.append(self.create_finding(
                            app=app,
                            title=f"Potential SQL Injection: {raw_method}()",
                            severity="high",
                            category="SQL Injection",
                            description=f"The app uses {raw_method}() in {method.get_class_name()} which may be vulnerable to SQL injection if user input is concatenated.",
                            impact="Attackers could read, modify, or delete database data. May lead to authentication bypass or data exfiltration.",
                            remediation="Use parameterized queries with selectionArgs. Never concatenate user input into SQL queries.",
                            file_path=class_path,
                            code_snippet=f'// {method.get_class_name()}\n// VULNERABLE:\ndb.{raw_method}("SELECT * FROM users WHERE id=" + userInput);\n\n// SAFE:\ndb.rawQuery("SELECT * FROM users WHERE id=?", new String[]{{userInput}});',
                            poc_evidence=f"Raw SQL method {raw_method}() found in {method.get_class_name()}",
                            poc_verification=f"1. Decompile APK: jadx -d output app.apk\n2. Open: output/{class_path}\n3. Search for {raw_method} calls\n4. Check if user input is concatenated",
                            poc_commands=[
                                f"jadx -d /tmp/out {app.file_path}",
                                f"grep -rn '{raw_method}' /tmp/out/",
                                "grep -rn 'SELECT.*+' /tmp/out/",
                            ],
                            cwe_id="CWE-89",
                            owasp_masvs_category="MASVS-CODE",
                        ))

        return findings

    async def _check_file_operations(
        self,
        app: MobileApp,
        dvm: Any,
        analysis: Any,
    ) -> list[Finding]:
        """Check for insecure file operations."""
        findings: list[Finding] = []

        insecure_modes = {
            "MODE_WORLD_READABLE": "File readable by all apps",
            "MODE_WORLD_WRITEABLE": "File writable by all apps",
        }

        for method in dvm.get_methods():
            code = method.get_code()
            if not code:
                continue

            bytecode = code.get_bc()
            for inst in bytecode.get_instructions():
                inst_str = str(inst.get_output())

                for mode, description in insecure_modes.items():
                    if mode in inst_str:
                        class_path = method.get_class_name().replace(".", "/") + ".java"
                        findings.append(self.create_finding(
                            app=app,
                            title=f"Insecure File Mode: {mode}",
                            severity="high",
                            category="File Security",
                            description=f"{description}. Found in {method.get_class_name()}.{method.get_name()}().",
                            impact="Other apps on the device can read or write to these files, potentially exposing sensitive data or allowing data tampering.",
                            remediation="Use MODE_PRIVATE for all internal files. For sharing data between apps, use ContentProvider with proper permissions.",
                            file_path=class_path,
                            code_snippet=f'// {method.get_class_name()}\n// INSECURE:\nopenFileOutput("data.txt", {mode});\n\n// SECURE:\nopenFileOutput("data.txt", MODE_PRIVATE);',
                            poc_evidence=f"Insecure file mode {mode} found in {method.get_class_name()}",
                            poc_verification=f"1. Decompile APK: jadx -d output app.apk\n2. Open: output/{class_path}\n3. Search for {mode}\n4. Check file operations",
                            poc_commands=[
                                f"jadx -d /tmp/out {app.file_path}",
                                f"grep -rn '{mode}' /tmp/out/",
                                "adb shell run-as <package> ls -la /data/data/<package>/files/",
                            ],
                            cwe_id="CWE-732",
                            owasp_masvs_category="MASVS-STORAGE",
                        ))

        return findings

    async def _fallback_analysis(self, app: MobileApp) -> list[Finding]:
        """Fallback analysis when androguard is not available."""
        findings: list[Finding] = []
        found_issues: set[str] = set()  # Track unique issues

        # Patterns for actual crypto usage (not just strings containing the text)
        crypto_patterns = [
            (r'\bDES/\w+/\w+', "DES cipher mode", "high"),
            (r'\bDESede\b', "Triple DES (DESede)", "medium"),
            (r'Cipher\.getInstance\(["\']DES', "DES cipher instantiation", "high"),
            (r'\bRC4\b', "RC4 stream cipher", "high"),
            (r'MessageDigest\.getInstance\(["\']MD5', "MD5 hash instantiation", "medium"),
            (r'\bMD5\s*\(', "MD5 function call", "medium"),
            (r'/ECB/', "ECB mode cipher", "high"),
            (r'AES/ECB', "AES with ECB mode", "high"),
        ]

        try:
            with zipfile.ZipFile(app.file_path, "r") as apk:
                for name in apk.namelist():
                    if name.endswith(".dex"):
                        dex_data = apk.read(name)
                        dex_text = dex_data.decode("utf-8", errors="ignore")

                        for pattern, issue_name, severity in crypto_patterns:
                            matches = re.findall(pattern, dex_text)
                            for match in matches:
                                issue_key = f"{issue_name}:{match}"
                                if issue_key not in found_issues:
                                    found_issues.add(issue_key)
                                    findings.append(self.create_finding(
                                        app=app,
                                        title=f"Weak Cryptography: {issue_name}",
                                        severity=severity,
                                        category="Cryptography",
                                        description=f"Found weak cryptographic pattern: {match}. This algorithm is considered insecure for modern applications.",
                                        impact="Weak cryptography can be broken to expose sensitive data. DES and RC4 can be cracked in reasonable time; MD5 has collision vulnerabilities; ECB mode leaks patterns.",
                                        remediation="Use AES-256 with GCM mode for encryption, SHA-256+ for hashing. Avoid ECB mode - use CBC or GCM instead.",
                                        file_path=name,
                                        code_snippet=f'// Found pattern: {match}\n// Use instead:\nCipher.getInstance("AES/GCM/NoPadding");',
                                        poc_evidence=f"Weak crypto pattern '{match}' found in {name}",
                                        poc_verification=f"1. Decompile APK: jadx -d output app.apk\n2. Search for: {match}\n3. Verify algorithm usage in context",
                                        poc_commands=[
                                            f"jadx -d /tmp/out {app.file_path}",
                                            f"grep -rn '{match}' /tmp/out/",
                                            "strings /tmp/out/classes*.dex | grep -i cipher",
                                        ],
                                        cwe_id="CWE-327",
                                        owasp_masvs_category="MASVS-CRYPTO",
                                    ))

        except Exception as e:
            logger.error(f"Fallback DEX analysis failed: {e}")

        return findings
