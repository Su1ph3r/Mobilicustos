"""Android DEX bytecode analyzer for security vulnerability detection.

Performs deep analysis of Dalvik Executable (DEX) bytecode within APK files
using the androguard library. When androguard is unavailable, falls back to
regex-based string pattern matching on raw DEX data.

Security checks performed:
    - **Weak cryptography** (CWE-327, MASVS-CRYPTO / MSTG-CRYPTO-4):
      Detection of insecure algorithms (DES, RC4, MD5, SHA1, ECB mode).
    - **Sensitive logging** (CWE-532, MASVS-STORAGE / MSTG-STORAGE-3):
      Counting Android Log calls that may leak sensitive data.
    - **WebView issues** (CWE-749, MASVS-PLATFORM / MSTG-PLATFORM-7):
      JavaScript enabled, JS interfaces exposed, file access allowed.
    - **SQL injection** (CWE-89, MASVS-CODE / MSTG-CODE-6):
      Use of rawQuery/execSQL with potential string concatenation.
    - **Insecure file operations** (CWE-732, MASVS-STORAGE / MSTG-STORAGE-2):
      World-readable or world-writable file modes.
"""

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class DexAnalyzer(BaseAnalyzer):
    """Analyzes Android DEX bytecode for security vulnerabilities.

    Uses androguard to parse DEX files and inspect method-level bytecode
    instructions for insecure API calls and patterns. Each finding includes
    Frida hook scripts for runtime verification and jadx decompilation
    commands for manual review.

    When androguard is not installed (e.g., minimal Docker image), falls
    back to ``_fallback_analysis()`` which uses regex matching on raw DEX
    binary data.

    Attributes:
        name: Analyzer identifier (``"dex_analyzer"``).
        platform: Target platform (``"android"`` only).
    """

    name = "dex_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze all DEX files within the APK for security issues.

        Loads each DEX file via androguard, creates cross-references, and
        runs all check methods. Falls back to regex-based analysis if
        androguard is not available.

        Args:
            app: MobileApp ORM model with ``file_path`` pointing to the APK.

        Returns:
            List of Finding objects for detected security issues.
        """
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
        """Check for use of weak or deprecated cryptographic algorithms.

        Inspects ``const-string`` bytecode instructions for algorithm names
        passed to ``Cipher.getInstance()`` or ``MessageDigest.getInstance()``.
        Detects: DES, DESede (3DES), RC4, MD5, SHA1, ECB mode.

        Maps to: CWE-327, MASVS-CRYPTO, MSTG-CRYPTO-4, MASTG-TEST-0014.
        """
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
                                    {"type": "bash", "command": f"jadx -d /tmp/out {app.file_path}", "description": "Decompile APK with jadx"},
                                    {"type": "bash", "command": f"grep -rn '{algo}' /tmp/out/", "description": f"Search for {algo} usage"},
                                ],
                                poc_frida_script=f'''Java.perform(function() {{
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {{
        console.log("[*] Cipher.getInstance: " + algo);
        if (algo.indexOf("{algo}") !== -1) {{
            console.log("[!] WEAK ALGORITHM DETECTED: " + algo);
        }}
        return this.getInstance(algo);
    }};
}});''',
                                cwe_id="CWE-327",
                                cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                                cvss_score=7.5 if algo in ("DES", "RC4", "ECB") else 5.3,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if algo in ("DES", "RC4", "ECB") else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                owasp_masvs_category="MASVS-CRYPTO",
                                owasp_masvs_control="MSTG-CRYPTO-4",
                                owasp_mastg_test="MASTG-TEST-0014",
                                remediation_code={
                                    "java": 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");',
                                    "kotlin": 'val cipher = Cipher.getInstance("AES/GCM/NoPadding")',
                                },
                                remediation_resources=[
                                    {"title": "OWASP MASTG - Testing for Insecure Cryptographic Algorithms", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/", "type": "documentation"},
                                ],
                            ))

        return findings

    async def _check_logging(
        self,
        app: MobileApp,
        dvm: Any,
        analysis: Any,
    ) -> list[Finding]:
        """Check for Android Log class usage that may leak sensitive data.

        Counts invocations of ``Log.v/d/i/w/e`` across all methods. A high
        count in release builds suggests logging is not being stripped.

        Maps to: CWE-532, MASVS-STORAGE, MSTG-STORAGE-3, MASTG-TEST-0003.
        """
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
                    {"type": "adb", "command": "adb logcat -d | grep -i password", "description": "Search logs for passwords"},
                    {"type": "adb", "command": "adb logcat -d | grep -i token", "description": "Search logs for tokens"},
                    {"type": "adb", "command": "adb logcat -d | grep -i key", "description": "Search logs for keys"},
                ],
                poc_frida_script='''Java.perform(function() {
    var Log = Java.use('android.util.Log');
    ['v', 'd', 'i', 'w', 'e'].forEach(function(level) {
        Log[level].overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
            console.log("[LOG/" + level.toUpperCase() + "] " + tag + ": " + msg);
            return this[level](tag, msg);
        };
    });
});''',
                cwe_id="CWE-532",
                cwe_name="Insertion of Sensitive Information into Log File",
                cvss_score=3.3,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                owasp_masvs_category="MASVS-STORAGE",
                owasp_masvs_control="MSTG-STORAGE-3",
                owasp_mastg_test="MASTG-TEST-0003",
                remediation_code={
                    "proguard": '''-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}'''
                },
                remediation_resources=[
                    {"title": "OWASP MASTG - Testing Logs for Sensitive Data", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/", "type": "documentation"},
                ],
            ))

        return findings

    async def _check_webview_issues(
        self,
        app: MobileApp,
        dvm: Any,
        analysis: Any,
    ) -> list[Finding]:
        """Check for insecure WebView configurations.

        Detects calls to ``setJavaScriptEnabled``, ``addJavascriptInterface``,
        and ``setAllowFileAccess`` which can expose the app to XSS, JavaScript
        injection, and file exfiltration attacks.

        Maps to: CWE-749, MASVS-PLATFORM, MSTG-PLATFORM-7, MASTG-TEST-0031.
        """
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
                                {"type": "bash", "command": f"jadx -d /tmp/out {app.file_path}", "description": "Decompile APK"},
                                {"type": "bash", "command": f"grep -rn '{issue_method}' /tmp/out/", "description": f"Search for {issue_method}"},
                                {"type": "bash", "command": "grep -rn 'WebView' /tmp/out/", "description": "Find all WebView usage"},
                            ],
                            poc_frida_script='''Java.perform(function() {
    var WebSettings = Java.use('android.webkit.WebSettings');
    WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
        console.log("[*] setJavaScriptEnabled: " + enabled);
        return this.setJavaScriptEnabled(enabled);
    };

    var WebView = Java.use('android.webkit.WebView');
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log("[!] addJavascriptInterface: " + name);
        console.log("    Object class: " + obj.$className);
        return this.addJavascriptInterface(obj, name);
    };
});''',
                            cwe_id="CWE-749",
                            cwe_name="Exposed Dangerous Method or Function",
                            cvss_score=7.5 if severity == "high" else 5.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if severity == "high" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            owasp_masvs_category="MASVS-PLATFORM",
                            owasp_masvs_control="MSTG-PLATFORM-7",
                            owasp_mastg_test="MASTG-TEST-0031",
                            remediation_resources=[
                                {"title": "OWASP MASTG - Testing WebView Protocol Handlers", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/", "type": "documentation"},
                            ],
                        ))

        return findings

    async def _check_sql_issues(
        self,
        app: MobileApp,
        dvm: Any,
        analysis: Any,
    ) -> list[Finding]:
        """Check for potential SQL injection via raw query methods.

        Detects calls to ``rawQuery()`` and ``execSQL()`` on
        ``SQLiteDatabase``, which are vulnerable to SQL injection if user
        input is concatenated into the query string.

        Maps to: CWE-89, MASVS-CODE, MSTG-CODE-6, MASTG-TEST-0025.
        """
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
                                {"type": "bash", "command": f"jadx -d /tmp/out {app.file_path}", "description": "Decompile APK"},
                                {"type": "bash", "command": f"grep -rn '{raw_method}' /tmp/out/", "description": f"Find {raw_method} calls"},
                                {"type": "bash", "command": "grep -rn 'SELECT.*+' /tmp/out/", "description": "Find string concatenation in SQL"},
                            ],
                            poc_frida_script='''Java.perform(function() {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
        console.log("[*] rawQuery: " + sql);
        if (args) {
            console.log("    Args: " + args.join(", "));
        }
        return this.rawQuery(sql, args);
    };

    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
        console.log("[*] execSQL: " + sql);
        return this.execSQL(sql);
    };
});''',
                            cwe_id="CWE-89",
                            cwe_name="SQL Injection",
                            cvss_score=8.6,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                            owasp_masvs_category="MASVS-CODE",
                            owasp_masvs_control="MSTG-CODE-6",
                            owasp_mastg_test="MASTG-TEST-0025",
                            remediation_code={
                                "java": '''// Use parameterized queries
String[] args = {userInput};
Cursor cursor = db.rawQuery("SELECT * FROM users WHERE id=?", args);''',
                                "kotlin": '''// Use parameterized queries
val cursor = db.rawQuery("SELECT * FROM users WHERE id=?", arrayOf(userInput))'''
                            },
                            remediation_resources=[
                                {"title": "OWASP MASTG - Testing for SQL Injection", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0025/", "type": "documentation"},
                            ],
                        ))

        return findings

    async def _check_file_operations(
        self,
        app: MobileApp,
        dvm: Any,
        analysis: Any,
    ) -> list[Finding]:
        """Check for insecure file permission modes.

        Detects use of ``MODE_WORLD_READABLE`` and ``MODE_WORLD_WRITEABLE``
        with ``openFileOutput()``, which make files accessible to all apps.

        Maps to: CWE-732, MASVS-STORAGE, MSTG-STORAGE-2, MASTG-TEST-0002.
        """
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
                                {"type": "bash", "command": f"jadx -d /tmp/out {app.file_path}", "description": "Decompile APK"},
                                {"type": "bash", "command": f"grep -rn '{mode}' /tmp/out/", "description": f"Search for {mode} usage"},
                                {"type": "adb", "command": f"adb shell run-as {app.package_name} ls -la /data/data/{app.package_name}/files/", "description": "List app files with permissions"},
                            ],
                            poc_frida_script='''Java.perform(function() {
    var Context = Java.use('android.content.Context');
    Context.openFileOutput.overload('java.lang.String', 'int').implementation = function(name, mode) {
        var modeStr = "";
        if (mode == 0) modeStr = "MODE_PRIVATE";
        else if (mode == 1) modeStr = "MODE_WORLD_READABLE";
        else if (mode == 2) modeStr = "MODE_WORLD_WRITEABLE";
        console.log("[*] openFileOutput: " + name + " mode=" + modeStr);
        return this.openFileOutput(name, mode);
    };
});''',
                            cwe_id="CWE-732",
                            cwe_name="Incorrect Permission Assignment for Critical Resource",
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            owasp_masvs_category="MASVS-STORAGE",
                            owasp_masvs_control="MSTG-STORAGE-2",
                            owasp_mastg_test="MASTG-TEST-0002",
                            remediation_code={
                                "java": 'FileOutputStream fos = openFileOutput("data.txt", Context.MODE_PRIVATE);',
                                "kotlin": 'val fos = openFileOutput("data.txt", Context.MODE_PRIVATE)'
                            },
                            remediation_resources=[
                                {"title": "OWASP MASTG - Testing Local Storage for Sensitive Data", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0002/", "type": "documentation"},
                            ],
                        ))

        return findings

    async def _fallback_analysis(self, app: MobileApp) -> list[Finding]:
        """Regex-based fallback analysis when androguard is not available.

        Reads raw DEX binary data from the APK and applies regex patterns
        to detect cryptographic algorithm usage. Less precise than bytecode
        analysis but works without androguard dependencies.

        Args:
            app: MobileApp ORM model with ``file_path`` pointing to the APK.

        Returns:
            List of Finding objects for detected weak crypto patterns.
        """
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
                                            {"type": "bash", "command": f"jadx -d /tmp/out {app.file_path}", "description": "Decompile APK"},
                                            {"type": "bash", "command": f"grep -rn '{match}' /tmp/out/", "description": f"Search for {match}"},
                                            {"type": "bash", "command": "strings /tmp/out/classes*.dex | grep -i cipher", "description": "Extract cipher strings from DEX"},
                                        ],
                                        cwe_id="CWE-327",
                                        cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                                        cvss_score=7.5 if severity == "high" else 5.3,
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if severity == "high" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                        owasp_masvs_category="MASVS-CRYPTO",
                                        owasp_masvs_control="MSTG-CRYPTO-4",
                                        owasp_mastg_test="MASTG-TEST-0014",
                                        remediation_code={
                                            "java": 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");',
                                        },
                                        remediation_resources=[
                                            {"title": "OWASP MASTG - Testing for Insecure Cryptographic Algorithms", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/", "type": "documentation"},
                                        ],
                                    ))

        except Exception as e:
            logger.error(f"Fallback DEX analysis failed: {e}")

        return findings
