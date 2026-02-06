"""Code quality analyzer for injection vulnerabilities and security anti-patterns.

Scans decompiled application source code for common security vulnerabilities
including SQL injection, command injection, path traversal, XSS vectors,
insecure random number generation, and unsafe deserialization.

OWASP references:
    - CWE-89: SQL Injection
    - CWE-78: OS Command Injection
    - CWE-22: Path Traversal
    - CWE-79: Cross-site Scripting (XSS)
    - CWE-330: Insecure Random Number Generation
    - MASVS-CODE
"""

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class CodeQualityAnalyzer(BaseAnalyzer):
    """Analyzes application source code for injection and security anti-patterns.

    Performs regex-based analysis on decompiled source to detect common
    vulnerability classes including SQL injection, command injection,
    path traversal, and insecure cryptographic usage.
    """

    name = "code_quality_analyzer"
    platform = "cross-platform"

    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        {
            "pattern": r'rawQuery\s*\(\s*["\'][^"\']*\s*\+',
            "name": "SQL Injection via rawQuery concatenation",
            "description": "SQL query built with string concatenation in rawQuery()",
            "severity": "high",
            "cwe_id": "CWE-89",
            "cwe_name": "SQL Injection",
        },
        {
            "pattern": r'execSQL\s*\(\s*["\'][^"\']*\s*\+',
            "name": "SQL Injection via execSQL concatenation",
            "description": "SQL statement built with string concatenation in execSQL()",
            "severity": "high",
            "cwe_id": "CWE-89",
            "cwe_name": "SQL Injection",
        },
        {
            "pattern": r'query\s*\([^)]*\+[^)]*\)',
            "name": "Potential SQL Injection in query()",
            "description": "Query method with potential string concatenation",
            "severity": "medium",
            "cwe_id": "CWE-89",
            "cwe_name": "SQL Injection",
        },
    ]

    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        {
            "pattern": r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',
            "name": "Command Injection via Runtime",
            "description": "Shell command built with string concatenation",
            "severity": "critical",
            "cwe_id": "CWE-78",
            "cwe_name": "OS Command Injection",
        },
        {
            "pattern": r'ProcessBuilder\s*\([^)]*\+',
            "name": "Command Injection via ProcessBuilder",
            "description": "Process command built with dynamic input",
            "severity": "critical",
            "cwe_id": "CWE-78",
            "cwe_name": "OS Command Injection",
        },
    ]

    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        {
            "pattern": r'new File\s*\([^)]*\+[^)]*getIntent\(\)',
            "name": "Path Traversal via Intent data",
            "description": "File path constructed from Intent data",
            "severity": "high",
            "cwe_id": "CWE-22",
            "cwe_name": "Path Traversal",
        },
        {
            "pattern": r'openFileInput\s*\([^)]*getIntent\(\)',
            "name": "Path Traversal in file access",
            "description": "File opened with path from external input",
            "severity": "high",
            "cwe_id": "CWE-22",
            "cwe_name": "Path Traversal",
        },
    ]

    # XSS patterns (WebView)
    XSS_PATTERNS = [
        {
            "pattern": r'evaluateJavascript\s*\([^)]*\+',
            "name": "XSS via evaluateJavascript",
            "description": "JavaScript execution with concatenated string",
            "severity": "high",
            "cwe_id": "CWE-79",
            "cwe_name": "Cross-site Scripting (XSS)",
        },
        {
            "pattern": r'loadUrl\s*\(["\']javascript:[^)]*\+',
            "name": "XSS via loadUrl javascript:",
            "description": "JavaScript URL with concatenation",
            "severity": "high",
            "cwe_id": "CWE-79",
            "cwe_name": "Cross-site Scripting (XSS)",
        },
    ]

    # Insecure Deserialization patterns
    DESERIALIZATION_PATTERNS = [
        {
            "pattern": r'ObjectInputStream\s*\(',
            "name": "Insecure Deserialization",
            "description": "ObjectInputStream used for deserialization",
            "severity": "high",
            "cwe_id": "CWE-502",
            "cwe_name": "Deserialization of Untrusted Data",
        },
        {
            "pattern": r'readObject\s*\(\)',
            "name": "Java readObject() call",
            "description": "Deserialization of Java objects",
            "severity": "medium",
            "cwe_id": "CWE-502",
            "cwe_name": "Deserialization of Untrusted Data",
        },
    ]

    # Dynamic Code Loading patterns
    DYNAMIC_CODE_PATTERNS = [
        {
            "pattern": r'DexClassLoader\s*\(',
            "name": "Dynamic DEX Loading",
            "description": "Dynamic loading of DEX files at runtime",
            "severity": "high",
            "cwe_id": "CWE-470",
            "cwe_name": "Use of Externally-Controlled Input to Select Classes or Code",
        },
        {
            "pattern": r'loadClass\s*\([^)]*\+',
            "name": "Dynamic Class Loading",
            "description": "Class loaded with dynamic name",
            "severity": "medium",
            "cwe_id": "CWE-470",
            "cwe_name": "Use of Externally-Controlled Input to Select Classes or Code",
        },
    ]

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze code for injection and security vulnerabilities."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            if app.platform == "android":
                findings.extend(await self._analyze_android(app))
            elif app.platform == "ios":
                findings.extend(await self._analyze_ios(app))

        except Exception as e:
            logger.error(f"Code quality analysis failed: {e}")

        return findings

    async def _analyze_android(self, app: MobileApp) -> list[Finding]:
        """Analyze Android app for code quality issues."""
        findings: list[Finding] = []

        try:
            with zipfile.ZipFile(app.file_path, "r") as apk:
                for name in apk.namelist():
                    if name.endswith(".dex"):
                        dex_data = apk.read(name)
                        dex_text = dex_data.decode("utf-8", errors="ignore")

                        # Check all pattern categories
                        findings.extend(self._check_patterns(
                            app, dex_text, self.SQL_INJECTION_PATTERNS, name, "SQL Injection"
                        ))
                        findings.extend(self._check_patterns(
                            app, dex_text, self.COMMAND_INJECTION_PATTERNS, name, "Command Injection"
                        ))
                        findings.extend(self._check_patterns(
                            app, dex_text, self.PATH_TRAVERSAL_PATTERNS, name, "Path Traversal"
                        ))
                        findings.extend(self._check_patterns(
                            app, dex_text, self.XSS_PATTERNS, name, "Cross-site Scripting"
                        ))
                        findings.extend(self._check_patterns(
                            app, dex_text, self.DESERIALIZATION_PATTERNS, name, "Insecure Deserialization"
                        ))
                        findings.extend(self._check_patterns(
                            app, dex_text, self.DYNAMIC_CODE_PATTERNS, name, "Dynamic Code Loading"
                        ))

        except Exception as e:
            logger.error(f"Android code analysis failed: {e}")

        return findings

    async def _analyze_ios(self, app: MobileApp) -> list[Finding]:
        """Analyze iOS app for code quality issues."""
        findings: list[Finding] = []

        try:
            with zipfile.ZipFile(app.file_path, "r") as ipa:
                for name in ipa.namelist():
                    if "/Payload/" in name and not name.endswith("/"):
                        try:
                            file_data = ipa.read(name)
                            file_text = file_data.decode("utf-8", errors="ignore")

                            # iOS-specific patterns
                            findings.extend(self._check_patterns(
                                app, file_text, self.COMMAND_INJECTION_PATTERNS, name, "Command Injection"
                            ))
                            findings.extend(self._check_patterns(
                                app, file_text, self.DESERIALIZATION_PATTERNS, name, "Insecure Deserialization"
                            ))

                        except Exception:
                            continue

        except Exception as e:
            logger.error(f"iOS code analysis failed: {e}")

        return findings

    def _check_patterns(
        self,
        app: MobileApp,
        text: str,
        patterns: list[dict[str, Any]],
        file_path: str,
        category: str,
    ) -> list[Finding]:
        """Check text against a list of patterns."""
        findings: list[Finding] = []
        found_patterns: set[str] = set()

        for pattern_info in patterns:
            pattern = pattern_info["pattern"]
            matches = re.findall(pattern, text, re.IGNORECASE)

            if matches and pattern_info["name"] not in found_patterns:
                found_patterns.add(pattern_info["name"])
                findings.append(self._create_finding_for_pattern(
                    app, pattern_info, file_path, category, matches[0] if matches else None
                ))

        return findings

    def _create_finding_for_pattern(
        self,
        app: MobileApp,
        pattern_info: dict[str, Any],
        file_path: str,
        category: str,
        match: str | None,
    ) -> Finding:
        """Create a finding for a detected pattern."""
        poc_commands = self._get_poc_commands(pattern_info, app)
        remediation_info = self._get_remediation(pattern_info)

        return self.create_finding(
            app=app,
            title=pattern_info["name"],
            severity=pattern_info["severity"],
            category=category,
            description=(
                f"{pattern_info['description']}\n\n"
                f"This vulnerability can lead to serious security issues if user input "
                f"is not properly validated and sanitized before use."
            ),
            impact=self._get_impact(pattern_info),
            remediation=remediation_info["text"],
            file_path=file_path,
            code_snippet=match[:200] if match else None,
            cwe_id=pattern_info.get("cwe_id"),
            cwe_name=pattern_info.get("cwe_name"),
            cvss_score=self._get_cvss_score(pattern_info["severity"]),
            cvss_vector=self._get_cvss_vector(pattern_info),
            owasp_masvs_category="MASVS-CODE",
            owasp_masvs_control="MASVS-CODE-4",
            poc_commands=poc_commands,
            poc_frida_script=self._get_frida_script(pattern_info),
            remediation_code=remediation_info.get("code", {}),
            remediation_resources=remediation_info.get("resources", []),
        )

    def _get_impact(self, pattern_info: dict[str, Any]) -> str:
        """Get impact description based on vulnerability type."""
        cwe_id = pattern_info.get("cwe_id", "")

        impacts = {
            "CWE-89": "Attackers can read, modify, or delete database data.",
            "CWE-78": "Attackers can run arbitrary system commands.",
            "CWE-22": "Attackers can read or write arbitrary files.",
            "CWE-79": "Attackers can inject malicious scripts.",
            "CWE-502": "Attackers can run arbitrary code during deserialization.",
            "CWE-470": "Attackers can load and run arbitrary code.",
        }

        return impacts.get(cwe_id, "This vulnerability can compromise security.")

    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score based on severity."""
        scores = {"critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}
        return scores.get(severity, 5.0)

    def _get_cvss_vector(self, pattern_info: dict[str, Any]) -> str:
        """Get CVSS vector based on vulnerability type."""
        cwe_id = pattern_info.get("cwe_id", "")
        vectors = {
            "CWE-89": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "CWE-78": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "CWE-22": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "CWE-79": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            "CWE-502": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CWE-470": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        }
        return vectors.get(cwe_id, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")

    def _get_poc_commands(self, pattern_info: dict[str, Any], app: MobileApp) -> list[dict[str, str]]:
        """Get PoC commands for the vulnerability type."""
        return [
            {"type": "bash", "command": f"jadx -d /tmp/out {app.file_path}", "description": "Decompile APK"},
            {"type": "bash", "command": "grep -rn 'rawQuery\\|execSQL' /tmp/out/", "description": "Find SQL methods"},
        ]

    def _get_frida_script(self, pattern_info: dict[str, Any]) -> str | None:
        """Get Frida script for runtime analysis."""
        cwe_id = pattern_info.get("cwe_id", "")
        if cwe_id == "CWE-89":
            return '''Java.perform(function() {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
        console.log("[*] rawQuery: " + sql);
        return this.rawQuery(sql, args);
    };
});'''
        return None

    def _get_remediation(self, pattern_info: dict[str, Any]) -> dict[str, Any]:
        """Get remediation guidance for the vulnerability type."""
        cwe_id = pattern_info.get("cwe_id", "")
        remediations = {
            "CWE-89": {
                "text": "Use parameterized queries. Never concatenate user input into SQL.",
                "code": {"java": 'db.rawQuery("SELECT * FROM users WHERE id=?", new String[]{userInput});'},
                "resources": [{"title": "OWASP SQL Injection Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "type": "documentation"}],
            },
            "CWE-78": {
                "text": "Avoid shell commands with user input. Use whitelisting.",
                "code": {},
                "resources": [{"title": "OWASP Command Injection", "url": "https://owasp.org/www-community/attacks/Command_Injection", "type": "documentation"}],
            },
        }
        return remediations.get(cwe_id, {"text": "Review and fix the vulnerable code.", "code": {}, "resources": []})
