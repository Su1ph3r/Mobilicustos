"""
iOS Binary Analyzer

Analyzes iOS Mach-O binaries for security issues.
"""

import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from .base_analyzer import BaseAnalyzer
from ..ios_toolchain import get_ios_toolchain


class iOSBinaryAnalyzer(BaseAnalyzer):
    """Analyzer for iOS Mach-O binaries"""

    name = "ios_binary_analyzer"
    platform = "ios"

    # Security patterns to detect in symbols
    INSECURE_FUNCTIONS = [
        ("strcpy", "Use of strcpy - vulnerable to buffer overflow"),
        ("strcat", "Use of strcat - vulnerable to buffer overflow"),
        ("sprintf", "Use of sprintf - vulnerable to buffer overflow"),
        ("gets", "Use of gets - extremely dangerous, always vulnerable"),
        ("scanf", "Use of scanf without bounds - vulnerable to overflow"),
        ("NSLog", "NSLog usage may leak sensitive data"),
        ("printf", "printf may be vulnerable to format string attacks"),
    ]

    # Jailbreak detection indicators
    JAILBREAK_DETECTION_PATTERNS = [
        "cydia",
        "substrate",
        "jailbreak",
        "jailbroken",
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt",
        "sileo",
        "checkra1n",
        "unc0ver",
    ]

    # Anti-debugging patterns
    ANTI_DEBUG_PATTERNS = [
        "ptrace",
        "sysctl",
        "getppid",
        "isatty",
        "PT_DENY_ATTACH",
    ]

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze iOS binary"""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        # Extract binary path from IPA
        binary_path = await self._extract_binary(Path(app.file_path))
        if not binary_path:
            return findings

        # Store app reference for create_finding
        self._current_app = app

        toolchain = get_ios_toolchain()
        tier = toolchain.get_tier()

        # Basic string analysis (Tier 1)
        strings = toolchain.extract_strings(binary_path)
        findings.extend(self._analyze_strings(app, strings, binary_path))

        # Tier 2 analysis (Mac-only)
        if tier >= 2:
            # otool analysis
            otool_result = toolchain.analyze_binary_otool(binary_path)
            if "error" not in otool_result:
                findings.extend(self._analyze_otool_result(app, otool_result, binary_path))

            # nm symbol analysis
            nm_result = toolchain.analyze_binary_nm(binary_path)
            if "error" not in nm_result:
                findings.extend(self._analyze_symbols(app, nm_result, binary_path))

            # class-dump analysis
            if toolchain.capabilities.get("class_dump"):
                class_dump = toolchain.class_dump_binary(binary_path)
                if "error" not in class_dump:
                    findings.extend(self._analyze_class_dump(app, class_dump, binary_path))

        return findings

    async def _extract_binary(self, ipa_path: Path) -> str | None:
        """Extract main binary from IPA."""
        try:
            import tempfile
            with zipfile.ZipFile(ipa_path, "r") as ipa:
                for name in ipa.namelist():
                    # Look for main executable in Payload/AppName.app/AppName
                    if "Payload/" in name and ".app/" in name:
                        parts = name.split("/")
                        if len(parts) >= 3:
                            app_dir = parts[1]  # AppName.app
                            app_name = app_dir.replace(".app", "")
                            expected_binary = f"Payload/{app_dir}/{app_name}"
                            if name == expected_binary:
                                temp_dir = Path(tempfile.mkdtemp())
                                ipa.extract(name, temp_dir)
                                return str(temp_dir / name)
        except Exception:
            pass
        return None

    def _analyze_strings(self, app: MobileApp, strings: list[str], binary_path: str) -> list[Finding]:
        """Analyze extracted strings for security issues"""
        findings: list[Finding] = []
        binary_name = Path(binary_path).name

        # Check for jailbreak detection
        jailbreak_indicators = []
        for string in strings:
            for pattern in self.JAILBREAK_DETECTION_PATTERNS:
                if pattern.lower() in string.lower():
                    jailbreak_indicators.append(string)
                    break

        if jailbreak_indicators:
            findings.append(
                self.create_finding(
                    app=app,
                    title="Jailbreak Detection Implemented",
                    description=f"The application contains jailbreak detection mechanisms. "
                    f"Found {len(jailbreak_indicators)} indicators including paths and tools "
                    f"commonly used to detect jailbroken devices.",
                    severity="info",
                    category="Anti-Tampering",
                    impact="Jailbreak detection can be bypassed using Frida or similar tools. "
                    "Consider implementing multiple layers of detection.",
                    remediation="Implement multiple jailbreak detection methods and use "
                    "obfuscation to make bypassing more difficult.",
                    file_path=f"Payload/*.app/{binary_name}",
                    code_snippet=f"// Jailbreak indicators found:\n{chr(10).join(jailbreak_indicators[:5])}",
                    poc_evidence=f"Indicators found: {', '.join(jailbreak_indicators[:10])}",
                    poc_verification="1. Extract IPA\n2. Run strings on binary\n3. Search for jailbreak paths",
                    poc_commands=[
                        f"unzip -o {app.file_path} -d /tmp/extracted",
                        f"strings /tmp/extracted/Payload/*.app/{binary_name} | grep -i cydia",
                        "# Bypass with Frida: frida -U -l jailbreak_bypass.js <app>",
                    ],
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-2",
                )
            )

        # Check for hardcoded URLs
        url_patterns = ["http://", "https://"]
        urls = [s for s in strings if any(p in s for p in url_patterns)]
        insecure_urls = [u for u in urls if u.startswith("http://")]

        if insecure_urls:
            findings.append(
                self.create_finding(
                    app=app,
                    title="Hardcoded HTTP URLs Detected",
                    description=f"Found {len(insecure_urls)} hardcoded HTTP URLs that may "
                    f"transmit data without encryption.",
                    severity="medium",
                    category="Network Security",
                    impact="Data transmitted over HTTP can be intercepted by attackers on "
                    "the same network, potentially exposing sensitive information.",
                    remediation="Use HTTPS for all network communications. Update hardcoded "
                    "URLs to use HTTPS protocol.",
                    file_path=f"Payload/*.app/{binary_name}",
                    code_snippet=f"// Insecure URLs found:\n{chr(10).join(insecure_urls[:5])}",
                    poc_evidence=f"Insecure URLs: {', '.join(insecure_urls[:5])}",
                    poc_verification="1. Extract IPA\n2. Run strings on binary\n3. Grep for http://",
                    poc_commands=[
                        f"strings /tmp/extracted/Payload/*.app/{binary_name} | grep 'http://'",
                        "# Intercept traffic with: mitmproxy -p 8080",
                    ],
                    owasp_masvs_category="MASVS-NETWORK",
                    owasp_masvs_control="MASVS-NETWORK-1",
                )
            )

        # Check for potential API keys and secrets
        secret_patterns = [
            ("api_key", "API Key"),
            ("apikey", "API Key"),
            ("secret", "Secret"),
            ("password", "Password"),
            ("private_key", "Private Key"),
            ("bearer", "Bearer Token"),
        ]

        # Collect all secret matches first
        all_secret_matches = []
        for pattern, name in secret_patterns:
            matches = [s for s in strings if pattern.lower() in s.lower() and len(s) < 500]
            for match in matches[:5]:  # Limit to 5 per pattern
                all_secret_matches.append((pattern, name, match))

        if all_secret_matches:
            # Group by pattern for display
            patterns_found = list(set(m[1] for m in all_secret_matches))
            sample_secrets = all_secret_matches[:10]  # Show up to 10 total

            # Format the evidence with actual strings found
            evidence_lines = []
            for pattern, name, match in sample_secrets:
                # Truncate very long matches
                display_match = match if len(match) <= 100 else match[:97] + "..."
                evidence_lines.append(f"[{name}] {display_match}")

            findings.append(
                self.create_finding(
                    app=app,
                    title=f"Potential Hardcoded Secrets Detected ({len(all_secret_matches)} matches)",
                    description=f"Found {len(all_secret_matches)} strings containing potential secrets "
                    f"({', '.join(patterns_found)}). These may indicate hardcoded credentials.",
                    severity="high",
                    category="Credential Management",
                    impact="Hardcoded credentials can be extracted from the binary by "
                    "reverse engineering, potentially compromising backend systems.",
                    remediation="Remove hardcoded credentials. Use secure credential "
                    "storage like iOS Keychain with appropriate protection class.",
                    file_path=f"Payload/*.app/{binary_name}",
                    code_snippet=f"// Detected secrets:\n{chr(10).join(evidence_lines)}",
                    poc_evidence=f"DETECTED SECRETS:\n{chr(10).join(evidence_lines)}",
                    poc_verification="1. Extract IPA: unzip app.ipa -d /tmp/extracted\n"
                    "2. Run strings on binary: strings Payload/*.app/<binary>\n"
                    "3. Search for patterns: grep -i 'api_key\\|secret\\|password'",
                    poc_commands=[
                        f"unzip -o {app.file_path} -d /tmp/extracted",
                        f"strings /tmp/extracted/Payload/*.app/{binary_name} | grep -iE 'api_key|apikey|secret|password|private_key|bearer'",
                        "# Extract with Frida: frida -U -l dump_keychain.js <app>",
                    ],
                    owasp_masvs_category="MASVS-STORAGE",
                    owasp_masvs_control="MASVS-STORAGE-1",
                )
            )

        return findings

    def _analyze_otool_result(self, app: MobileApp, otool_result: dict[str, Any], binary_path: str) -> list[Finding]:
        """Analyze otool output for security issues"""
        findings: list[Finding] = []
        binary_name = Path(binary_path).name

        # Check encryption status
        encryption_info = otool_result.get("encryption_info", {})
        if encryption_info.get("encrypted") is False:
            findings.append(
                self.create_finding(
                    app=app,
                    title="Binary Not Encrypted",
                    description="The application binary is not encrypted with Apple FairPlay DRM. "
                    "This is normal for development builds but unusual for App Store releases.",
                    severity="info",
                    category="Binary Protection",
                    impact="Unencrypted binaries are easier to reverse engineer as they don't "
                    "require decryption before analysis.",
                    remediation="For production releases, ensure the app is submitted through "
                    "the App Store which applies FairPlay encryption automatically.",
                    file_path=f"Payload/*.app/{binary_name}",
                    code_snippet="# Check encryption:\notool -l binary | grep -A4 LC_ENCRYPTION_INFO\n# cryptid 0 = not encrypted",
                    poc_evidence="cryptid is 0 - binary is not encrypted",
                    poc_verification="1. Run otool on binary\n2. Check LC_ENCRYPTION_INFO load command\n3. Verify cryptid value",
                    poc_commands=[
                        f"otool -l /tmp/extracted/Payload/*.app/{binary_name} | grep -A4 LC_ENCRYPTION_INFO",
                        "# If encrypted, decrypt with: frida-ios-dump <app>",
                    ],
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-3",
                )
            )

        # Check for dangerous libraries
        libraries = otool_result.get("linked_libraries", [])
        dangerous_libs = {
            "libsqlite": "SQLite linked - ensure parameterized queries are used",
            "libxml": "XML parser linked - check for XXE vulnerabilities",
            "libz": "Compression library - may indicate zip bomb susceptibility",
        }

        for lib in libraries:
            for dangerous, message in dangerous_libs.items():
                if dangerous in lib.lower():
                    findings.append(
                        self.create_finding(
                            app=app,
                            title=f"Security-Sensitive Library Linked: {dangerous}",
                            description=message,
                            severity="info",
                            category="Dependencies",
                            impact="Using this library requires careful implementation to "
                            "avoid common security pitfalls.",
                            remediation="Review usage of this library and implement security "
                            "best practices for it.",
                            file_path=lib,
                            poc_evidence=f"Library {dangerous} is linked",
                            poc_verification="1. Run otool -L on binary\n2. Check linked libraries",
                            poc_commands=[
                                f"otool -L /tmp/extracted/Payload/*.app/{binary_name}",
                            ],
                            owasp_masvs_category="MASVS-CODE",
                        )
                    )

        # Check for PIE (Position Independent Executable)
        load_commands = otool_result.get("load_commands", "")
        if "PIE" not in load_commands and "MH_PIE" not in load_commands:
            findings.append(
                self.create_finding(
                    app=app,
                    title="Binary Not Compiled with PIE",
                    description="The binary was not compiled with Position Independent Executable "
                    "(PIE) flag, which is required for ASLR protection.",
                    severity="medium",
                    category="Binary Protection",
                    impact="Without PIE, ASLR (Address Space Layout Randomization) cannot "
                    "fully protect the application, making exploitation easier.",
                    remediation="Recompile the application with PIE enabled. In Xcode, ensure "
                    "'Generate Position-Dependent Code' is set to NO.",
                    file_path=f"Payload/*.app/{binary_name}",
                    code_snippet="# Check for PIE flag:\notool -hv binary | grep PIE\n# Should show: PIE",
                    poc_evidence="PIE flag not found in Mach-O header",
                    poc_verification="1. Run otool -hv on binary\n2. Check for PIE flag in output",
                    poc_commands=[
                        f"otool -hv /tmp/extracted/Payload/*.app/{binary_name} | grep PIE",
                    ],
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-4",
                )
            )

        # Check for stack canaries
        if "__stack_chk_guard" not in load_commands and "_stack_chk" not in str(libraries):
            findings.append(
                self.create_finding(
                    app=app,
                    title="Stack Canaries May Not Be Enabled",
                    description="The binary may not have stack canaries enabled, which help "
                    "protect against buffer overflow attacks.",
                    severity="medium",
                    category="Binary Protection",
                    impact="Without stack canaries, buffer overflow vulnerabilities are easier "
                    "to exploit for arbitrary code execution.",
                    remediation="Ensure the app is compiled with -fstack-protector-all flag.",
                    file_path=f"Payload/*.app/{binary_name}",
                    code_snippet="# Check for stack canaries:\nnm binary | grep stack_chk\n# Should find: ___stack_chk_guard",
                    poc_evidence="Stack canary symbols not found",
                    poc_verification="1. Run nm on binary\n2. Search for stack_chk symbols",
                    poc_commands=[
                        f"nm /tmp/extracted/Payload/*.app/{binary_name} | grep stack_chk",
                    ],
                    owasp_masvs_category="MASVS-CODE",
                    owasp_masvs_control="MASVS-CODE-4",
                )
            )

        return findings

    def _analyze_symbols(self, app: MobileApp, nm_result: dict[str, Any], binary_path: str) -> list[Finding]:
        """Analyze binary symbols for security issues"""
        findings: list[Finding] = []
        binary_name = Path(binary_path).name

        symbols = nm_result.get("symbols", [])
        symbols_lower = [s.lower() for s in symbols]

        # Check for insecure functions
        for func, description in self.INSECURE_FUNCTIONS:
            if func.lower() in symbols_lower:
                findings.append(
                    self.create_finding(
                        app=app,
                        title=f"Insecure Function Used: {func}",
                        description=description,
                        severity="medium",
                        category="Code Security",
                        impact="Using insecure functions can lead to buffer overflows, "
                        "format string vulnerabilities, or information disclosure.",
                        remediation=f"Replace {func} with a safer alternative. For string "
                        f"operations, use strlcpy, strlcat, or snprintf.",
                        file_path=f"Payload/*.app/{binary_name}",
                        code_snippet=f"// Insecure function {func} found\n// Replace with safe alternative",
                        poc_evidence=f"Symbol {func} found in binary",
                        poc_verification=f"1. Run nm on binary\n2. Search for {func}",
                        poc_commands=[
                            f"nm /tmp/extracted/Payload/*.app/{binary_name} | grep -i '{func}'",
                        ],
                        owasp_masvs_category="MASVS-CODE",
                        owasp_masvs_control="MASVS-CODE-4",
                    )
                )

        # Check for anti-debugging
        anti_debug_found = []
        for pattern in self.ANTI_DEBUG_PATTERNS:
            if pattern.lower() in symbols_lower:
                anti_debug_found.append(pattern)

        if anti_debug_found:
            findings.append(
                self.create_finding(
                    app=app,
                    title="Anti-Debugging Mechanisms Detected",
                    description=f"The application implements anti-debugging techniques using "
                    f"functions: {', '.join(anti_debug_found)}",
                    severity="info",
                    category="Anti-Tampering",
                    impact="Anti-debugging can be bypassed by skilled attackers but adds "
                    "complexity to dynamic analysis.",
                    remediation="Consider implementing multiple anti-debugging methods and "
                    "using obfuscation to make bypassing more difficult.",
                    file_path=f"Payload/*.app/{binary_name}",
                    code_snippet=f"// Anti-debug functions found:\n{chr(10).join(anti_debug_found)}",
                    poc_evidence=f"Anti-debug functions: {', '.join(anti_debug_found)}",
                    poc_verification="1. Run nm on binary\n2. Search for ptrace, sysctl symbols",
                    poc_commands=[
                        f"nm /tmp/extracted/Payload/*.app/{binary_name} | grep -E 'ptrace|sysctl'",
                        "# Bypass with Frida: frida -U -l anti_debug_bypass.js <app>",
                    ],
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-2",
                )
            )

        # Security functions used (positive indicator)
        security_funcs = nm_result.get("security_functions", [])
        if security_funcs:
            findings.append(
                self.create_finding(
                    app=app,
                    title="Security APIs Used",
                    description=f"The application uses iOS security APIs: "
                    f"{', '.join(security_funcs[:10])}",
                    severity="info",
                    category="Cryptography",
                    impact="Usage of security APIs is positive but requires proper implementation.",
                    remediation="Verify that security APIs are used correctly with proper "
                    "key management and secure defaults.",
                    file_path=f"Payload/*.app/{binary_name}",
                    poc_evidence=f"Security APIs: {', '.join(security_funcs[:5])}",
                    owasp_masvs_category="MASVS-CRYPTO",
                )
            )

        return findings

    def _analyze_class_dump(self, app: MobileApp, class_dump: dict[str, Any], binary_path: str) -> list[Finding]:
        """Analyze class-dump output for security issues"""
        findings: list[Finding] = []
        binary_name = Path(binary_path).name

        classes = class_dump.get("classes", [])
        raw_output = class_dump.get("raw_output", "")

        # Check for sensitive data handling classes
        sensitive_classes = [
            ("Keychain", "Keychain usage detected - verify proper implementation"),
            ("Password", "Password handling class detected"),
            ("Credential", "Credential handling class detected"),
            ("Encryption", "Custom encryption class detected"),
            ("Crypto", "Cryptography class detected"),
        ]

        for pattern, message in sensitive_classes:
            matching = [c for c in classes if pattern.lower() in c.lower()]
            if matching:
                findings.append(
                    self.create_finding(
                        app=app,
                        title=f"Sensitive Data Handling: {pattern}",
                        description=f"{message}. Classes: {', '.join(matching[:5])}",
                        severity="info",
                        category="Data Handling",
                        impact="Review these classes to ensure sensitive data is handled securely.",
                        remediation="Audit the implementation of these classes for security issues.",
                        file_path=f"Payload/*.app/{binary_name}",
                        code_snippet=f"// Classes containing '{pattern}':\n{chr(10).join(matching[:5])}",
                        poc_evidence=f"Sensitive classes: {', '.join(matching[:5])}",
                        poc_verification="1. Run class-dump on binary\n2. Search for sensitive class names",
                        poc_commands=[
                            f"class-dump /tmp/extracted/Payload/*.app/{binary_name} | grep -i '{pattern}'",
                        ],
                        owasp_masvs_category="MASVS-STORAGE",
                    )
                )

        # Check for potential WebView usage
        webview_patterns = ["WKWebView", "UIWebView", "SFSafariViewController"]
        webviews = [c for c in classes if any(w in c for w in webview_patterns)]
        if webviews:
            has_uiwebview = any("UIWebView" in c for c in webviews)
            findings.append(
                self.create_finding(
                    app=app,
                    title="WebView Usage Detected",
                    description=f"The application uses WebView components: {', '.join(webviews)}",
                    severity="medium" if has_uiwebview else "info",
                    category="Web Security",
                    impact="WebViews can introduce XSS, JavaScript injection, and other "
                    "web-based vulnerabilities if not properly configured.",
                    remediation="Use WKWebView instead of UIWebView. Disable JavaScript if not "
                    "needed. Implement proper content security policies.",
                    file_path=f"Payload/*.app/{binary_name}",
                    code_snippet=f"// WebView classes found:\n{chr(10).join(webviews)}",
                    poc_evidence=f"WebView classes: {', '.join(webviews)}",
                    poc_verification="1. Run class-dump on binary\n2. Search for WebView classes\n3. Check for UIWebView (deprecated)",
                    poc_commands=[
                        f"class-dump /tmp/extracted/Payload/*.app/{binary_name} | grep -E 'WKWebView|UIWebView'",
                    ],
                    owasp_masvs_category="MASVS-PLATFORM",
                    owasp_masvs_control="MASVS-PLATFORM-2",
                )
            )

        return findings
