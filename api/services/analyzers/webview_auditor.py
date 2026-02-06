"""WebView security auditor for Android and iOS mobile applications.

Performs static analysis of decompiled source code to detect WebView
security misconfigurations and vulnerabilities that can lead to code
injection, data theft, and man-in-the-middle attacks.

Security checks performed:
    Android WebView:
        - JavaScript enabled without trusted content sources
        - JavaScript interface (addJavascriptInterface) exposure -- RCE
          risk on Android < 4.2 (API 17)
        - File access (setAllowFileAccess, setAllowFileAccessFromFileURLs,
          setAllowUniversalAccessFromFileURLs)
        - Mixed content mode (HTTP/HTTPS content mixing)
        - WebView remote debugging enabled in production
        - Deprecated settings (setSavePassword, setPluginState)

    iOS WKWebView:
        - Deprecated UIWebView usage (iOS 12+)
        - JavaScript enabled and popup auto-open settings
        - File URL cross-origin access
        - Script message handler bridge security
        - evaluateJavaScript with unsanitized input

    SSL/TLS Bypass Detection:
        - onReceivedSslError with proceed() (Android)
        - Empty X509TrustManager (Android)
        - didReceive challenge with useCredential (iOS)
        - allowsAnyHTTPSCertificateForHost private API (iOS)

    JavaScript Bridge Security:
        - @JavascriptInterface annotated method exposure
        - evaluateJavascript with string concatenation (injection risk)
        - loadUrl with javascript: scheme (XSS vector)
        - loadDataWithBaseURL with untrusted base URL

    URL Handling:
        - Insecure scheme loading (http://, intent://, file://)
        - Intent-based URL loading (URL injection)
        - shouldOverrideUrlLoading returning false for all URLs

OWASP references:
    - MASVS-PLATFORM: Platform Interaction
    - MASVS-PLATFORM-2: WebView Security
    - MASVS-NETWORK: Network Communication
    - OWASP Mobile Top 10 M7: Client Code Quality
    - CWE-79: Cross-site Scripting (XSS)
    - CWE-295: Improper Certificate Validation
    - CWE-749: Exposed Dangerous Method or Function
    - CWE-346: Origin Validation Error
    - CWE-489: Active Debug Code
    - CWE-922: Insecure Storage of Sensitive Information
"""

import os
import re
import logging
from typing import Optional

from api.models.database import MobileApp, Finding
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class WebViewAuditor(BaseAnalyzer):
    """Analyzes WebView security in Android and iOS mobile applications.

    Extracts the application archive and scans decompiled source code
    for WebView configuration anti-patterns, SSL/TLS certificate
    validation bypasses, JavaScript bridge security issues, and
    dangerous URL handling patterns.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform ("cross-platform").
        ANDROID_WEBVIEW_ISSUES: Tuple patterns of (regex, name, severity,
            description) for Android WebView security settings.
        SSL_BYPASS_PATTERNS: Patterns for Android SSL validation bypass.
        IOS_WEBVIEW_ISSUES: Patterns for iOS WKWebView/UIWebView issues.
        IOS_SSL_BYPASS: Patterns for iOS SSL certificate bypass.
        JS_BRIDGE_PATTERNS: Patterns for JavaScript bridge exposure.
        DANGEROUS_URL_PATTERNS: Patterns for insecure URL loading.
    """

    name = "webview_auditor"
    platform = "cross-platform"

    # Android WebView security issues
    ANDROID_WEBVIEW_ISSUES = [
        # JavaScript enabled (check context)
        (r'setJavaScriptEnabled\s*\(\s*true\s*\)', "JavaScript enabled", "medium", "JavaScript is enabled in WebView. Ensure content sources are trusted."),

        # JavaScript interface - major risk
        (r'addJavascriptInterface\s*\(', "JavaScript interface exposed", "high", "JavaScript interface exposes native methods to JavaScript. On Android < 4.2, this allows arbitrary code execution."),

        # File access
        (r'setAllowFileAccess\s*\(\s*true\s*\)', "File access allowed", "medium", "WebView can access local files. This may allow reading sensitive app data."),
        (r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)', "File URL cross-origin allowed", "high", "File URLs can access other file URLs. This is a significant security risk."),
        (r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)', "Universal file access allowed", "critical", "File URLs can access content from any origin. This is extremely dangerous."),

        # Content access
        (r'setAllowContentAccess\s*\(\s*true\s*\)', "Content provider access allowed", "low", "WebView can access content providers. Review what content is exposed."),

        # Mixed content
        (r'setMixedContentMode\s*\(\s*(?:MIXED_CONTENT_ALWAYS_ALLOW|0)\s*\)', "Mixed content allowed", "medium", "Mixed HTTP/HTTPS content is allowed. This can enable MITM attacks."),

        # DOM storage
        (r'setDomStorageEnabled\s*\(\s*true\s*\)', "DOM storage enabled", "info", "DOM storage (localStorage) is enabled. Ensure sensitive data is not stored."),

        # Debugging
        (r'setWebContentsDebuggingEnabled\s*\(\s*true\s*\)', "WebView debugging enabled", "high", "WebView debugging is enabled. This should be disabled in production."),

        # Geolocation
        (r'setGeolocationEnabled\s*\(\s*true\s*\)', "Geolocation enabled", "low", "Geolocation is enabled. Ensure user consent is obtained."),

        # Plugins
        (r'setPluginState\s*\(\s*(?:WebSettings\.PluginState\.ON|ON_DEMAND)\s*\)', "Plugins enabled", "medium", "WebView plugins are enabled. This increases attack surface."),

        # Save password (deprecated but still seen)
        (r'setSavePassword\s*\(\s*true\s*\)', "Password saving enabled", "medium", "Password saving in WebView is enabled. This is deprecated and insecure."),

        # Form data
        (r'setSaveFormData\s*\(\s*true\s*\)', "Form data saving enabled", "low", "Form data saving is enabled. Sensitive data may be cached."),
    ]

    # SSL/TLS validation issues
    SSL_BYPASS_PATTERNS = [
        (r'onReceivedSslError[^}]*\.proceed\s*\(\s*\)', "SSL error bypassed", "critical", "SSL certificate errors are being ignored. This allows MITM attacks."),
        (r'SslErrorHandler.*\.proceed\s*\(\s*\)', "SSL handler proceeds on error", "critical", "SSL errors are ignored in WebViewClient. All certificate validation is bypassed."),
        (r'X509TrustManager[^}]*checkServerTrusted[^}]*\{\s*\}', "Empty SSL trust manager", "critical", "X509TrustManager has empty checkServerTrusted. All certificates are trusted."),
        (r'TrustManager[^}]*getAcceptedIssuers[^}]*return\s+null', "Trust all certificates", "critical", "TrustManager returns null accepted issuers. This trusts all certificates."),
    ]

    # iOS WKWebView issues
    IOS_WEBVIEW_ISSUES = [
        # JavaScript
        (r'javaScriptEnabled\s*=\s*true', "JavaScript enabled", "medium", "JavaScript is enabled in WKWebView. Ensure content sources are trusted."),
        (r'javaScriptCanOpenWindowsAutomatically\s*=\s*true', "JavaScript popups allowed", "low", "JavaScript can open windows automatically."),

        # File access
        (r'allowFileAccessFromFileURLs\s*=\s*true', "File URL cross-origin allowed", "high", "File URLs can access other file URLs in WKWebView."),
        (r'allowUniversalAccessFromFileURLs\s*=\s*true', "Universal file access allowed", "critical", "File URLs can access any origin in WKWebView."),

        # User scripts/message handlers (potential bridge issues)
        (r'addScriptMessageHandler', "Script message handler", "medium", "Native-to-JS bridge via message handlers. Verify input validation."),
        (r'evaluateJavaScript', "JavaScript evaluation", "medium", "JavaScript is being evaluated from native code. Ensure input is sanitized."),

        # Custom schemes
        (r'setURLSchemeHandler', "Custom URL scheme handler", "info", "Custom URL scheme handler registered. Review for security issues."),

        # Data detectors
        (r'dataDetectorTypes.*all', "All data detectors enabled", "low", "All data detectors enabled. Phone numbers, links, etc. become tappable."),
    ]

    # iOS SSL bypass patterns
    IOS_SSL_BYPASS = [
        (r'didReceive.*challenge.*completionHandler\(.*\.useCredential', "SSL challenge bypassed", "critical", "SSL certificate challenge is bypassed with useCredential."),
        (r'serverTrust.*SecTrustEvaluateWithError.*=\s*false', "Server trust evaluation failed but continued", "critical", "SSL trust evaluation failed but the app continues anyway."),
        (r'allowsAnyHTTPSCertificateForHost', "Allows any HTTPS certificate", "critical", "Private API to allow any HTTPS certificate is being used."),
    ]

    # JavaScript bridge security patterns
    JS_BRIDGE_PATTERNS = [
        (r'@JavascriptInterface', "JavaScript interface annotation", "high", "Method exposed to JavaScript via @JavascriptInterface. Review for sensitive operations."),
        (r'evaluateJavascript\s*\([^)]*\+', "JavaScript with concatenation", "high", "JavaScript evaluation uses string concatenation. Potential injection vulnerability."),
        (r'loadUrl\s*\(["\']javascript:', "loadUrl with javascript:", "high", "Using loadUrl with javascript: scheme. Ensure input is sanitized."),
        (r'loadDataWithBaseURL', "loadDataWithBaseURL", "medium", "Loading data with base URL. Verify the base URL is trusted."),
    ]

    # Dangerous URL patterns in WebView
    DANGEROUS_URL_PATTERNS = [
        (r'loadUrl\s*\([^)]*(?:http://|intent://|file://)', "Insecure URL loading", "high", "WebView loads URLs using insecure schemes (http, intent, file)."),
        (r'loadUrl\s*\([^)]*getIntent\(\)', "Intent URL loading", "high", "WebView loads URL from intent. This may allow URL injection."),
        (r'shouldOverrideUrlLoading.*return\s+false', "URL override returns false", "medium", "shouldOverrideUrlLoading returns false for all URLs. Review URL handling."),
    ]

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze the application for WebView security vulnerabilities.

        Args:
            app: The mobile application to analyze.

        Returns:
            A list of Finding objects covering WebView configuration,
            SSL bypass, JavaScript bridge, and URL handling issues.
        """
        if not app.file_path:
            return []

        import shutil
        import tempfile
        import zipfile

        extracted_path = None
        try:
            extracted_path = tempfile.mkdtemp(prefix="webview_audit_")
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            findings = []

            if app.platform == "android":
                findings.extend(await self._analyze_android_webview(app, extracted_path))
            elif app.platform == "ios":
                findings.extend(await self._analyze_ios_webview(app, extracted_path))

            # Common WebView analyses
            findings.extend(await self._analyze_ssl_bypass(app, extracted_path))
            findings.extend(await self._analyze_js_bridge(app, extracted_path))
            findings.extend(await self._analyze_url_handling(app, extracted_path))

            logger.info(f"WebViewAuditor found {len(findings)} issues in {app.app_id}")
            return findings

        except Exception as e:
            logger.error(f"Error in WebViewAuditor: {e}")
            return []
        finally:
            if extracted_path and os.path.exists(extracted_path):
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    async def _analyze_android_webview(self, app: MobileApp, extracted_path: str) -> list[Finding]:
        """Analyze Android WebView configuration for security issues.

        Scans Java/Kotlin/Smali source files that reference WebView,
        WebSettings, or WebViewClient for each pattern in
        ANDROID_WEBVIEW_ISSUES. Also checks for addJavascriptInterface
        exposure across all WebView files.

        Args:
            app: The mobile application being analyzed.
            extracted_path: Root directory of the extracted APK.

        Returns:
            A list of Finding objects for Android WebView issues.
        """
        findings = []

        source_dirs = [
            os.path.join(extracted_path, "sources"),
            os.path.join(extracted_path, "smali"),
            os.path.join(extracted_path, "java"),
        ]

        webview_files = []

        for source_dir in source_dirs:
            if not os.path.exists(source_dir):
                continue

            for root, _, files in os.walk(source_dir):
                for file in files:
                    if not file.endswith(('.java', '.kt', '.smali')):
                        continue

                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, extracted_path)

                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()

                        # Check if this file uses WebView
                        if not re.search(r'WebView|WebSettings|WebViewClient', content):
                            continue

                        webview_files.append(file_path)
                        lines = content.split('\n')

                        # Check each security issue pattern
                        for pattern, name, severity, description in self.ANDROID_WEBVIEW_ISSUES:
                            for match in re.finditer(pattern, content):
                                line_num = content[:match.start()].count('\n') + 1

                                findings.append(self._create_finding(
                                    app=app,
                                    title=f"WebView Security: {name}",
                                    description=description,
                                    severity=severity,
                                    category="MASVS-PLATFORM",
                                    file_path=relative_path,
                                    line_number=line_num,
                                    code_snippet=self._get_context(lines, line_num, 3),
                                    cwe_id=self._get_cwe_for_issue(name),
                                    owasp_category="M7",
                                ))

                    except Exception as e:
                        logger.debug(f"Error reading {file_path}: {e}")

        # Check for WebView without security settings
        if webview_files:
            has_ssl_check = False
            has_js_interface = False

            for file_path in webview_files:
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()

                    if re.search(r'onReceivedSslError|SslErrorHandler', content):
                        has_ssl_check = True
                    if re.search(r'addJavascriptInterface', content):
                        has_js_interface = True
                except:
                    pass

            if has_js_interface:
                findings.append(self._create_finding(
                    app=app,
                    title="JavaScript Interface Exposed to WebView",
                    description="The app exposes native methods to JavaScript via addJavascriptInterface. On Android versions below 4.2 (API 17), this allows remote code execution through JavaScript.",
                    severity="high",
                    category="MASVS-PLATFORM",
                    cwe_id="CWE-749",
                    owasp_category="M7",
                ))

        return findings

    async def _analyze_ios_webview(self, app: MobileApp, extracted_path: str) -> list[Finding]:
        """Analyze iOS WKWebView and UIWebView configuration.

        Detects deprecated UIWebView usage, checks WKWebView security
        settings, and scans for iOS-specific SSL bypass patterns.

        Args:
            app: The mobile application being analyzed.
            extracted_path: Root directory of the extracted IPA.

        Returns:
            A list of Finding objects for iOS WebView issues.
        """
        findings = []

        for root, _, files in os.walk(extracted_path):
            for file in files:
                if not file.endswith(('.m', '.swift', '.mm', '.h')):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, extracted_path)

                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()

                    # Check if this file uses WebView
                    if not re.search(r'WKWebView|UIWebView|WKWebViewConfiguration', content):
                        continue

                    lines = content.split('\n')

                    # Check for deprecated UIWebView
                    if re.search(r'UIWebView', content):
                        findings.append(self._create_finding(
                            app=app,
                            title="Deprecated UIWebView Usage",
                            description="The app uses the deprecated UIWebView class. UIWebView has known security vulnerabilities and has been deprecated since iOS 12. Migrate to WKWebView.",
                            severity="high",
                            category="MASVS-PLATFORM",
                            file_path=relative_path,
                            cwe_id="CWE-477",
                            owasp_category="M7",
                        ))

                    # Check each iOS WebView security issue
                    for pattern, name, severity, description in self.IOS_WEBVIEW_ISSUES:
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count('\n') + 1

                            findings.append(self._create_finding(
                                app=app,
                                title=f"WKWebView Security: {name}",
                                description=description,
                                severity=severity,
                                category="MASVS-PLATFORM",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=self._get_context(lines, line_num, 3),
                                cwe_id=self._get_cwe_for_issue(name),
                                owasp_category="M7",
                            ))

                    # Check iOS SSL bypass
                    for pattern, name, severity, description in self.IOS_SSL_BYPASS:
                        for match in re.finditer(pattern, content, re.DOTALL):
                            line_num = content[:match.start()].count('\n') + 1

                            findings.append(self._create_finding(
                                app=app,
                                title=f"SSL/TLS Bypass: {name}",
                                description=description,
                                severity=severity,
                                category="MASVS-NETWORK",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=self._get_context(lines, line_num, 5),
                                cwe_id="CWE-295",
                                owasp_category="M3",
                            ))

                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {e}")

        return findings

    async def _analyze_ssl_bypass(self, app: MobileApp, extracted_path: str) -> list[Finding]:
        """Analyze SSL/TLS certificate validation bypass in source code.

        Args:
            app: The mobile application being analyzed.
            extracted_path: Root directory of the extracted archive.

        Returns:
            A list of critical Finding objects for SSL bypass patterns.
        """
        findings = []

        extensions = ('.java', '.kt', '.smali') if app.platform == 'android' else ('.m', '.swift', '.mm')

        for root, _, files in os.walk(extracted_path):
            for file in files:
                if not file.endswith(extensions):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, extracted_path)

                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')

                    # Check SSL bypass patterns
                    patterns = self.SSL_BYPASS_PATTERNS if app.platform == 'android' else self.IOS_SSL_BYPASS

                    for pattern, name, severity, description in patterns:
                        for match in re.finditer(pattern, content, re.DOTALL | re.MULTILINE):
                            line_num = content[:match.start()].count('\n') + 1

                            findings.append(self._create_finding(
                                app=app,
                                title=f"SSL/TLS Vulnerability: {name}",
                                description=description,
                                severity=severity,
                                category="MASVS-NETWORK",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=self._get_context(lines, line_num, 5),
                                cwe_id="CWE-295",
                                owasp_category="M3",
                            ))

                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {e}")

        return findings

    async def _analyze_js_bridge(self, app: MobileApp, extracted_path: str) -> list[Finding]:
        """Analyze JavaScript bridge security for native-to-JS exposure.

        Args:
            app: The mobile application being analyzed.
            extracted_path: Root directory of the extracted archive.

        Returns:
            A list of Finding objects for JavaScript bridge issues.
        """
        findings = []

        extensions = ('.java', '.kt') if app.platform == 'android' else ('.m', '.swift')

        for root, _, files in os.walk(extracted_path):
            for file in files:
                if not file.endswith(extensions):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, extracted_path)

                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')

                    for pattern, name, severity, description in self.JS_BRIDGE_PATTERNS:
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count('\n') + 1

                            findings.append(self._create_finding(
                                app=app,
                                title=f"JavaScript Bridge: {name}",
                                description=description,
                                severity=severity,
                                category="MASVS-PLATFORM",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=self._get_context(lines, line_num, 3),
                                cwe_id="CWE-749",
                                owasp_category="M7",
                            ))

                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {e}")

        return findings

    async def _analyze_url_handling(self, app: MobileApp, extracted_path: str) -> list[Finding]:
        """Analyze URL handling in WebViews for insecure patterns.

        Detects insecure scheme loading (http://, intent://, file://),
        intent-based URL injection, and permissive URL override behavior.

        Args:
            app: The mobile application being analyzed.
            extracted_path: Root directory of the extracted archive.

        Returns:
            A list of Finding objects for URL handling issues.
        """
        findings = []

        extensions = ('.java', '.kt', '.smali') if app.platform == 'android' else ('.m', '.swift')

        for root, _, files in os.walk(extracted_path):
            for file in files:
                if not file.endswith(extensions):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, extracted_path)

                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')

                    for pattern, name, severity, description in self.DANGEROUS_URL_PATTERNS:
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count('\n') + 1

                            findings.append(self._create_finding(
                                app=app,
                                title=f"WebView URL Handling: {name}",
                                description=description,
                                severity=severity,
                                category="MASVS-PLATFORM",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=self._get_context(lines, line_num, 3),
                                cwe_id="CWE-79",
                                owasp_category="M7",
                            ))

                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {e}")

        return findings

    def _get_context(self, lines: list[str], line_num: int, context: int = 3) -> str:
        """Get code context around a line number."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)

        context_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            context_lines.append(f"{i + 1:4d}{prefix}{lines[i]}")

        return '\n'.join(context_lines)

    def _get_cwe_for_issue(self, issue_name: str) -> str:
        """Map WebView issue names to their corresponding CWE IDs.

        Args:
            issue_name: The short name of the WebView issue.

        Returns:
            The CWE identifier string (e.g., "CWE-79"). Falls back
            to "CWE-693" (Protection Mechanism Failure) for unknown issues.
        """
        cwe_map = {
            "JavaScript enabled": "CWE-79",
            "JavaScript interface exposed": "CWE-749",
            "JavaScript interface annotation": "CWE-749",
            "File access allowed": "CWE-200",
            "File URL cross-origin allowed": "CWE-346",
            "Universal file access allowed": "CWE-346",
            "Content provider access allowed": "CWE-200",
            "Mixed content allowed": "CWE-311",
            "DOM storage enabled": "CWE-922",
            "WebView debugging enabled": "CWE-489",
            "SSL error bypassed": "CWE-295",
            "SSL handler proceeds on error": "CWE-295",
            "SSL challenge bypassed": "CWE-295",
            "JavaScript with concatenation": "CWE-94",
            "loadUrl with javascript:": "CWE-94",
            "Insecure URL loading": "CWE-319",
            "Intent URL loading": "CWE-926",
            "Password saving enabled": "CWE-312",
            "Form data saving enabled": "CWE-312",
        }
        return cwe_map.get(issue_name, "CWE-693")

    def _create_finding(
        self,
        app: MobileApp,
        title: str,
        description: str,
        severity: str,
        category: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        code_snippet: Optional[str] = None,
        cwe_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
    ) -> Finding:
        """Create a security finding using BaseAnalyzer.create_finding."""
        severity_cvss_map = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.5,
            "info": 0.0,
        }

        return self.create_finding(
            app=app,
            title=title,
            description=description,
            severity=severity,
            category=category,
            impact="WebView security misconfigurations can lead to code injection, data theft, or MITM attacks.",
            remediation="Review WebView security settings and ensure proper content validation.",
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=cwe_id,
            cvss_score=severity_cvss_map.get(severity, 0.0),
            owasp_masvs_category="MASVS-PLATFORM",
            owasp_masvs_control="MASVS-PLATFORM-2",
        )
