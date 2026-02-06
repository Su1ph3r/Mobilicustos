"""SSL/TLS certificate pinning analyzer for Android and iOS applications.

Examines application binaries for SSL/TLS certificate pinning implementations
and dangerous SSL bypass patterns. Supports both Android (DEX bytecode,
Network Security Config) and iOS (Mach-O binaries, frameworks).

Detection categories:
    - **Pinning implementations**: OkHttp CertificatePinner, Network Security
      Config ``<pin-set>``, TrustKit, custom TrustManager, Alamofire
      ServerTrustManager, URLSession delegate, SecTrust API.
    - **SSL bypass patterns** (CWE-295): TrustAllCerts, empty
      checkServerTrusted, SslErrorHandler.proceed, ALLOW_ALL_HOSTNAME_VERIFIER.
    - **Configuration issues**: Cleartext traffic permitted, user-installed
      certificates trusted.

OWASP references:
    - MASVS-NETWORK-1, MASVS-NETWORK-2
    - MASTG-TEST-0021, MASTG-TEST-0022, MASTG-TEST-0068
    - CWE-295: Improper Certificate Validation
    - CWE-319: Cleartext Transmission of Sensitive Information
"""

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class SSLPinningAnalyzer(BaseAnalyzer):
    """Analyzes SSL/TLS pinning implementation and detects SSL bypass code.

    Scans application binaries and configuration files for certificate
    pinning implementations (positive security control) and SSL validation
    bypass patterns (critical vulnerability). Produces both informational
    findings for detected pinning and vulnerability findings for missing
    or bypassed certificate validation.

    Class-level pattern dictionaries define known pinning libraries and
    bypass patterns for both Android and iOS platforms.

    Attributes:
        name: Analyzer identifier (``"ssl_pinning_analyzer"``).
        platform: Target platform (``"cross-platform"``).
        ANDROID_PINNING_PATTERNS: Regex patterns for Android pinning libraries.
        IOS_PINNING_PATTERNS: Regex patterns for iOS pinning libraries.
        BYPASS_PATTERNS: Regex patterns for SSL validation bypass code.
    """

    name = "ssl_pinning_analyzer"
    platform = "cross-platform"

    # Android pinning patterns
    ANDROID_PINNING_PATTERNS = {
        "okhttp_certificate_pinner": {
            "pattern": r"CertificatePinner\.Builder\(\)",
            "description": "OkHttp CertificatePinner",
            "strong": True,
        },
        "okhttp_pin_add": {
            "pattern": r'\.add\(["\'][^"\']+["\'],\s*["\']sha256/',
            "description": "OkHttp pin configuration",
            "strong": True,
        },
        "network_security_config_pin": {
            "pattern": r"<pin-set",
            "description": "Network Security Config pinning",
            "strong": True,
        },
        "trustkit": {
            "pattern": r"TrustKit\.initSharedInstance",
            "description": "TrustKit library",
            "strong": True,
        },
        "custom_trust_manager": {
            "pattern": r"X509TrustManager|checkServerTrusted",
            "description": "Custom TrustManager (may bypass or implement pinning)",
            "strong": False,
        },
    }

    # iOS pinning patterns
    IOS_PINNING_PATTERNS = {
        "trustkit_ios": {
            "pattern": r"TrustKit\.initSharedInstance|TrustKit\.setLoggerBlock",
            "description": "TrustKit library",
            "strong": True,
        },
        "alamofire_pinning": {
            "pattern": r"ServerTrustManager|PinnedCertificatesTrustEvaluator",
            "description": "Alamofire ServerTrustManager",
            "strong": True,
        },
        "urlsession_delegate": {
            "pattern": r"urlSession.*didReceive.*challenge.*completionHandler",
            "description": "URLSession authentication challenge handler",
            "strong": False,
        },
        "sec_trust": {
            "pattern": r"SecTrustEvaluate|SecTrustSetAnchorCertificates",
            "description": "Security framework trust evaluation",
            "strong": False,
        },
        "public_key_pinning": {
            "pattern": r"SecCertificateCopyPublicKey|SecKeyCopyExternalRepresentation",
            "description": "Public key extraction (potential pinning)",
            "strong": False,
        },
    }

    # Bypass indicators
    BYPASS_PATTERNS = {
        "trust_all_certs": {
            "pattern": r"TrustAllCerts|TrustAll|AllowAllHostnameVerifier",
            "description": "Trust-all implementation",
            "severity": "critical",
        },
        "empty_trust_manager": {
            "pattern": r"checkServerTrusted[^}]*\{\s*\}|checkServerTrusted[^}]*\{\s*//|checkServerTrusted[^}]*\{\s*return\s*;?\s*\}",
            "description": "Empty checkServerTrusted",
            "severity": "critical",
        },
        "proceed_ssl_error": {
            "pattern": r"handler\.proceed\(\)|SslErrorHandler.*proceed",
            "description": "SSL error proceed (WebView)",
            "severity": "critical",
        },
        "allow_all_hostname": {
            "pattern": r"ALLOW_ALL_HOSTNAME_VERIFIER|verify.*return\s*true",
            "description": "Hostname verification bypass",
            "severity": "critical",
        },
    }

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze the application for SSL/TLS pinning and bypass patterns.

        Dispatches to platform-specific analysis (Android or iOS) based on
        the app's platform field.

        Args:
            app: MobileApp ORM model with ``file_path`` and ``platform`` set.

        Returns:
            List of Finding objects including both positive (pinning found)
            and negative (no pinning or bypass detected) findings.
        """
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            if app.platform == "android":
                findings.extend(await self._analyze_android(app))
            elif app.platform == "ios":
                findings.extend(await self._analyze_ios(app))

        except Exception as e:
            logger.error(f"SSL pinning analysis failed: {e}")

        return findings

    async def _analyze_android(self, app: MobileApp) -> list[Finding]:
        """Analyze an Android APK for SSL pinning implementations and bypasses.

        Checks Network Security Config XML, scans DEX bytecode for pinning
        library patterns and SSL bypass patterns, and produces a summary
        finding indicating whether pinning was detected.
        """
        findings: list[Finding] = []
        pinning_found = False
        bypass_found = False
        pinning_details: list[str] = []
        bypass_details: list[str] = []

        try:
            with zipfile.ZipFile(app.file_path, "r") as apk:
                # Check Network Security Config
                nsc_findings = await self._check_network_security_config(app, apk)
                findings.extend(nsc_findings)
                if any(f.title.startswith("SSL Pinning Configured") for f in nsc_findings):
                    pinning_found = True
                    pinning_details.append("Network Security Config")

                # Analyze DEX files for code patterns
                for name in apk.namelist():
                    if name.endswith(".dex"):
                        dex_data = apk.read(name)
                        dex_text = dex_data.decode("utf-8", errors="ignore").replace('\x00', '')

                        # Check for pinning patterns
                        for pattern_name, pattern_info in self.ANDROID_PINNING_PATTERNS.items():
                            if re.search(pattern_info["pattern"], dex_text):
                                pinning_found = True
                                pinning_details.append(pattern_info["description"])

                        # Check for bypass patterns
                        for pattern_name, pattern_info in self.BYPASS_PATTERNS.items():
                            match = re.search(pattern_info["pattern"], dex_text, re.IGNORECASE | re.DOTALL)
                            if match:
                                bypass_found = True
                                bypass_details.append(pattern_info["description"])
                                # Extract context around the match
                                start = max(0, match.start() - 100)
                                end = min(len(dex_text), match.end() + 100)
                                matched_context = dex_text[start:end].strip()
                                findings.append(self._create_bypass_finding(
                                    app, pattern_name, pattern_info, name, matched_context
                                ))

        except Exception as e:
            logger.error(f"Android SSL pinning analysis failed: {e}")

        # Create summary finding
        if not pinning_found and not bypass_found:
            findings.append(self.create_finding(
                app=app,
                title="SSL/TLS Certificate Pinning Not Detected",
                severity="medium",
                category="Network Security",
                description=(
                    "No SSL/TLS certificate pinning implementation was detected in the "
                    "application. Without pinning, the app trusts any certificate signed "
                    "by a trusted CA, making it vulnerable to man-in-the-middle attacks "
                    "if a CA is compromised or if a user installs a malicious root certificate."
                ),
                impact=(
                    "Attackers with network access can intercept HTTPS traffic using a "
                    "proxy with a trusted certificate (corporate proxy, compromised CA, "
                    "or user-installed certificate on older Android versions)."
                ),
                remediation=(
                    "Implement certificate pinning using one of these methods:\n"
                    "1. Network Security Config (Android 7+): Add <pin-set> for your domains\n"
                    "2. OkHttp CertificatePinner: Pin to public key hash\n"
                    "3. TrustKit: Cross-platform pinning library"
                ),
                file_path="N/A",
                cwe_id="CWE-295",
                cwe_name="Improper Certificate Validation",
                cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                owasp_masvs_category="MASVS-NETWORK",
                owasp_masvs_control="MASVS-NETWORK-2",
                owasp_mastg_test="MASTG-TEST-0021",
                poc_commands=[
                    {
                        "type": "bash",
                        "command": f"grep -rn 'CertificatePinner\\|pin-set' /tmp/out/",
                        "description": "Search for pinning implementation",
                    },
                    {
                        "type": "bash",
                        "command": "mitmproxy -p 8080",
                        "description": "Test with mitmproxy - if traffic is intercepted, no effective pinning",
                    },
                ],
                poc_frida_script='''// Test SSL pinning
Java.perform(function() {
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[*] OkHttp CertificatePinner.check: " + hostname);
            // Comment out below to bypass pinning for testing
            // return;
            return this.check(hostname, peerCertificates);
        };
    } catch(e) {
        console.log("[-] OkHttp not found or different version");
    }
});
''',
                remediation_code={
                    "network_security_config": '''<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <pin digest="SHA-256">base64EncodedPublicKeyHash=</pin>
            <pin digest="SHA-256">backupPin=</pin>
        </pin-set>
    </domain-config>
</network-security-config>''',
                    "okhttp": '''CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build();

OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build();''',
                },
                remediation_resources=[
                    {
                        "title": "OWASP MASTG - Testing Custom Certificate Validation",
                        "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0021/",
                        "type": "documentation",
                    },
                    {
                        "title": "Android Developer - Network Security Config",
                        "url": "https://developer.android.com/training/articles/security-config",
                        "type": "documentation",
                    },
                ],
            ))
        elif pinning_found:
            findings.append(self.create_finding(
                app=app,
                title=f"SSL Pinning Detected: {', '.join(set(pinning_details))}",
                severity="info",
                category="Network Security",
                description=(
                    f"SSL/TLS certificate pinning implementation detected using: "
                    f"{', '.join(set(pinning_details))}. "
                    "This is a positive security control that helps prevent "
                    "man-in-the-middle attacks."
                ),
                impact="Positive finding - pinning provides additional protection against MITM attacks.",
                remediation="Ensure pins are kept up-to-date with certificate rotation schedules.",
                file_path="N/A",
                owasp_masvs_category="MASVS-NETWORK",
                owasp_masvs_control="MASVS-NETWORK-2",
            ))

        return findings

    async def _check_network_security_config(
        self,
        app: MobileApp,
        apk: zipfile.ZipFile,
    ) -> list[Finding]:
        """Check Android Network Security Config XML for pinning and misconfigurations.

        Parses ``network_security_config.xml`` for ``<pin-set>`` elements
        (positive), ``cleartextTrafficPermitted="true"`` (critical), and
        ``<certificates src="user">`` (medium risk).
        """
        findings = []

        try:
            # Look for network_security_config.xml
            for name in apk.namelist():
                if "network_security_config" in name.lower() and name.endswith(".xml"):
                    config_data = apk.read(name)
                    config_text = config_data.decode("utf-8", errors="ignore")

                    # Check for pin-set
                    if "<pin-set" in config_text:
                        # Extract pinned domains
                        domain_matches = re.findall(
                            r'<domain[^>]*>([^<]+)</domain>', config_text
                        )
                        pin_matches = re.findall(
                            r'<pin digest="([^"]+)">([^<]+)</pin>', config_text
                        )

                        findings.append(self.create_finding(
                            app=app,
                            title="SSL Pinning Configured in Network Security Config",
                            severity="info",
                            category="Network Security",
                            description=(
                                f"Certificate pinning configured for domains: "
                                f"{', '.join(domain_matches) if domain_matches else 'unknown'}. "
                                f"Found {len(pin_matches)} pin(s) configured."
                            ),
                            impact="Positive - Network Security Config pinning provides protection against MITM.",
                            remediation="Ensure backup pins are configured and pins are rotated before certificate expiry.",
                            file_path=name,
                            code_snippet=config_text[:500] if len(config_text) > 500 else config_text,
                            owasp_masvs_category="MASVS-NETWORK",
                        ))

                    # Check for cleartext traffic
                    if 'cleartextTrafficPermitted="true"' in config_text:
                        findings.append(self.create_finding(
                            app=app,
                            title="Cleartext Traffic Permitted in Network Security Config",
                            severity="high",
                            category="Network Security",
                            description="Network Security Config allows cleartext (HTTP) traffic.",
                            impact="Network traffic can be intercepted without SSL.",
                            remediation='Set cleartextTrafficPermitted="false".',
                            file_path=name,
                            code_snippet='cleartextTrafficPermitted="true"',
                            cwe_id="CWE-319",
                            cwe_name="Cleartext Transmission of Sensitive Information",
                            owasp_masvs_category="MASVS-NETWORK",
                        ))

                    # Check for user certificates trusted
                    if '<certificates src="user"' in config_text:
                        findings.append(self.create_finding(
                            app=app,
                            title="User-Installed Certificates Trusted",
                            severity="medium",
                            category="Network Security",
                            description=(
                                "Network Security Config trusts user-installed CA certificates. "
                                "This allows easier interception of HTTPS traffic."
                            ),
                            impact="User or MDM-installed certificates can intercept app traffic.",
                            remediation='Remove <certificates src="user"> from trust-anchors.',
                            file_path=name,
                            code_snippet='<certificates src="user"',
                            cwe_id="CWE-295",
                            cwe_name="Improper Certificate Validation",
                            owasp_masvs_category="MASVS-NETWORK",
                        ))

        except Exception as e:
            logger.error(f"Network security config analysis failed: {e}")

        return findings

    async def _analyze_ios(self, app: MobileApp) -> list[Finding]:
        """Analyze an iOS IPA for SSL pinning implementations.

        Scans Mach-O binaries and embedded frameworks for pinning library
        references (TrustKit, Alamofire, URLSession delegates, SecTrust API).
        """
        findings: list[Finding] = []
        pinning_found = False
        bypass_found = False
        pinning_details: list[str] = []

        try:
            with zipfile.ZipFile(app.file_path, "r") as ipa:
                # Analyze binary and frameworks
                for name in ipa.namelist():
                    if name.endswith((".framework", ".dylib")) or "/Payload/" in name:
                        try:
                            file_data = ipa.read(name)
                            file_text = file_data.decode("utf-8", errors="ignore")

                            # Check for pinning patterns
                            for pattern_name, pattern_info in self.IOS_PINNING_PATTERNS.items():
                                if re.search(pattern_info["pattern"], file_text, re.IGNORECASE):
                                    pinning_found = True
                                    pinning_details.append(pattern_info["description"])

                        except Exception:
                            continue

        except Exception as e:
            logger.error(f"iOS SSL pinning analysis failed: {e}")

        # Create summary finding
        if not pinning_found:
            findings.append(self.create_finding(
                app=app,
                title="SSL/TLS Certificate Pinning Not Detected",
                severity="medium",
                category="Network Security",
                description=(
                    "No SSL/TLS certificate pinning implementation was detected in the "
                    "iOS application. Without pinning, HTTPS traffic can be intercepted "
                    "if a root certificate is installed on the device."
                ),
                impact="Traffic can be intercepted using corporate proxies or user-installed certificates.",
                remediation=(
                    "Implement certificate pinning using:\n"
                    "1. TrustKit library\n"
                    "2. Alamofire ServerTrustManager\n"
                    "3. URLSession authentication challenge delegate"
                ),
                file_path="N/A",
                cwe_id="CWE-295",
                cwe_name="Improper Certificate Validation",
                cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                owasp_masvs_category="MASVS-NETWORK",
                owasp_masvs_control="MASVS-NETWORK-2",
                owasp_mastg_test="MASTG-TEST-0068",
                poc_commands=[
                    {
                        "type": "bash",
                        "command": "strings binary | grep -i 'TrustKit\\|ServerTrustManager'",
                        "description": "Search for pinning libraries",
                    },
                ],
                poc_frida_script='''// Test iOS SSL pinning
if (ObjC.available) {
    var TrustKit = ObjC.classes.TrustKit;
    if (TrustKit) {
        console.log("[*] TrustKit detected");
    }

    // Hook URLSession challenge handler
    var NSURLSession = ObjC.classes.NSURLSession;
    Interceptor.attach(NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
        onEnter: function(args) {
            console.log("[*] NSURLSession request");
        }
    });
}
''',
                remediation_code={
                    "trustkit": '''// Configure TrustKit
let trustKitConfig = [
    kTSKSwizzleNetworkDelegates: false,
    kTSKPinnedDomains: [
        "api.example.com": [
            kTSKEnforcePinning: true,
            kTSKPublicKeyHashes: [
                "base64PublicKeyHash1=",
                "base64PublicKeyHash2="
            ]
        ]
    ]
]
TrustKit.initSharedInstance(withConfiguration: trustKitConfig)''',
                },
                remediation_resources=[
                    {
                        "title": "OWASP MASTG - iOS Testing Custom Certificate Validation",
                        "url": "https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/MASTG-TEST-0068/",
                        "type": "documentation",
                    },
                    {
                        "title": "TrustKit Documentation",
                        "url": "https://github.com/datatheorem/TrustKit",
                        "type": "documentation",
                    },
                ],
            ))
        elif pinning_found:
            findings.append(self.create_finding(
                app=app,
                title=f"SSL Pinning Detected: {', '.join(set(pinning_details))}",
                severity="info",
                category="Network Security",
                description=f"SSL/TLS certificate pinning implementation detected: {', '.join(set(pinning_details))}.",
                impact="Positive finding - pinning provides protection against MITM attacks.",
                remediation="Ensure pins are kept up-to-date.",
                file_path="N/A",
                owasp_masvs_category="MASVS-NETWORK",
            ))

        return findings

    def _create_bypass_finding(
        self,
        app: MobileApp,
        pattern_name: str,
        pattern_info: dict[str, Any],
        file_path: str,
        matched_context: str = "",
    ) -> Finding:
        """Create a critical finding for detected SSL certificate validation bypass.

        Args:
            app: MobileApp ORM model for the scanned application.
            pattern_name: Internal pattern identifier (e.g., ``"trust_all_certs"``).
            pattern_info: Pattern dict with ``description`` and ``severity``.
            file_path: Archive-relative path where the bypass was found.
            matched_context: Code context around the matched bypass pattern.

        Returns:
            Finding ORM model for the SSL bypass vulnerability.
        """
        return self.create_finding(
            app=app,
            title=f"SSL Certificate Validation Bypass: {pattern_info['description']}",
            severity=pattern_info["severity"],
            category="Network Security",
            description=(
                f"The application contains code that bypasses SSL certificate validation: "
                f"{pattern_info['description']}. This completely disables transport security."
            ),
            impact=(
                "All HTTPS traffic can be intercepted using any certificate, including "
                "self-signed certificates. Complete loss of transport layer security."
            ),
            remediation=(
                "Remove SSL bypass code. Use proper certificate validation. If testing "
                "is needed, use build configurations to enable bypass only in debug builds."
            ),
            file_path=file_path,
            code_snippet=matched_context[:500] if matched_context else None,
            cwe_id="CWE-295",
            cwe_name="Improper Certificate Validation",
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            owasp_masvs_category="MASVS-NETWORK",
            owasp_masvs_control="MASVS-NETWORK-2",
            owasp_mastg_test="MASTG-TEST-0022",
            poc_evidence=f"Pattern '{pattern_info['description']}' matched in {file_path}",
            poc_verification=(
                "1. Extract the APK and decompile with jadx\n"
                "2. Search for the bypass pattern in decompiled source\n"
                "3. Set up mitmproxy with a self-signed certificate\n"
                "4. Verify the app accepts the proxy certificate without errors"
            ),
            poc_commands=[
                {
                    "type": "bash",
                    "command": f"jadx -d /tmp/out {app.file_path or 'app.apk'} && grep -rn '{pattern_info['pattern'][:60]}' /tmp/out/",
                    "description": f"Decompile and search for {pattern_info['description']}",
                },
                {
                    "type": "bash",
                    "command": "mitmproxy -p 8080 --ssl-insecure",
                    "description": "Start mitmproxy to intercept HTTPS traffic",
                },
                {
                    "type": "adb",
                    "command": f"adb shell settings put global http_proxy 127.0.0.1:8080",
                    "description": "Configure device to use proxy",
                },
            ],
            poc_frida_script=f'''// Verify SSL bypass - hook the bypass pattern to confirm it executes
Java.perform(function() {{
    // Hook WebViewClient.onReceivedSslError to detect proceed() calls
    try {{
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {{
            console.log("[!] SSL error handler called - bypass pattern: {pattern_info['description']}");
            console.log("[!] Error: " + error.toString());
            console.log("[!] URL: " + error.getUrl());
            this.onReceivedSslError(view, handler, error);
        }};
    }} catch(e) {{
        console.log("WebViewClient hook failed: " + e);
    }}
}});
''',
            remediation_code={
                "java": (
                    "// REMOVE the SSL bypass code and use proper validation:\n"
                    "@Override\n"
                    "public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {\n"
                    "    handler.cancel();  // Reject invalid certificates\n"
                    "}"
                ),
            },
        )
