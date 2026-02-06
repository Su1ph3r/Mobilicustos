"""Runtime analyzer — Frida-based dynamic analysis of running apps."""

import asyncio
import logging
import subprocess
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

# Frida script that hooks security-relevant APIs and reports back
RUNTIME_HOOKS_SCRIPT = r"""
'use strict';

var findings = [];

function reportFinding(category, title, severity, detail) {
    findings.push({category: category, title: title, severity: severity, detail: detail});
    send({type: 'finding', category: category, title: title, severity: severity, detail: detail});
}

// ---- Root Detection Hooks ----
Java.perform(function() {

    // 1. Check if app probes for 'su' binary (root detection)
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
                reportFinding('Root Detection', 'Root detection via Runtime.exec',
                    'info', 'App executes: ' + cmd);
            }
            return this.exec(cmd);
        };
    } catch(e) {}

    // 2. Check File.exists for root indicator paths
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var rootPaths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
                             '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
                             '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su',
                             '/su/bin/su', '/magisk'];
            for (var i = 0; i < rootPaths.length; i++) {
                if (path.indexOf(rootPaths[i]) !== -1) {
                    reportFinding('Root Detection', 'Root detection via File.exists',
                        'info', 'App checks path: ' + path);
                }
            }
            return this.exists();
        };
    } catch(e) {}

    // ---- SSL Pinning Detection ----
    // 3. OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCerts) {
            reportFinding('SSL Pinning', 'SSL certificate pinning detected (OkHttp)',
                'info', 'Pinning check for host: ' + hostname);
            return this.check(hostname, peerCerts);
        };
    } catch(e) {}

    // 4. TrustManagerFactory with null KeyStore
    try {
        var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        TrustManagerFactory.init.overload('java.security.KeyStore').implementation = function(ks) {
            if (ks === null) {
                reportFinding('SSL/TLS', 'TrustManager initialized with null KeyStore',
                    'high', 'App initializes TrustManagerFactory with null KeyStore - trusts all certificates');
            }
            return this.init(ks);
        };
    } catch(e) {}

    // ---- Crypto Usage ----
    // 5. Cipher.getInstance - detect weak algorithms
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
            var t = transformation.toUpperCase();
            if (t.indexOf('ECB') !== -1) {
                reportFinding('Cryptography', 'Weak cipher mode: ECB detected at runtime',
                    'high', 'Cipher.getInstance("' + transformation + '") - ECB mode lacks diffusion');
            }
            if (t.indexOf('DES') !== -1 && t.indexOf('3DES') === -1 && t.indexOf('DESEDE') === -1) {
                reportFinding('Cryptography', 'Weak cipher: DES detected at runtime',
                    'high', 'Cipher.getInstance("' + transformation + '") - DES has 56-bit key');
            }
            if (t.indexOf('RC4') !== -1) {
                reportFinding('Cryptography', 'Weak cipher: RC4 detected at runtime',
                    'high', 'Cipher.getInstance("' + transformation + '") - RC4 is broken');
            }
            return this.getInstance(transformation);
        };
    } catch(e) {}

    // 6. SecureRandom manual seeding
    try {
        var SecureRandom = Java.use('java.security.SecureRandom');
        SecureRandom.setSeed.overload('[B').implementation = function(seed) {
            reportFinding('Cryptography', 'SecureRandom manually seeded',
                'medium', 'App calls SecureRandom.setSeed() with ' + seed.length + ' byte seed');
            return this.setSeed(seed);
        };
    } catch(e) {}

    // ---- Clipboard ----
    // 7. ClipboardManager
    try {
        var ClipboardManager = Java.use('android.content.ClipboardManager');
        ClipboardManager.setPrimaryClip.implementation = function(clip) {
            var text = '';
            try { text = clip.getItemAt(0).getText().toString(); } catch(e) {}
            reportFinding('Data Leakage', 'Data written to clipboard at runtime',
                'medium', 'App copies data to clipboard: "' + text.substring(0, 80) + '..."');
            return this.setPrimaryClip(clip);
        };
    } catch(e) {}

    // ---- Logging ----
    // 8. Detect excessive logging
    try {
        var logCount = {d: 0, v: 0, i: 0};
        var Log = Java.use('android.util.Log');
        ['d', 'v', 'i'].forEach(function(level) {
            try {
                Log[level].overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
                    logCount[level]++;
                    if (logCount[level] === 20) {
                        reportFinding('Data Leakage', 'Excessive runtime logging detected (Log.' + level + ')',
                            'low', 'App has made 20+ Log.' + level + '() calls - may leak sensitive data to logcat');
                    }
                    return this[level](tag, msg);
                };
            } catch(e) {}
        });
    } catch(e) {}

    // ---- WebView ----
    // 9. JavaScript interface exposure
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.addJavascriptInterface.implementation = function(obj, name) {
            reportFinding('WebView', 'JavaScript interface exposed in WebView',
                'high', 'WebView.addJavascriptInterface() - interface name: "' + name + '"');
            return this.addJavascriptInterface(obj, name);
        };
    } catch(e) {}

    // ---- SharedPreferences ----
    // 10. Detect MODE_WORLD_READABLE / MODE_WORLD_WRITABLE
    try {
        var Context = Java.use('android.content.Context');
        Context.getSharedPreferences.overload('java.lang.String', 'int').implementation = function(name, mode) {
            if (mode === 1 || mode === 2) {
                reportFinding('Data Storage', 'World-readable/writable SharedPreferences',
                    'high', 'getSharedPreferences("' + name + '", mode=' + mode + ') - insecure file mode');
            }
            return this.getSharedPreferences(name, mode);
        };
    } catch(e) {}

    send({type: 'hooks_ready', count: 10});
});

setTimeout(function() {
    send({type: 'collection_done', findings: findings});
}, 25000);
"""


class RuntimeAnalyzer(BaseAnalyzer):
    """Dynamic runtime analyzer using Frida instrumentation."""

    name = "runtime_analyzer"
    platform = "android"

    def __init__(self, device_id: str | None = None):
        self.device_id = device_id

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Run Frida-based runtime analysis on the app."""
        findings: list[Finding] = []

        if not app.package_name:
            logger.warning("No package_name on app - skipping runtime analysis")
            return findings

        device_id = self.device_id or await self._find_device()
        if not device_id:
            logger.error("No connected Android device found for runtime analysis")
            return findings

        logger.info(f"Starting runtime analysis of {app.package_name} on device {device_id}")

        try:
            import frida
            from api.config import get_settings

            # Get device — prefer TCP tunnel (required in Docker), fall back to USB
            frida_host = get_settings().frida_server_host
            if frida_host:
                device = frida.get_device_manager().add_remote_device(frida_host)
            elif ":" in device_id:
                device = frida.get_device_manager().add_remote_device(device_id)
            else:
                device = frida.get_usb_device(timeout=10)

            # Spawn the app
            logger.info(f"Spawning {app.package_name}")
            pid = await asyncio.wait_for(
                asyncio.to_thread(device.spawn, [app.package_name]),
                timeout=30,
            )

            session = await asyncio.wait_for(
                asyncio.to_thread(device.attach, pid),
                timeout=15,
            )

            # Inject hooks
            messages: list[dict] = []

            def on_message(message: dict, data: Any):
                if message.get("type") == "send":
                    messages.append(message["payload"])
                elif message.get("type") == "error":
                    logger.warning(f"Frida script error: {message.get('description', '')}")

            script = session.create_script(RUNTIME_HOOKS_SCRIPT)
            script.on("message", on_message)
            await asyncio.to_thread(script.load)

            # Resume app so it runs with hooks active
            await asyncio.to_thread(device.resume, pid)

            # Wait for hooks to collect data
            logger.info("Waiting for runtime hooks to collect data (30s)...")
            await asyncio.sleep(30)

            # Cleanup
            try:
                await asyncio.to_thread(script.unload)
                await asyncio.to_thread(session.detach)
                await asyncio.to_thread(device.kill, pid)
            except Exception:
                pass

            # Convert Frida messages to Finding objects
            findings = self._process_messages(messages, app)
            logger.info(f"Runtime analysis produced {len(findings)} findings")

            # Meta-finding if no issues
            if not findings:
                findings.append(self.create_finding(
                    app=app,
                    title="Runtime analysis completed - no dynamic issues detected",
                    severity="info",
                    category="Runtime Analysis",
                    description=(
                        "Frida-based runtime instrumentation was performed on the running application. "
                        "Hooks were placed on root detection, SSL pinning, cryptographic APIs, "
                        "clipboard access, logging, WebView, and SharedPreferences. "
                        "No security issues were triggered during the observation window."
                    ),
                    impact="No impact - informational result.",
                    remediation="No action required.",
                    poc_evidence=f"Device: {device_id}, PID: {pid}, hooks installed, 30s observation",
                ))

        except ImportError:
            logger.error("Frida not installed - cannot run runtime analysis")
            findings.append(self._tool_missing_finding(app, "frida"))
        except asyncio.TimeoutError:
            logger.error("Frida operation timed out during runtime analysis")
            findings.append(self._timeout_finding(app, "Frida spawn/attach timed out"))
        except Exception as e:
            logger.error(f"Runtime analysis failed: {e}")
            findings.append(self._error_finding(app, str(e)))

        return findings

    def _process_messages(self, messages: list[dict], app: MobileApp) -> list[Finding]:
        """Convert Frida hook messages into Finding objects."""
        findings: list[Finding] = []
        seen_titles: set[str] = set()

        for msg in messages:
            if not isinstance(msg, dict):
                continue

            msg_type = msg.get("type")

            if msg_type == "finding":
                title = msg.get("title", "Unknown runtime finding")
                if title in seen_titles:
                    continue
                seen_titles.add(title)

                finding = self._map_finding(
                    app, msg.get("category", "Runtime Analysis"),
                    title, msg.get("severity", "info"), msg.get("detail", ""),
                )
                if finding:
                    findings.append(finding)

            elif msg_type == "collection_done":
                for f in msg.get("findings", []):
                    title = f.get("title", "")
                    if title not in seen_titles:
                        seen_titles.add(title)
                        finding = self._map_finding(
                            app, f.get("category", "Runtime"),
                            title, f.get("severity", "info"), f.get("detail", ""),
                        )
                        if finding:
                            findings.append(finding)

        return findings

    def _map_finding(
        self, app: MobileApp, category: str, title: str, severity: str, detail: str,
    ) -> Finding | None:
        """Map a Frida hook result to a structured Finding."""
        category_metadata = {
            "Root Detection": {
                "cwe_id": "CWE-919", "owasp": "MASVS-RESILIENCE",
                "impact": "If root detection is absent or bypassable, attackers on rooted devices can tamper with the app.",
                "remediation": "Implement multi-layered root detection using SafetyNet/Play Integrity, file checks, and native checks.",
            },
            "SSL Pinning": {
                "cwe_id": "CWE-295", "owasp": "MASVS-NETWORK",
                "impact": "Presence or absence of pinning affects resistance to MitM attacks.",
                "remediation": "Implement certificate pinning with backup pins and proper failure handling.",
            },
            "SSL/TLS": {
                "cwe_id": "CWE-295", "owasp": "MASVS-NETWORK",
                "impact": "Weak TLS trust configuration enables man-in-the-middle attacks.",
                "remediation": "Use the platform default TrustManager. Never initialize with null KeyStore.",
            },
            "Cryptography": {
                "cwe_id": "CWE-327", "owasp": "MASVS-CRYPTO",
                "impact": "Weak ciphers or improper random seeding can be exploited to decrypt sensitive data.",
                "remediation": "Use AES-GCM or AES-CBC with HMAC. Avoid ECB, DES, RC4. Do not manually seed SecureRandom.",
            },
            "Data Leakage": {
                "cwe_id": "CWE-532", "owasp": "MASVS-STORAGE",
                "impact": "Sensitive data exposed via clipboard or logs can be captured by other apps.",
                "remediation": "Disable clipboard for sensitive fields. Remove debug/verbose logging in release builds.",
            },
            "WebView": {
                "cwe_id": "CWE-749", "owasp": "MASVS-PLATFORM",
                "impact": "JavaScript interfaces in WebViews can be exploited for code execution.",
                "remediation": "Minimize JavaScript interface exposure. Validate all WebView URLs.",
            },
            "Data Storage": {
                "cwe_id": "CWE-922", "owasp": "MASVS-STORAGE",
                "impact": "World-readable SharedPreferences expose data to all apps on the device.",
                "remediation": "Use MODE_PRIVATE for SharedPreferences. Use EncryptedSharedPreferences for sensitive data.",
            },
        }

        meta = category_metadata.get(category, {
            "cwe_id": None, "owasp": "MASVS-RESILIENCE",
            "impact": "Dynamic analysis detected a potential security concern.",
            "remediation": "Review the finding detail and apply appropriate mitigations.",
        })

        return self.create_finding(
            app=app,
            title=title,
            severity=severity,
            category=category,
            description=f"Runtime hook detected: {detail}",
            impact=meta["impact"],
            remediation=meta["remediation"],
            poc_evidence=f"Detected by Frida runtime hook: {detail}",
            cwe_id=meta.get("cwe_id"),
            owasp_masvs_category=meta.get("owasp"),
        )

    async def _find_device(self) -> str | None:
        """Find the first connected Android device via ADB."""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["adb", "devices"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "device":
                    return parts[0]
        except Exception as e:
            logger.error(f"ADB device discovery failed: {e}")
        return None

    def _tool_missing_finding(self, app: MobileApp, tool: str) -> Finding:
        return self.create_finding(
            app=app, title=f"Runtime analysis skipped - {tool} not available",
            severity="info", category="Runtime Analysis",
            description=f"The {tool} tool is not installed in the analysis environment.",
            impact="Dynamic runtime checks could not be performed.",
            remediation=f"Install {tool} to enable runtime analysis.",
        )

    def _timeout_finding(self, app: MobileApp, detail: str) -> Finding:
        return self.create_finding(
            app=app, title="Runtime analysis timed out",
            severity="info", category="Runtime Analysis",
            description=f"A timeout occurred during runtime analysis: {detail}",
            impact="Some runtime checks may be incomplete.",
            remediation="Ensure the device is responsive and the app can be launched.",
        )

    def _error_finding(self, app: MobileApp, error: str) -> Finding:
        return self.create_finding(
            app=app, title="Runtime analysis encountered an error",
            severity="info", category="Runtime Analysis",
            description=f"An error occurred during Frida-based runtime analysis: {error}",
            impact="Runtime checks could not complete.",
            remediation="Check device connectivity, root/Frida server status, and app compatibility.",
        )
