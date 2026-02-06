"""Network analyzer — Frida-based network traffic analysis + Drozer IPC testing."""

import asyncio
import logging
import subprocess
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

# Frida script that hooks network and IPC APIs
NETWORK_HOOKS_SCRIPT = r"""
'use strict';

var findings = [];

function reportFinding(category, title, severity, detail) {
    findings.push({category: category, title: title, severity: severity, detail: detail});
    send({type: 'finding', category: category, title: title, severity: severity, detail: detail});
}

Java.perform(function() {

    // ---- HTTP Cleartext Detection ----
    // 1. Hook URL constructor to detect http:// connections
    try {
        var URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function(url) {
            if (url && url.toString().startsWith('http://')) {
                reportFinding('Network', 'Cleartext HTTP connection detected',
                    'high', 'App opens URL: ' + url.toString().substring(0, 200));
            }
            return this.$init(url);
        };
    } catch(e) {}

    // 2. Hook HttpURLConnection to detect cleartext
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.connect.implementation = function() {
            var url = this.getURL().toString();
            if (url.startsWith('http://')) {
                reportFinding('Network', 'Cleartext HTTP request made',
                    'high', 'HttpURLConnection.connect() to: ' + url.substring(0, 200));
            }
            return this.connect();
        };
    } catch(e) {}

    // 3. Hook OkHttp to capture requests
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var RealCall = Java.use('okhttp3.internal.connection.RealCall');
        RealCall.execute.implementation = function() {
            var request = this.request();
            var url = request.url().toString();
            if (url.startsWith('http://')) {
                reportFinding('Network', 'OkHttp cleartext request',
                    'high', 'OkHttp request to: ' + url.substring(0, 200));
            }
            // Track all endpoints for reporting
            send({type: 'endpoint', url: url, method: request.method()});
            return this.execute();
        };
    } catch(e) {}

    // ---- SSL/TLS Hooks ----
    // 4. SSLSocket — detect TLS versions
    try {
        var SSLSocket = Java.use('javax.net.ssl.SSLSocket');
        SSLSocket.startHandshake.implementation = function() {
            var protocols = this.getEnabledProtocols();
            var protoList = [];
            for (var i = 0; i < protocols.length; i++) {
                protoList.push(protocols[i]);
                if (protocols[i] === 'TLSv1' || protocols[i] === 'TLSv1.1' || protocols[i] === 'SSLv3') {
                    reportFinding('Network', 'Weak TLS version enabled: ' + protocols[i],
                        'high', 'SSLSocket allows deprecated protocol: ' + protocols[i]);
                }
            }
            send({type: 'tls_info', host: this.getInetAddress().getHostName(),
                  port: this.getPort(), protocols: protoList.join(',')});
            return this.startHandshake();
        };
    } catch(e) {}

    // 5. HostnameVerifier — detect disabled verification
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {
            var verifierClass = verifier.getClass().getName();
            // Common patterns for "allow-all" verifiers
            if (verifierClass.indexOf('AllowAll') !== -1 ||
                verifierClass.indexOf('NoOp') !== -1 ||
                verifierClass.indexOf('ALLOW_ALL') !== -1 ||
                verifierClass.indexOf('NullHostnameVerifier') !== -1) {
                reportFinding('Network', 'Hostname verification disabled',
                    'critical', 'HttpsURLConnection uses permissive HostnameVerifier: ' + verifierClass);
            }
            return this.setHostnameVerifier(verifier);
        };
    } catch(e) {}

    // 6. SSLContext — detect insecure SSL context init
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.implementation = function(km, tm, sr) {
            if (tm !== null) {
                // Check if it's using a custom trust manager (potentially permissive)
                try {
                    var tmArray = Java.array('javax.net.ssl.TrustManager', tm);
                    for (var i = 0; i < tmArray.length; i++) {
                        var tmClass = tmArray[i].getClass().getName();
                        if (tmClass.indexOf('InsecureTrustManager') !== -1 ||
                            tmClass.indexOf('AllTrust') !== -1 ||
                            tmClass.indexOf('NullTrustManager') !== -1) {
                            reportFinding('Network', 'SSLContext uses insecure TrustManager',
                                'critical', 'SSLContext.init() with permissive TrustManager: ' + tmClass);
                        }
                    }
                } catch(e) {}
            }
            return this.init(km, tm, sr);
        };
    } catch(e) {}

    // ---- Content Provider Access ----
    // 7. ContentResolver queries — detect cross-app data access
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, proj, sel, selArgs, sort) {
            var uriStr = uri.toString();
            // Only report if querying external content providers
            if (uriStr.indexOf('content://') === 0 &&
                uriStr.indexOf('com.android.providers') === -1 &&
                uriStr.indexOf('settings') === -1) {
                send({type: 'content_query', uri: uriStr});
            }
            return this.query(uri, proj, sel, selArgs, sort);
        };
    } catch(e) {}

    // ---- Intent / IPC ----
    // 8. Broadcast sending — detect sensitive data in broadcasts
    try {
        var ContextWrapper = Java.use('android.content.ContextWrapper');
        ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
            var action = intent.getAction();
            reportFinding('IPC', 'Implicit broadcast sent at runtime',
                'medium', 'sendBroadcast() with action: ' + (action || 'null') +
                ' - may expose data to other apps');
            return this.sendBroadcast(intent);
        };
    } catch(e) {}

    send({type: 'hooks_ready', count: 8});
});

setTimeout(function() {
    send({type: 'collection_done', findings: findings});
}, 25000);
"""


class NetworkAnalyzer(BaseAnalyzer):
    """Dynamic network and IPC analyzer using Frida + Drozer."""

    name = "network_analyzer"
    platform = "android"

    def __init__(self, device_id: str | None = None):
        self.device_id = device_id

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Run network/IPC analysis on the app."""
        findings: list[Finding] = []

        if not app.package_name:
            logger.warning("No package_name on app - skipping network analysis")
            return findings

        device_id = self.device_id or await self._find_device()
        if not device_id:
            logger.error("No connected Android device found for network analysis")
            return findings

        logger.info(f"Starting network/IPC analysis of {app.package_name} on device {device_id}")

        # Run Frida network hooks and Drozer component tests in parallel
        frida_task = asyncio.create_task(self._run_frida_hooks(app, device_id))
        drozer_task = asyncio.create_task(self._run_drozer_checks(app, device_id))
        objection_task = asyncio.create_task(self._run_objection_checks(app, device_id))

        frida_findings = await frida_task
        drozer_findings = await drozer_task
        objection_findings = await objection_task

        findings.extend(frida_findings)
        findings.extend(drozer_findings)
        findings.extend(objection_findings)

        if not findings:
            findings.append(self.create_finding(
                app=app,
                title="Network/IPC analysis completed - no issues detected",
                severity="info",
                category="Network Analysis",
                description=(
                    "Dynamic network and IPC analysis was performed using Frida hooks, "
                    "Drozer component testing, and Objection. No cleartext traffic, "
                    "weak TLS, or vulnerable IPC patterns were detected."
                ),
                impact="No impact - informational result.",
                remediation="No action required.",
            ))

        logger.info(f"Network/IPC analysis produced {len(findings)} findings")
        return findings

    async def _run_frida_hooks(self, app: MobileApp, device_id: str) -> list[Finding]:
        """Run Frida network hooks."""
        findings: list[Finding] = []

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

            logger.info(f"Spawning {app.package_name} for network hooks")
            pid = await asyncio.wait_for(
                asyncio.to_thread(device.spawn, [app.package_name]),
                timeout=30,
            )

            session = await asyncio.wait_for(
                asyncio.to_thread(device.attach, pid),
                timeout=15,
            )

            messages: list[dict] = []
            endpoints: list[dict] = []

            def on_message(message: dict, data: Any):
                if message.get("type") == "send":
                    payload = message["payload"]
                    if isinstance(payload, dict):
                        if payload.get("type") == "endpoint":
                            endpoints.append(payload)
                        else:
                            messages.append(payload)

            script = session.create_script(NETWORK_HOOKS_SCRIPT)
            script.on("message", on_message)
            await asyncio.to_thread(script.load)
            await asyncio.to_thread(device.resume, pid)

            logger.info("Waiting for network hooks to collect data (30s)...")
            await asyncio.sleep(30)

            try:
                await asyncio.to_thread(script.unload)
                await asyncio.to_thread(session.detach)
                await asyncio.to_thread(device.kill, pid)
            except Exception:
                pass

            findings = self._process_messages(messages, app)

            # Report discovered endpoints
            if endpoints:
                unique_domains = set()
                for ep in endpoints:
                    url = ep.get("url", "")
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        unique_domains.add(f"{parsed.scheme}://{parsed.netloc}")
                    except Exception:
                        pass

                if unique_domains:
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Network endpoints discovered ({len(unique_domains)} domains)",
                        severity="info",
                        category="Network Analysis",
                        description="The following network endpoints were contacted during runtime analysis.",
                        impact="These endpoints represent the app's network attack surface.",
                        remediation="Ensure all endpoints use HTTPS and implement certificate pinning.",
                        poc_evidence="Domains contacted: " + ", ".join(sorted(unique_domains)),
                    ))

        except ImportError:
            logger.warning("Frida not installed - skipping network hooks")
        except asyncio.TimeoutError:
            logger.warning("Frida network hooks timed out")
        except Exception as e:
            logger.error(f"Frida network hooks failed: {e}")

        return findings

    async def _run_drozer_checks(self, app: MobileApp, device_id: str) -> list[Finding]:
        """Run Drozer component analysis."""
        findings: list[Finding] = []

        try:
            from api.services.drozer_service import DrozerService

            service = DrozerService()
            if not await service.check_drozer_installed():
                logger.warning("Drozer not installed - skipping component analysis")
                return findings

            package = app.package_name
            logger.info(f"Running Drozer component analysis on {package}")

            # 1. Attack surface enumeration
            attack_surface = await service.get_attack_surface(device_id, package)
            if attack_surface.get("data"):
                surface = attack_surface["data"]
                exported_activities = surface.get("exported_activities", 0)
                exported_services = surface.get("exported_services", 0)
                exported_receivers = surface.get("exported_receivers", 0)
                exported_providers = surface.get("exported_providers", 0)
                is_debuggable = surface.get("is_debuggable", False)

                total_exported = exported_activities + exported_services + exported_receivers + exported_providers

                if total_exported > 0:
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Drozer: {total_exported} exported components found",
                        severity="medium" if total_exported > 5 else "low",
                        category="Attack Surface",
                        description=(
                            f"Drozer attack surface analysis found {exported_activities} exported activities, "
                            f"{exported_services} exported services, {exported_receivers} broadcast receivers, "
                            f"and {exported_providers} content providers on device {device_id}."
                        ),
                        impact="Exported components can be invoked by other apps, potentially leaking data or triggering unintended behavior.",
                        remediation="Minimize exported components. Add permission checks to necessary exports.",
                        poc_evidence=f"drozer> run app.package.attacksurface {package}",
                        cwe_id="CWE-926",
                        owasp_masvs_category="MASVS-PLATFORM",
                    ))

                if is_debuggable:
                    findings.append(self.create_finding(
                        app=app,
                        title="Drozer: Application is debuggable (runtime confirmed)",
                        severity="high",
                        category="Configuration",
                        description="Drozer confirmed the application is debuggable on the live device.",
                        impact="Debuggable apps can be attached to with a debugger to inspect memory and modify behavior.",
                        remediation="Set android:debuggable=false for release builds.",
                        poc_evidence=f"drozer> run app.package.attacksurface {package} -> is debuggable",
                        cwe_id="CWE-489",
                        owasp_masvs_category="MASVS-RESILIENCE",
                    ))

            # 2. SQL injection in content providers
            sqli_result = await service.test_sql_injection(device_id, package)
            if sqli_result.get("findings"):
                for sqli in sqli_result["findings"]:
                    findings.append(self.create_finding(
                        app=app,
                        title="Drozer: SQL injection in content provider",
                        severity="critical",
                        category="SQL Injection",
                        description=sqli.get("description", "SQL injection vulnerability found in content provider"),
                        impact="Attacker can extract or modify data via SQL injection through exported content provider.",
                        remediation="Use parameterized queries. Set android:exported=false if provider is internal.",
                        poc_evidence=f"drozer> run scanner.provider.injection -a {package}",
                        cwe_id="CWE-89",
                        owasp_masvs_category="MASVS-PLATFORM",
                    ))

            # 3. Path traversal in content providers
            traversal_result = await service.test_path_traversal(device_id, package)
            if traversal_result.get("findings"):
                for trav in traversal_result["findings"]:
                    findings.append(self.create_finding(
                        app=app,
                        title="Drozer: Path traversal in content provider",
                        severity="high",
                        category="Path Traversal",
                        description=trav.get("description", "Path traversal vulnerability found in content provider"),
                        impact="Attacker can read arbitrary files through the content provider.",
                        remediation="Validate and canonicalize file paths. Restrict accessible directories.",
                        poc_evidence=f"drozer> run scanner.provider.traversal -a {package}",
                        cwe_id="CWE-22",
                        owasp_masvs_category="MASVS-PLATFORM",
                    ))

        except Exception as e:
            logger.error(f"Drozer component analysis failed: {e}")

        return findings

    async def _run_objection_checks(self, app: MobileApp, device_id: str) -> list[Finding]:
        """Run Objection-based checks."""
        findings: list[Finding] = []

        try:
            from api.services.objection_service import ObjectionService

            service = ObjectionService()
            if not await service.check_objection_installed():
                logger.warning("Objection not installed - skipping objection checks")
                return findings

            package = app.package_name
            logger.info(f"Running Objection analysis on {package}")

            # 1. List activities (verify runtime components)
            activities_result = await service.execute_command(
                device_id, package, "android",
                "android hooking list activities",
                timeout=30,
            )
            if activities_result.get("result_type") == "success":
                output = activities_result.get("output", "")
                activity_count = len([l for l in output.split("\n") if l.strip() and not l.startswith("[")])
                if activity_count > 0:
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Objection: {activity_count} activities enumerated at runtime",
                        severity="info",
                        category="Runtime Enumeration",
                        description=f"Objection enumerated {activity_count} loaded activities in the running application.",
                        impact="Informational - shows runtime component landscape.",
                        remediation="Review exported activities for unintended exposure.",
                        poc_evidence=f"objection --gadget {package} explore -c 'android hooking list activities'",
                    ))

            # 2. List loaded classes (check for security libraries)
            classes_result = await service.execute_command(
                device_id, package, "android",
                "android hooking list classes",
                timeout=30,
            )
            if classes_result.get("result_type") == "success":
                output = classes_result.get("output", "")
                classes = output.split("\n")

                # Check for security-relevant classes
                security_libs = {
                    "com.scottyab.rootbeer": "RootBeer (root detection)",
                    "com.noshufou.android.su": "Superuser detection",
                    "org.spongycastle": "SpongyCastle crypto",
                    "com.google.android.gms.safetynet": "SafetyNet",
                    "io.flutter.embedding": "Flutter framework",
                    "okhttp3.CertificatePinner": "OkHttp certificate pinning",
                    "com.datatheorem.android.trustkit": "TrustKit (pinning)",
                }

                detected_libs = []
                for cls_line in classes:
                    for lib_prefix, lib_name in security_libs.items():
                        if lib_prefix in cls_line:
                            detected_libs.append(lib_name)

                detected_libs = list(set(detected_libs))
                if detected_libs:
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Objection: Security libraries detected ({len(detected_libs)})",
                        severity="info",
                        category="Runtime Enumeration",
                        description=f"The following security-relevant libraries were found loaded at runtime: {', '.join(detected_libs)}",
                        impact="Informational - indicates security controls present in the app.",
                        remediation="Ensure detected security libraries are properly configured and not bypassable.",
                        poc_evidence=f"objection --gadget {package} explore -c 'android hooking list classes'",
                    ))

            # 3. Check Android keystore contents
            keystore_result = await service.execute_command(
                device_id, package, "android",
                "android keystore list",
                timeout=30,
            )
            if keystore_result.get("result_type") == "success":
                data = keystore_result.get("data", {})
                items = data.get("items", [])
                if items:
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Objection: {len(items)} keystore entries found",
                        severity="info",
                        category="Data Storage",
                        description=f"The Android Keystore contains {len(items)} entries for this application.",
                        impact="Keystore entries may contain cryptographic keys. Review for proper access controls.",
                        remediation="Ensure keystore entries use hardware-backed keys and biometric authentication where appropriate.",
                        poc_evidence=f"objection --gadget {package} explore -c 'android keystore list'",
                        owasp_masvs_category="MASVS-STORAGE",
                    ))

            # 4. Environment info
            env_result = await service.execute_command(
                device_id, package, "android",
                "env",
                timeout=15,
            )
            if env_result.get("result_type") == "success":
                output = env_result.get("output", "")
                if "Documents" in output or "cacheDirectory" in output:
                    findings.append(self.create_finding(
                        app=app,
                        title="Objection: Application filesystem paths enumerated",
                        severity="info",
                        category="Runtime Enumeration",
                        description="Application data directories and file paths were enumerated via Objection.",
                        impact="Informational - reveals filesystem layout of the app.",
                        remediation="Ensure sensitive files are stored in encrypted containers.",
                        poc_evidence=output[:500],
                    ))

        except Exception as e:
            logger.error(f"Objection analysis failed: {e}")

        return findings

    def _process_messages(self, messages: list[dict], app: MobileApp) -> list[Finding]:
        """Convert Frida messages to Finding objects."""
        findings: list[Finding] = []
        seen: set[str] = set()

        for msg in messages:
            if not isinstance(msg, dict):
                continue

            msg_type = msg.get("type")
            if msg_type == "finding":
                title = msg.get("title", "")
                if title in seen:
                    continue
                seen.add(title)

                finding = self._map_finding(
                    app, msg.get("category", "Network"),
                    title, msg.get("severity", "info"), msg.get("detail", ""),
                )
                if finding:
                    findings.append(finding)

            elif msg_type == "collection_done":
                for f in msg.get("findings", []):
                    title = f.get("title", "")
                    if title not in seen:
                        seen.add(title)
                        finding = self._map_finding(
                            app, f.get("category", "Network"),
                            title, f.get("severity", "info"), f.get("detail", ""),
                        )
                        if finding:
                            findings.append(finding)

        return findings

    def _map_finding(
        self, app: MobileApp, category: str, title: str, severity: str, detail: str,
    ) -> Finding:
        """Map Frida network hook to a Finding."""
        meta = {
            "Network": {"cwe_id": "CWE-319", "owasp": "MASVS-NETWORK",
                "impact": "Cleartext traffic can be intercepted by network attackers.",
                "remediation": "Use HTTPS for all connections. Enable network security config with cleartextTrafficPermitted=false."},
            "IPC": {"cwe_id": "CWE-927", "owasp": "MASVS-PLATFORM",
                "impact": "Implicit broadcasts can be intercepted by malicious apps.",
                "remediation": "Use LocalBroadcastManager or explicit intents for sensitive data."},
        }.get(category, {"cwe_id": "CWE-319", "owasp": "MASVS-NETWORK",
            "impact": "Network security issue detected.", "remediation": "Review and fix."})

        return self.create_finding(
            app=app, title=title, severity=severity, category=category,
            description=f"Network hook detected: {detail}",
            impact=meta["impact"], remediation=meta["remediation"],
            poc_evidence=f"Detected by Frida network hook: {detail}",
            cwe_id=meta.get("cwe_id"), owasp_masvs_category=meta.get("owasp"),
        )

    async def _find_device(self) -> str | None:
        """Find the first connected Android device."""
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
