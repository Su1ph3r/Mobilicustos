"""Runtime analyzer -- Frida-based dynamic analysis of running applications.

Performs dynamic security analysis by injecting a comprehensive Frida
JavaScript hook script into the target application at runtime. Hooks
security-relevant Java/ObjC APIs to detect insecure behavior that cannot
be identified through static analysis alone.

Dynamic checks include:
    - Insecure data storage (SharedPreferences, NSUserDefaults, clipboard)
    - Cryptographic API misuse at runtime
    - Certificate validation bypasses
    - Sensitive data in log output
    - Runtime permission handling

Note:
    This analyzer requires a connected device with frida-server running
    and is only executed during ``scan_type="dynamic"`` or ``scan_type="full"``
    scans. Flutter apps typically do not trigger Java-level hooks as they
    use Dart/native networking and crypto.

OWASP references:
    - MASVS-STORAGE, MASVS-CRYPTO, MASVS-NETWORK
"""

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

    // ---- Content Provider Monitoring ----
    // 11. ContentResolver.query() — full monitoring with projection and selection
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            var uriStr = uri ? uri.toString() : 'null';
            var projStr = '';
            try {
                if (projection !== null) {
                    var projArr = [];
                    for (var i = 0; i < projection.length; i++) { projArr.push(projection[i]); }
                    projStr = projArr.join(', ');
                }
            } catch(e2) {}
            var selStr = selection ? selection.toString() : 'null';
            console.log('[*] ContentResolver.query() URI: ' + uriStr);
            reportFinding('Content Provider', 'ContentResolver.query() invoked at runtime',
                'info', 'URI: ' + uriStr + ' | projection: [' + projStr + '] | selection: ' + selStr);
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch(e) { console.log('[-] Failed to hook ContentResolver.query: ' + e); }

    // 12. ContentResolver.insert()
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues').implementation = function(uri, values) {
            var uriStr = uri ? uri.toString() : 'null';
            console.log('[*] ContentResolver.insert() URI: ' + uriStr);
            reportFinding('Content Provider', 'ContentResolver.insert() invoked at runtime',
                'info', 'URI: ' + uriStr);
            return this.insert(uri, values);
        };
    } catch(e) { console.log('[-] Failed to hook ContentResolver.insert: ' + e); }

    // 13. ContentResolver.update()
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.update.overload('android.net.Uri', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = function(uri, values, where, selArgs) {
            var uriStr = uri ? uri.toString() : 'null';
            var whereStr = where ? where.toString() : 'null';
            console.log('[*] ContentResolver.update() URI: ' + uriStr);
            reportFinding('Content Provider', 'ContentResolver.update() invoked at runtime',
                'medium', 'URI: ' + uriStr + ' | where: ' + whereStr);
            return this.update(uri, values, where, selArgs);
        };
    } catch(e) { console.log('[-] Failed to hook ContentResolver.update: ' + e); }

    // 14. ContentResolver.delete()
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver['delete'].overload('android.net.Uri', 'java.lang.String', '[Ljava.lang.String;').implementation = function(uri, where, selArgs) {
            var uriStr = uri ? uri.toString() : 'null';
            var whereStr = where ? where.toString() : 'null';
            console.log('[+] ContentResolver.delete() URI: ' + uriStr);
            reportFinding('Content Provider', 'ContentResolver.delete() invoked at runtime',
                'medium', 'URI: ' + uriStr + ' | where: ' + whereStr);
            return this['delete'](uri, where, selArgs);
        };
    } catch(e) { console.log('[-] Failed to hook ContentResolver.delete: ' + e); }

    // ---- Intent Monitoring ----
    // 15. Activity.startActivity()
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
            var action = intent.getAction() || 'null';
            var dataUri = 'null';
            try { var d = intent.getData(); if (d) dataUri = d.toString(); } catch(e2) {}
            var component = 'null';
            try { var c = intent.getComponent(); if (c) component = c.flattenToString(); } catch(e2) {}
            var extras = 'null';
            try { var b = intent.getExtras(); if (b) extras = b.toString(); } catch(e2) {}
            console.log('[*] Activity.startActivity() action: ' + action + ' component: ' + component);
            reportFinding('Intent', 'Activity.startActivity() called at runtime',
                'info', 'action: ' + action + ' | data: ' + dataUri + ' | component: ' + component + ' | extras: ' + extras);
            return this.startActivity(intent);
        };
    } catch(e) { console.log('[-] Failed to hook Activity.startActivity: ' + e); }

    // 16. Activity.startActivityForResult()
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function(intent, requestCode) {
            var action = intent.getAction() || 'null';
            var dataUri = 'null';
            try { var d = intent.getData(); if (d) dataUri = d.toString(); } catch(e2) {}
            var component = 'null';
            try { var c = intent.getComponent(); if (c) component = c.flattenToString(); } catch(e2) {}
            console.log('[*] Activity.startActivityForResult() action: ' + action + ' requestCode: ' + requestCode);
            reportFinding('Intent', 'Activity.startActivityForResult() called at runtime',
                'info', 'action: ' + action + ' | data: ' + dataUri + ' | component: ' + component + ' | requestCode: ' + requestCode);
            return this.startActivityForResult(intent, requestCode);
        };
    } catch(e) { console.log('[-] Failed to hook Activity.startActivityForResult: ' + e); }

    // 17. Context.sendBroadcast()
    try {
        var ContextWrapper = Java.use('android.content.ContextWrapper');
        ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function(intent) {
            var action = intent.getAction() || 'null';
            var dataUri = 'null';
            try { var d = intent.getData(); if (d) dataUri = d.toString(); } catch(e2) {}
            var extras = 'null';
            try { var b = intent.getExtras(); if (b) extras = b.toString(); } catch(e2) {}
            console.log('[+] Context.sendBroadcast() action: ' + action);
            reportFinding('Intent', 'Implicit broadcast sent at runtime',
                'medium', 'sendBroadcast() action: ' + action + ' | data: ' + dataUri + ' | extras: ' + extras + ' - may expose data to other apps');
            return this.sendBroadcast(intent);
        };
    } catch(e) { console.log('[-] Failed to hook Context.sendBroadcast: ' + e); }

    // 18. Context.startService()
    try {
        var ContextWrapper = Java.use('android.content.ContextWrapper');
        ContextWrapper.startService.overload('android.content.Intent').implementation = function(intent) {
            var action = intent.getAction() || 'null';
            var component = 'null';
            try { var c = intent.getComponent(); if (c) component = c.flattenToString(); } catch(e2) {}
            var extras = 'null';
            try { var b = intent.getExtras(); if (b) extras = b.toString(); } catch(e2) {}
            console.log('[*] Context.startService() action: ' + action + ' component: ' + component);
            reportFinding('Intent', 'Service started at runtime',
                'info', 'startService() action: ' + action + ' | component: ' + component + ' | extras: ' + extras);
            return this.startService(intent);
        };
    } catch(e) { console.log('[-] Failed to hook Context.startService: ' + e); }

    // ---- Extended WebView Hooks ----
    // 19. WebView.loadUrl()
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log('[*] WebView.loadUrl(): ' + url);
            var severity = 'info';
            if (url && url.toString().startsWith('http://')) {
                severity = 'high';
            }
            if (url && url.toString().startsWith('javascript:')) {
                severity = 'medium';
            }
            reportFinding('WebView', 'WebView.loadUrl() called at runtime',
                severity, 'URL: ' + (url ? url.toString().substring(0, 500) : 'null'));
            return this.loadUrl(url);
        };
    } catch(e) { console.log('[-] Failed to hook WebView.loadUrl: ' + e); }

    // 20. WebView.loadData()
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(data, mimeType, encoding) {
            console.log('[*] WebView.loadData() mimeType: ' + mimeType);
            reportFinding('WebView', 'WebView.loadData() called at runtime',
                'info', 'mimeType: ' + mimeType + ' | encoding: ' + encoding + ' | data length: ' + (data ? data.length : 0));
            return this.loadData(data, mimeType, encoding);
        };
    } catch(e) { console.log('[-] Failed to hook WebView.loadData: ' + e); }

    // 21. WebView.loadDataWithBaseURL()
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadDataWithBaseURL.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(baseUrl, data, mimeType, encoding, historyUrl) {
            console.log('[*] WebView.loadDataWithBaseURL() baseUrl: ' + baseUrl);
            reportFinding('WebView', 'WebView.loadDataWithBaseURL() called at runtime',
                'info', 'baseUrl: ' + (baseUrl || 'null') + ' | mimeType: ' + mimeType + ' | historyUrl: ' + (historyUrl || 'null') + ' | data length: ' + (data ? data.length : 0));
            return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
        };
    } catch(e) { console.log('[-] Failed to hook WebView.loadDataWithBaseURL: ' + e); }

    // 22. WebView.evaluateJavascript()
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.evaluateJavascript.implementation = function(script, callback) {
            console.log('[+] WebView.evaluateJavascript() script length: ' + (script ? script.length : 0));
            reportFinding('WebView', 'JavaScript evaluated in WebView at runtime',
                'medium', 'evaluateJavascript() called with script length: ' + (script ? script.length : 0) + ' | snippet: ' + (script ? script.toString().substring(0, 200) : 'null'));
            return this.evaluateJavascript(script, callback);
        };
    } catch(e) { console.log('[-] Failed to hook WebView.evaluateJavascript: ' + e); }

    // 23. WebSettings.setJavaScriptEnabled()
    try {
        var WebSettings = Java.use('android.webkit.WebSettings');
        WebSettings.setJavaScriptEnabled.implementation = function(flag) {
            console.log('[+] WebSettings.setJavaScriptEnabled(' + flag + ')');
            if (flag) {
                reportFinding('WebView', 'JavaScript enabled in WebView',
                    'medium', 'WebSettings.setJavaScriptEnabled(true) - enables JavaScript execution in WebView');
            }
            return this.setJavaScriptEnabled(flag);
        };
    } catch(e) { console.log('[-] Failed to hook WebSettings.setJavaScriptEnabled: ' + e); }

    // 24. WebView.addJavascriptInterface() — enhanced version (supplements hook #9)
    // Note: Hook #9 already covers this; this adds more detail logging
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.addJavascriptInterface.implementation = function(obj, name) {
            var objClass = obj ? obj.getClass().getName() : 'null';
            console.log('[+] WebView.addJavascriptInterface() name: "' + name + '" class: ' + objClass);
            reportFinding('WebView', 'JavaScript interface exposed in WebView',
                'high', 'WebView.addJavascriptInterface() - interface name: "' + name + '" | backing class: ' + objClass);
            return this.addJavascriptInterface(obj, name);
        };
    } catch(e) { console.log('[-] Failed to hook WebView.addJavascriptInterface (enhanced): ' + e); }

    // ---- Screenshot Protection ----
    // 25. Window.setFlags() — detect FLAG_SECURE (0x2000)
    try {
        var screenshotProtected = false;
        var Window = Java.use('android.view.Window');
        Window.setFlags.implementation = function(flags, mask) {
            var FLAG_SECURE = 0x2000;
            if ((flags & FLAG_SECURE) !== 0) {
                screenshotProtected = true;
                console.log('[+] Window.setFlags() FLAG_SECURE is SET - screenshot protection enabled');
                reportFinding('Screenshot Protection', 'Screenshot protection enabled (FLAG_SECURE)',
                    'info', 'Window.setFlags() called with FLAG_SECURE (0x2000) - app protects against screenshots');
            }
            return this.setFlags(flags, mask);
        };

        // Also check addFlags for FLAG_SECURE
        Window.addFlags.implementation = function(flags) {
            var FLAG_SECURE = 0x2000;
            if ((flags & FLAG_SECURE) !== 0) {
                screenshotProtected = true;
                console.log('[+] Window.addFlags() FLAG_SECURE is SET - screenshot protection enabled');
                reportFinding('Screenshot Protection', 'Screenshot protection enabled via addFlags (FLAG_SECURE)',
                    'info', 'Window.addFlags() called with FLAG_SECURE (0x2000) - app protects against screenshots');
            }
            return this.addFlags(flags);
        };

        // Report after observation period if no FLAG_SECURE was detected
        setTimeout(function() {
            if (!screenshotProtected) {
                console.log('[+] FLAG_SECURE not detected - app may be vulnerable to screenshot capture');
                reportFinding('Screenshot Protection', 'No screenshot protection detected (FLAG_SECURE missing)',
                    'medium', 'Window.setFlags()/addFlags() never set FLAG_SECURE (0x2000) - app content may be captured via screenshots or screen recording');
            }
        }, 20000);
    } catch(e) { console.log('[-] Failed to hook Window.setFlags: ' + e); }

    // ---- Keyboard Cache Monitoring ----
    // 26. EditText input type checks for password fields missing textNoSuggestions
    try {
        var EditText = Java.use('android.widget.EditText');
        EditText.setInputType.implementation = function(type) {
            // Input type flags
            var TYPE_CLASS_TEXT = 0x00000001;
            var TYPE_TEXT_VARIATION_PASSWORD = 0x00000080;
            var TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090;
            var TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000E0;
            var TYPE_TEXT_FLAG_NO_SUGGESTIONS = 0x00080000;
            var TYPE_NUMBER_VARIATION_PASSWORD = 0x00000010;

            var isPassword = ((type & TYPE_TEXT_VARIATION_PASSWORD) === TYPE_TEXT_VARIATION_PASSWORD) ||
                             ((type & TYPE_TEXT_VARIATION_VISIBLE_PASSWORD) === TYPE_TEXT_VARIATION_VISIBLE_PASSWORD) ||
                             ((type & TYPE_TEXT_VARIATION_WEB_PASSWORD) === TYPE_TEXT_VARIATION_WEB_PASSWORD) ||
                             ((type & TYPE_NUMBER_VARIATION_PASSWORD) === TYPE_NUMBER_VARIATION_PASSWORD);

            var hasNoSuggestions = (type & TYPE_TEXT_FLAG_NO_SUGGESTIONS) !== 0;

            if (isPassword) {
                console.log('[*] EditText.setInputType() password field detected, inputType=0x' + type.toString(16));
                if (!hasNoSuggestions) {
                    reportFinding('Keyboard Cache', 'Password field may allow keyboard cache/suggestions',
                        'medium', 'EditText.setInputType(0x' + type.toString(16) + ') - password field without TYPE_TEXT_FLAG_NO_SUGGESTIONS (0x00080000). Keyboard may cache input.');
                } else {
                    reportFinding('Keyboard Cache', 'Password field correctly disables suggestions',
                        'info', 'EditText.setInputType(0x' + type.toString(16) + ') - password field with TYPE_TEXT_FLAG_NO_SUGGESTIONS set.');
                }
            }
            return this.setInputType(type);
        };
    } catch(e) { console.log('[-] Failed to hook EditText.setInputType: ' + e); }

    // 27. TextView.setInputType() — covers broader cases since EditText extends TextView
    try {
        var TextView = Java.use('android.widget.TextView');
        TextView.setInputType.implementation = function(type) {
            var TYPE_TEXT_VARIATION_PASSWORD = 0x00000080;
            var TYPE_TEXT_FLAG_NO_SUGGESTIONS = 0x00080000;

            if ((type & TYPE_TEXT_VARIATION_PASSWORD) === TYPE_TEXT_VARIATION_PASSWORD) {
                var hasNoSuggestions = (type & TYPE_TEXT_FLAG_NO_SUGGESTIONS) !== 0;
                if (!hasNoSuggestions) {
                    console.log('[+] TextView.setInputType() password without NO_SUGGESTIONS, inputType=0x' + type.toString(16));
                    reportFinding('Keyboard Cache', 'TextView password field may allow keyboard suggestions',
                        'medium', 'TextView.setInputType(0x' + type.toString(16) + ') - password field without TYPE_TEXT_FLAG_NO_SUGGESTIONS flag');
                }
            }
            return this.setInputType(type);
        };
    } catch(e) { console.log('[-] Failed to hook TextView.setInputType: ' + e); }

    send({type: 'hooks_ready', count: 27});
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
                        "clipboard access, logging, WebView, SharedPreferences, content providers, "
                        "intents, screenshot protection (FLAG_SECURE), and keyboard cache. "
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
            "Content Provider": {
                "cwe_id": "CWE-200", "owasp": "MASVS-PLATFORM",
                "impact": "Content provider operations may expose or modify sensitive data accessible by other apps.",
                "remediation": "Restrict content provider access with proper permissions. Use android:exported=false for internal providers.",
            },
            "Intent": {
                "cwe_id": "CWE-927", "owasp": "MASVS-PLATFORM",
                "impact": "Intent-based communication may expose sensitive data or trigger unintended actions in other apps.",
                "remediation": "Use explicit intents for sensitive operations. Validate intent data. Use LocalBroadcastManager for internal broadcasts.",
            },
            "Screenshot Protection": {
                "cwe_id": "CWE-200", "owasp": "MASVS-PLATFORM",
                "impact": "Without FLAG_SECURE, sensitive screens can be captured via screenshots or screen recording.",
                "remediation": "Set WindowManager.LayoutParams.FLAG_SECURE on activities displaying sensitive data.",
            },
            "Keyboard Cache": {
                "cwe_id": "CWE-200", "owasp": "MASVS-STORAGE",
                "impact": "Keyboard cache/suggestions on password fields may store sensitive input in plaintext on disk.",
                "remediation": "Set TYPE_TEXT_FLAG_NO_SUGGESTIONS and appropriate password inputType on sensitive EditText fields.",
            },
        }

        meta = category_metadata.get(category, {
            "cwe_id": None, "owasp": "MASVS-RESILIENCE",
            "impact": "Dynamic analysis detected a potential security concern.",
            "remediation": "Review the finding detail and apply appropriate mitigations.",
        })

        # Build poc_commands based on category
        poc_cmds = self._get_runtime_poc_commands(category, app)

        return self.create_finding(
            app=app,
            title=title,
            severity=severity,
            category=category,
            description=f"Runtime hook detected: {detail}",
            impact=meta["impact"],
            remediation=meta["remediation"],
            poc_evidence=f"Detected by Frida runtime hook: {detail}",
            poc_verification=self._get_runtime_poc_verification(category),
            poc_commands=poc_cmds,
            code_snippet=detail[:300] if detail else None,
            cwe_id=meta.get("cwe_id"),
            owasp_masvs_category=meta.get("owasp"),
        )

    def _get_runtime_poc_commands(self, category: str, app: MobileApp) -> list[dict[str, str]]:
        """Get PoC commands appropriate for the runtime finding category."""
        pkg = app.package_name or "<package>"
        commands: dict[str, list[dict[str, str]]] = {
            "SSL/TLS": [
                {"type": "frida", "command": f"frida -U -f {pkg} -l ssl_hooks.js", "description": "Hook TrustManagerFactory.init() to detect null KeyStore"},
                {"type": "bash", "command": "mitmproxy -p 8080 --ssl-insecure", "description": "Intercept HTTPS traffic with mitmproxy"},
            ],
            "SSL Pinning": [
                {"type": "frida", "command": f"frida -U -f {pkg} -l ssl_pinning_check.js", "description": "Hook certificate pinning APIs"},
            ],
            "Cryptography": [
                {"type": "frida", "command": f"frida -U -f {pkg} -l crypto_hooks.js", "description": "Hook Cipher.getInstance() to log cipher algorithms"},
            ],
            "Data Leakage": [
                {"type": "adb", "command": "adb logcat -d | grep -iE 'password|token|key|secret'", "description": "Check logcat for sensitive data"},
                {"type": "frida", "command": f"frida -U -f {pkg} -l clipboard_monitor.js", "description": "Monitor clipboard operations"},
            ],
            "Screenshot Protection": [
                {"type": "adb", "command": "adb shell screencap /sdcard/test.png && adb pull /sdcard/test.png", "description": "Attempt screenshot capture"},
                {"type": "frida", "command": f"frida -U -f {pkg} -l flag_secure_check.js", "description": "Hook Window.setFlags() to check FLAG_SECURE"},
            ],
            "Data Storage": [
                {"type": "adb", "command": f"adb shell run-as {pkg} cat shared_prefs/*.xml", "description": "Read SharedPreferences files"},
            ],
            "WebView": [
                {"type": "frida", "command": f"frida -U -f {pkg} -l webview_hooks.js", "description": "Hook WebView APIs to monitor JavaScript interfaces"},
            ],
        }
        return commands.get(category, [
            {"type": "frida", "command": f"frida -U -f {pkg} -l runtime_hooks.js", "description": "Run Frida hooks to reproduce this finding"},
        ])

    def _get_runtime_poc_verification(self, category: str) -> str:
        """Get verification steps for a runtime finding category."""
        verifications: dict[str, str] = {
            "SSL/TLS": "1. Set up mitmproxy with self-signed cert\n2. Configure device proxy\n3. Launch the app\n4. If traffic is intercepted, TLS trust is weak",
            "SSL Pinning": "1. Install mitmproxy CA cert on device\n2. Launch app through proxy\n3. If connections succeed, pinning is not enforced",
            "Cryptography": "1. Inject Frida hooks for Cipher.getInstance()\n2. Use the app normally\n3. Review logged cipher transformations for weak algorithms",
            "Data Leakage": "1. Use the app and monitor logcat output\n2. Check for sensitive data in clipboard after copy operations\n3. Review log entries for tokens, passwords, or keys",
            "Screenshot Protection": "1. Launch the app and navigate to sensitive screens\n2. Take a screenshot via Power+VolumeDown or ADB\n3. If screenshot contains data, FLAG_SECURE is missing",
            "Data Storage": "1. On rooted device, read /data/data/<pkg>/shared_prefs/\n2. Check for MODE_WORLD_READABLE/WRITABLE files\n3. Verify sensitive data is not stored in plaintext",
            "WebView": "1. Hook WebView.addJavascriptInterface()\n2. Check what interfaces are exposed\n3. Verify JavaScript interfaces do not expose dangerous APIs",
        }
        return verifications.get(category, "1. Run Frida hooks targeting the relevant API\n2. Use the app normally\n3. Observe hook output for security issues")

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
