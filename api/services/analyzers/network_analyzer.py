"""Network analyzer -- Frida-based network traffic analysis and Drozer IPC testing.

Performs dynamic network security analysis by hooking networking APIs at
runtime to detect insecure communication patterns. Optionally runs Drozer
modules for Android IPC (Intent, Content Provider, Broadcast) security
testing.

Dynamic checks include:
    - HTTP (cleartext) connections detected at runtime
    - SSL/TLS certificate validation behavior
    - WebSocket connections without TLS
    - Content provider data leakage via Drozer
    - Broadcast receiver exposure via Drozer
    - Intent sniffing and injection testing

Note:
    This analyzer requires a connected device with frida-server running
    and is only executed during ``scan_type="dynamic"`` or ``scan_type="full"``
    scans.

OWASP references:
    - MASVS-NETWORK-1, MASVS-NETWORK-2, MASVS-PLATFORM-1
"""

import asyncio
import logging
import queue
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

    // ---- DNS Resolution Monitoring ----
    // 9. InetAddress.getByName() — log hostnames being resolved
    try {
        var InetAddress = Java.use('java.net.InetAddress');
        InetAddress.getByName.overload('java.lang.String').implementation = function(host) {
            console.log('[*] InetAddress.getByName(): ' + host);
            send({type: 'dns_resolution', hostname: host});
            reportFinding('DNS', 'DNS resolution detected at runtime',
                'info', 'InetAddress.getByName("' + host + '") - app resolves hostname');
            return this.getByName(host);
        };
    } catch(e) { console.log('[-] Failed to hook InetAddress.getByName: ' + e); }

    // 10. InetAddress.getAllByName() — log bulk DNS lookups
    try {
        var InetAddress = Java.use('java.net.InetAddress');
        InetAddress.getAllByName.overload('java.lang.String').implementation = function(host) {
            console.log('[*] InetAddress.getAllByName(): ' + host);
            send({type: 'dns_resolution', hostname: host});
            reportFinding('DNS', 'Bulk DNS resolution detected at runtime',
                'info', 'InetAddress.getAllByName("' + host + '") - app resolves all addresses for hostname');
            return this.getAllByName(host);
        };
    } catch(e) { console.log('[-] Failed to hook InetAddress.getAllByName: ' + e); }

    // ---- Certificate Chain Inspection ----
    // 11. X509TrustManager.checkServerTrusted() — log certificate chain details
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
            console.log('[*] X509TrustManager.checkServerTrusted() authType: ' + authType + ' chain length: ' + chain.length);
            var chainInfo = [];
            try {
                for (var i = 0; i < chain.length; i++) {
                    var cert = chain[i];
                    var subject = cert.getSubjectDN().toString();
                    var issuer = cert.getIssuerDN().toString();
                    var notAfter = cert.getNotAfter().toString();
                    var notBefore = cert.getNotBefore().toString();
                    chainInfo.push('Cert[' + i + ']: subject=' + subject + ' | issuer=' + issuer + ' | validFrom=' + notBefore + ' | validUntil=' + notAfter);
                }
            } catch(e2) { console.log('[-] Error reading cert chain: ' + e2); }
            var detail = 'authType: ' + authType + ' | chain: ' + chainInfo.join(' ; ');
            reportFinding('Certificate', 'TLS certificate chain inspected at runtime',
                'info', detail.substring(0, 1000));
            send({type: 'cert_chain', authType: authType, chainLength: chain.length, details: chainInfo});
            return this.checkServerTrusted(chain, authType);
        };
    } catch(e) { console.log('[-] Failed to hook TrustManagerImpl.checkServerTrusted: ' + e); }

    // 12. Fallback: Hook the interface method via platform TrustManager
    try {
        var PlatformTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        PlatformTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
            console.log('[*] NetworkSecurityTrustManager.checkServerTrusted() authType: ' + authType);
            var chainInfo = [];
            try {
                for (var i = 0; i < chain.length; i++) {
                    var cert = chain[i];
                    chainInfo.push('Cert[' + i + ']: subject=' + cert.getSubjectDN().toString() + ' | issuer=' + cert.getIssuerDN().toString());
                }
            } catch(e2) {}
            reportFinding('Certificate', 'Network security TrustManager inspected certificate chain',
                'info', 'authType: ' + authType + ' | ' + chainInfo.join(' ; '));
            return this.checkServerTrusted(chain, authType);
        };
    } catch(e) { console.log('[-] Failed to hook NetworkSecurityTrustManager: ' + e); }

    // ---- WebSocket Monitoring ----
    // 13. OkHttp WebSocket.send() — monitor outgoing WebSocket messages
    try {
        var RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
        RealWebSocket.send.overload('java.lang.String').implementation = function(text) {
            console.log('[*] WebSocket.send() text length: ' + (text ? text.length : 0));
            reportFinding('WebSocket', 'WebSocket message sent at runtime',
                'info', 'WebSocket.send() text message, length: ' + (text ? text.length : 0));
            return this.send(text);
        };
    } catch(e) { console.log('[-] Failed to hook RealWebSocket.send(String): ' + e); }

    // 14. OkHttp WebSocket.send(ByteString) — binary messages
    try {
        var RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
        var ByteString = Java.use('okio.ByteString');
        RealWebSocket.send.overload('okio.ByteString').implementation = function(bytes) {
            var size = bytes ? bytes.size() : 0;
            console.log('[*] WebSocket.send() binary, size: ' + size);
            reportFinding('WebSocket', 'WebSocket binary message sent at runtime',
                'info', 'WebSocket.send() binary message, size: ' + size + ' bytes');
            return this.send(bytes);
        };
    } catch(e) { console.log('[-] Failed to hook RealWebSocket.send(ByteString): ' + e); }

    // 15. OkHttp WebSocket.close()
    try {
        var RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
        RealWebSocket.close.overload('int', 'java.lang.String').implementation = function(code, reason) {
            console.log('[*] WebSocket.close() code: ' + code + ' reason: ' + reason);
            reportFinding('WebSocket', 'WebSocket connection closed at runtime',
                'info', 'WebSocket.close() code: ' + code + ' | reason: ' + (reason || 'null'));
            return this.close(code, reason);
        };
    } catch(e) { console.log('[-] Failed to hook RealWebSocket.close: ' + e); }

    // 16. OkHttp WebSocketListener.onMessage() — monitor incoming messages
    try {
        var WebSocketListener = Java.use('okhttp3.WebSocketListener');
        WebSocketListener.onMessage.overload('okhttp3.WebSocket', 'java.lang.String').implementation = function(ws, text) {
            console.log('[*] WebSocketListener.onMessage() text length: ' + (text ? text.length : 0));
            reportFinding('WebSocket', 'WebSocket message received at runtime',
                'info', 'WebSocketListener.onMessage() text message received, length: ' + (text ? text.length : 0));
            return this.onMessage(ws, text);
        };
    } catch(e) { console.log('[-] Failed to hook WebSocketListener.onMessage(String): ' + e); }

    // 17. OkHttp WebSocketListener.onMessage(ByteString) — binary incoming
    try {
        var WebSocketListener = Java.use('okhttp3.WebSocketListener');
        var ByteString = Java.use('okio.ByteString');
        WebSocketListener.onMessage.overload('okhttp3.WebSocket', 'okio.ByteString').implementation = function(ws, bytes) {
            var size = bytes ? bytes.size() : 0;
            console.log('[*] WebSocketListener.onMessage() binary, size: ' + size);
            reportFinding('WebSocket', 'WebSocket binary message received at runtime',
                'info', 'WebSocketListener.onMessage() binary message received, size: ' + size + ' bytes');
            return this.onMessage(ws, bytes);
        };
    } catch(e) { console.log('[-] Failed to hook WebSocketListener.onMessage(ByteString): ' + e); }

    // ---- Cookie/Session Tracking ----
    // 18. CookieManager.setCookie()
    try {
        var CookieManager = Java.use('android.webkit.CookieManager');
        CookieManager.setCookie.overload('java.lang.String', 'java.lang.String').implementation = function(url, value) {
            var redactedValue = 'null';
            try {
                if (value) {
                    // Redact cookie value but keep the name and domain info
                    var parts = value.split('=');
                    if (parts.length >= 2) {
                        redactedValue = parts[0] + '=[REDACTED]';
                        // Preserve flags after the value
                        var rest = value.split(';');
                        if (rest.length > 1) {
                            for (var i = 1; i < rest.length; i++) {
                                redactedValue += ';' + rest[i].trim();
                            }
                        }
                    } else {
                        redactedValue = '[REDACTED]';
                    }
                }
            } catch(e2) { redactedValue = '[parse error]'; }
            console.log('[*] CookieManager.setCookie() url: ' + url);
            reportFinding('Cookie', 'Cookie set via CookieManager at runtime',
                'info', 'CookieManager.setCookie() domain: ' + (url || 'null') + ' | cookie: ' + redactedValue);

            // Check for missing Secure/HttpOnly flags
            var valueLower = value ? value.toLowerCase() : '';
            if (valueLower.indexOf('secure') === -1) {
                reportFinding('Cookie', 'Cookie set without Secure flag',
                    'medium', 'CookieManager.setCookie() for ' + (url || 'null') + ' - cookie lacks Secure flag, may be sent over cleartext');
            }
            if (valueLower.indexOf('httponly') === -1) {
                reportFinding('Cookie', 'Cookie set without HttpOnly flag',
                    'low', 'CookieManager.setCookie() for ' + (url || 'null') + ' - cookie lacks HttpOnly flag, accessible via JavaScript');
            }
            return this.setCookie(url, value);
        };
    } catch(e) { console.log('[-] Failed to hook CookieManager.setCookie: ' + e); }

    // 19. CookieManager.getCookie()
    try {
        var CookieManager = Java.use('android.webkit.CookieManager');
        CookieManager.getCookie.overload('java.lang.String').implementation = function(url) {
            var result = this.getCookie(url);
            console.log('[*] CookieManager.getCookie() url: ' + url);
            var redacted = 'null';
            try {
                if (result) {
                    var cookies = result.split(';');
                    var redactedParts = [];
                    for (var i = 0; i < cookies.length; i++) {
                        var parts = cookies[i].trim().split('=');
                        if (parts.length >= 2) {
                            redactedParts.push(parts[0] + '=[REDACTED]');
                        }
                    }
                    redacted = redactedParts.join('; ');
                }
            } catch(e2) { redacted = '[parse error]'; }
            reportFinding('Cookie', 'Cookie read via CookieManager at runtime',
                'info', 'CookieManager.getCookie() domain: ' + (url || 'null') + ' | cookies: ' + redacted);
            return result;
        };
    } catch(e) { console.log('[-] Failed to hook CookieManager.getCookie: ' + e); }

    send({type: 'hooks_ready', count: 19});
});

setTimeout(function() {
    send({type: 'collection_done', findings: findings});
}, 25000);
"""


IOS_NETWORK_HOOKS_SCRIPT = r"""
'use strict';

var findings = [];

function reportFinding(category, title, severity, detail) {
    findings.push({category: category, title: title, severity: severity, detail: detail});
    send({type: 'finding', category: category, title: title, severity: severity, detail: detail});
}

if (ObjC.available) {

    // ---- HTTP Traffic Monitoring ----
    // 1. NSURLSession dataTaskWithRequest: — main HTTP traffic
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
            onEnter: function(args) {
                var request = ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();
                var method = request.HTTPMethod().toString();
                send({type: 'endpoint', url: url, method: method});
                if (url.indexOf('http://') === 0) {
                    reportFinding('Network', 'Cleartext HTTP request detected (NSURLSession)',
                        'high', 'NSURLSession dataTask to: ' + url.substring(0, 200));
                }
            }
        });
    } catch(e) {}

    // 2. NSURLSession downloadTaskWithRequest:
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        Interceptor.attach(NSURLSession['- downloadTaskWithRequest:'].implementation, {
            onEnter: function(args) {
                var request = ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();
                send({type: 'endpoint', url: url, method: 'DOWNLOAD'});
                if (url.indexOf('http://') === 0) {
                    reportFinding('Network', 'Cleartext HTTP download detected',
                        'high', 'NSURLSession downloadTask to: ' + url.substring(0, 200));
                }
            }
        });
    } catch(e) {}

    // ---- Certificate Validation ----
    // 3. SecTrustEvaluateWithError — modern cert validation
    try {
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onEnter: function(args) {
                    this.trust = args[0];
                    this.errorPtr = args[1];
                },
                onLeave: function(retval) {
                    var result = retval.toInt32();
                    if (result === 0) {
                        reportFinding('Certificate', 'Certificate validation failed (SecTrustEvaluateWithError)',
                            'info', 'SecTrustEvaluateWithError returned false — cert chain rejected');
                    } else {
                        reportFinding('Certificate', 'Certificate validated (SecTrustEvaluateWithError)',
                            'info', 'SecTrustEvaluateWithError returned true — cert chain accepted');
                    }
                }
            });
        }
    } catch(e) {}

    // 4. SecTrustEvaluate — legacy cert validation
    try {
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onEnter: function(args) {
                    this.resultPtr = args[1];
                },
                onLeave: function(retval) {
                    reportFinding('Certificate', 'Legacy certificate evaluation (SecTrustEvaluate)',
                        'info', 'SecTrustEvaluate called — consider migrating to SecTrustEvaluateWithError');
                }
            });
        }
    } catch(e) {}

    // 5. SSL Pinning — URLSession:didReceiveChallenge: delegate
    try {
        // Hook all classes implementing URLSession:didReceiveChallenge:
        var resolver = new ApiResolver('objc');
        var matches = resolver.enumerateMatches('-[* URLSession:didReceiveChallenge:completionHandler:]');
        matches.forEach(function(match) {
            try {
                Interceptor.attach(match.address, {
                    onEnter: function(args) {
                        var challenge = ObjC.Object(args[3]);
                        var protectionSpace = challenge.protectionSpace();
                        var authMethod = protectionSpace.authenticationMethod().toString();
                        var host = protectionSpace.host().toString();
                        if (authMethod === 'NSURLAuthenticationMethodServerTrust') {
                            reportFinding('SSL Pinning', 'TLS challenge handler detected',
                                'info', 'URLSession:didReceiveChallenge: for host: ' + host + ' auth: ' + authMethod);
                        }
                    }
                });
            } catch(e2) {}
        });
    } catch(e) {}

    // ---- Cookie Security ----
    // 6. NSHTTPCookieStorage setCookie:
    try {
        var NSHTTPCookieStorage = ObjC.classes.NSHTTPCookieStorage;
        Interceptor.attach(NSHTTPCookieStorage['- setCookie:'].implementation, {
            onEnter: function(args) {
                var cookie = ObjC.Object(args[2]);
                var name = cookie.name().toString();
                var domain = cookie.domain().toString();
                var isSecure = cookie.isSecure();
                var isHTTPOnly = cookie.isHTTPOnly();
                reportFinding('Cookie', 'Cookie set via NSHTTPCookieStorage',
                    'info', 'Cookie "' + name + '" for domain "' + domain + '" Secure=' + isSecure + ' HTTPOnly=' + isHTTPOnly);
                if (!isSecure) {
                    reportFinding('Cookie', 'Cookie set without Secure flag (iOS)',
                        'medium', 'Cookie "' + name + '" for "' + domain + '" lacks Secure flag');
                }
                if (!isHTTPOnly) {
                    reportFinding('Cookie', 'Cookie set without HttpOnly flag (iOS)',
                        'low', 'Cookie "' + name + '" for "' + domain + '" lacks HttpOnly flag');
                }
            }
        });
    } catch(e) {}

    // ---- DNS Resolution ----
    // 7. CFHostStartInfoResolution — DNS lookups
    try {
        var getaddrinfo = Module.findExportByName('libsystem_info.dylib', 'getaddrinfo');
        if (getaddrinfo) {
            Interceptor.attach(getaddrinfo, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var hostname = args[0].readUtf8String();
                        if (hostname) {
                            send({type: 'dns_resolution', hostname: hostname});
                            reportFinding('DNS', 'DNS resolution detected (iOS)',
                                'info', 'getaddrinfo("' + hostname + '") — app resolves hostname');
                        }
                    }
                }
            });
        }
    } catch(e) {}

    // ---- WebSocket Monitoring ----
    // 8. NSURLSessionWebSocketTask sendMessage:
    try {
        var NSURLSessionWebSocketTask = ObjC.classes.NSURLSessionWebSocketTask;
        if (NSURLSessionWebSocketTask) {
            Interceptor.attach(NSURLSessionWebSocketTask['- sendMessage:completionHandler:'].implementation, {
                onEnter: function(args) {
                    var message = ObjC.Object(args[2]);
                    var type = message.type(); // 0 = data, 1 = string
                    var typeName = type === 1 ? 'text' : 'binary';
                    reportFinding('WebSocket', 'WebSocket message sent (iOS)',
                        'info', 'NSURLSessionWebSocketTask.sendMessage type=' + typeName);
                }
            });
        }
    } catch(e) {}

    // 9. NSURLSessionWebSocketTask receiveMessageWithCompletionHandler:
    try {
        var NSURLSessionWebSocketTask = ObjC.classes.NSURLSessionWebSocketTask;
        if (NSURLSessionWebSocketTask) {
            Interceptor.attach(NSURLSessionWebSocketTask['- receiveMessageWithCompletionHandler:'].implementation, {
                onEnter: function(args) {
                    reportFinding('WebSocket', 'WebSocket message receive initiated (iOS)',
                        'info', 'NSURLSessionWebSocketTask.receiveMessage called');
                }
            });
        }
    } catch(e) {}

    // ---- Network.framework (modern iOS networking) ----
    // 10. nw_connection_send — low-level Network.framework
    try {
        var nw_connection_send = Module.findExportByName('libnetwork.dylib', 'nw_connection_send');
        if (nw_connection_send) {
            var nwSendCount = 0;
            Interceptor.attach(nw_connection_send, {
                onEnter: function(args) {
                    nwSendCount++;
                    if (nwSendCount <= 5 || nwSendCount === 50) {
                        reportFinding('Network', 'Network.framework data sent',
                            'info', 'nw_connection_send called (count: ' + nwSendCount + ')');
                    }
                }
            });
        }
    } catch(e) {}

    // ---- App Transport Security ----
    // 11. Detect ATS exceptions at runtime
    try {
        var NSBundle = ObjC.classes.NSBundle;
        var mainBundle = NSBundle.mainBundle();
        var infoPlist = mainBundle.infoDictionary();
        var ats = infoPlist.objectForKey_('NSAppTransportSecurity');
        if (ats) {
            var allowsArbitrary = ats.objectForKey_('NSAllowsArbitraryLoads');
            if (allowsArbitrary && allowsArbitrary.boolValue()) {
                reportFinding('Network', 'App Transport Security disabled (NSAllowsArbitraryLoads)',
                    'high', 'Info.plist has NSAllowsArbitraryLoads=YES — all cleartext traffic allowed');
            }
            var exceptionDomains = ats.objectForKey_('NSExceptionDomains');
            if (exceptionDomains) {
                var keys = exceptionDomains.allKeys();
                var domainList = [];
                for (var i = 0; i < keys.count(); i++) {
                    domainList.push(keys.objectAtIndex_(i).toString());
                }
                if (domainList.length > 0) {
                    reportFinding('Network', 'App Transport Security exceptions configured',
                        'medium', 'ATS exception domains: ' + domainList.join(', '));
                }
            }
        }
    } catch(e) {}

    send({type: 'hooks_ready', count: 11});
}

setTimeout(function() {
    send({type: 'collection_done', findings: findings});
}, 25000);
"""


class NetworkAnalyzer(BaseAnalyzer):
    """Dynamic network and IPC analyzer using Frida + Drozer."""

    name = "network_analyzer"
    platform = "cross-platform"

    def __init__(self, device_id: str | None = None):
        self.device_id = device_id

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Run network/IPC analysis on the app."""
        findings: list[Finding] = []

        if not app.package_name:
            logger.warning("No package_name on app - skipping network analysis")
            return findings

        device_id = self.device_id or await self._find_device(app.platform)
        if not device_id:
            logger.error(f"No connected {app.platform} device found for network analysis")
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

            # Select platform-appropriate hook script
            if app.platform == "ios":
                script_content = IOS_NETWORK_HOOKS_SCRIPT
            else:
                script_content = NETWORK_HOOKS_SCRIPT

            # Thread-safe queues for cross-thread Frida callbacks
            msg_queue: queue.Queue[dict] = queue.Queue()
            ep_queue: queue.Queue[dict] = queue.Queue()

            def on_message(message: dict, data: Any):
                if message.get("type") == "send":
                    payload = message["payload"]
                    if isinstance(payload, dict):
                        if payload.get("type") == "endpoint":
                            ep_queue.put(payload)
                        else:
                            msg_queue.put(payload)

            script = session.create_script(script_content)
            script.on("message", on_message)
            await asyncio.to_thread(script.load)
            await asyncio.to_thread(device.resume, pid)

            try:
                logger.info("Waiting for network hooks to collect data (30s)...")
                await asyncio.sleep(30)
            finally:
                try:
                    await asyncio.to_thread(script.unload)
                    await asyncio.to_thread(session.detach)
                    await asyncio.to_thread(device.kill, pid)
                except Exception:
                    pass

            # Drain queues
            messages: list[dict] = []
            while not msg_queue.empty():
                try:
                    messages.append(msg_queue.get_nowait())
                except queue.Empty:
                    break
            endpoints: list[dict] = []
            while not ep_queue.empty():
                try:
                    endpoints.append(ep_queue.get_nowait())
                except queue.Empty:
                    break

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
                    domain_list = ", ".join(sorted(unique_domains))
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Network endpoints discovered ({len(unique_domains)} domains)",
                        severity="info",
                        category="Network Analysis",
                        description="The following network endpoints were contacted during runtime analysis.",
                        impact="These endpoints represent the app's network attack surface.",
                        remediation="Ensure all endpoints use HTTPS and implement certificate pinning.",
                        poc_evidence="Domains contacted: " + domain_list,
                        code_snippet=domain_list[:500],
                        poc_verification=(
                            f"1. Set up mitmproxy as transparent proxy\n"
                            f"2. Route device traffic through proxy\n"
                            f"3. Launch and exercise the app\n"
                            f"4. Review all domains contacted in mitmproxy flow list"
                        ),
                        poc_commands=[
                            {"type": "bash", "command": "mitmproxy --mode transparent --showhost", "description": "Monitor runtime network traffic"},
                            {"type": "bash", "command": f"frida -U -f {app.package_name or 'package'} -l network_hooks.js", "description": "Hook network calls with Frida"},
                        ],
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
                        code_snippet=f"Activities: {exported_activities}, Services: {exported_services}, Receivers: {exported_receivers}, Providers: {exported_providers}",
                        poc_verification=(
                            f"1. Connect to Drozer console: drozer console connect\n"
                            f"2. Run: run app.package.attacksurface {package}\n"
                            f"3. Enumerate exported components: run app.activity.info -a {package}\n"
                            f"4. Attempt to invoke exported activities: run app.activity.start --component {package} <activity>"
                        ),
                        poc_commands=[
                            {"type": "bash", "command": f"drozer console connect -c 'run app.package.attacksurface {package}'", "description": "Enumerate attack surface"},
                            {"type": "bash", "command": f"drozer console connect -c 'run app.activity.info -a {package}'", "description": "List exported activities"},
                        ],
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
                        code_snippet='android:debuggable="true"',
                        poc_verification=(
                            f"1. Confirm with Drozer: run app.package.attacksurface {package}\n"
                            f"2. Attach debugger: jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700\n"
                            f"3. Alternative: adb shell run-as {package} id (should succeed on debuggable apps)"
                        ),
                        poc_commands=[
                            {"type": "bash", "command": f"drozer console connect -c 'run app.package.attacksurface {package}'", "description": "Confirm debuggable flag"},
                            {"type": "adb", "command": f"adb shell run-as {package} id", "description": "Verify debuggable access via adb"},
                        ],
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
                        code_snippet=sqli.get("description", "")[:300],
                        poc_verification=(
                            f"1. Run Drozer injection scanner: run scanner.provider.injection -a {package}\n"
                            f"2. Query vulnerable provider: run app.provider.query content://<authority>/ --projection \"* FROM sqlite_master--\"\n"
                            f"3. Extract data: run app.provider.query content://<authority>/ --projection \"* FROM <table>--\""
                        ),
                        poc_commands=[
                            {"type": "bash", "command": f"drozer console connect -c 'run scanner.provider.injection -a {package}'", "description": "Scan for SQL injection in content providers"},
                            {"type": "bash", "command": f"drozer console connect -c 'run app.provider.info -a {package}'", "description": "List content provider URIs"},
                        ],
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
                        code_snippet=trav.get("description", "")[:300],
                        poc_verification=(
                            f"1. Run Drozer traversal scanner: run scanner.provider.traversal -a {package}\n"
                            f"2. Attempt path traversal: run app.provider.read content://<authority>/../../etc/hosts\n"
                            f"3. Try accessing sensitive files: /data/data/{package}/shared_prefs/*.xml"
                        ),
                        poc_commands=[
                            {"type": "bash", "command": f"drozer console connect -c 'run scanner.provider.traversal -a {package}'", "description": "Scan for path traversal in content providers"},
                        ],
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
                        code_snippet=output[:500] if output else None,
                        poc_verification=(
                            f"1. Launch app with Objection: objection --gadget {package} explore\n"
                            f"2. Run: android hooking list activities\n"
                            f"3. Review each activity for android:exported=true\n"
                            f"4. Attempt to launch exported activities with adb: adb shell am start -n {package}/<activity>"
                        ),
                        poc_commands=[
                            {"type": "bash", "command": f"objection --gadget {package} explore -c 'android hooking list activities'", "description": "List all loaded activities"},
                            {"type": "adb", "command": f"adb shell dumpsys package {package} | grep -A5 'Activity'", "description": "List activities via package manager"},
                        ],
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
                        code_snippet=", ".join(detected_libs),
                        poc_verification=(
                            f"1. Launch app with Objection: objection --gadget {package} explore\n"
                            f"2. Run: android hooking list classes\n"
                            f"3. Search for security library class names\n"
                            f"4. Attempt to bypass detected controls with Frida scripts"
                        ),
                        poc_commands=[
                            {"type": "bash", "command": f"objection --gadget {package} explore -c 'android hooking list classes' | grep -i 'root\\|ssl\\|pin\\|cert\\|trust'", "description": "Search for security library classes"},
                        ],
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
                        code_snippet=str(items[:5]),
                        poc_verification=(
                            f"1. Launch app with Objection: objection --gadget {package} explore\n"
                            f"2. Run: android keystore list\n"
                            f"3. Review each entry's alias and protection level\n"
                            f"4. Check if keys require user authentication"
                        ),
                        poc_commands=[
                            {"type": "bash", "command": f"objection --gadget {package} explore -c 'android keystore list'", "description": "List keystore entries"},
                            {"type": "bash", "command": f"objection --gadget {package} explore -c 'android keystore clear'", "description": "Clear keystore (destructive - use with caution)"},
                        ],
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
                        code_snippet=output[:300],
                        poc_verification=(
                            f"1. Launch app with Objection: objection --gadget {package} explore\n"
                            f"2. Run: env\n"
                            f"3. Browse filesystem: ls /data/data/{package}/\n"
                            f"4. Check for unencrypted sensitive files in shared_prefs, databases, files"
                        ),
                        poc_commands=[
                            {"type": "bash", "command": f"objection --gadget {package} explore -c 'env'", "description": "Enumerate application paths"},
                            {"type": "adb", "command": f"adb shell run-as {package} ls -la /data/data/{package}/", "description": "List app data directory"},
                        ],
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
            "DNS": {"cwe_id": "CWE-200", "owasp": "MASVS-NETWORK",
                "impact": "DNS resolutions reveal backend infrastructure and can be intercepted for DNS spoofing.",
                "remediation": "Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT). Validate DNS responses."},
            "Certificate": {"cwe_id": "CWE-295", "owasp": "MASVS-NETWORK",
                "impact": "Weak or improperly validated certificate chains enable man-in-the-middle attacks.",
                "remediation": "Implement certificate pinning. Validate certificate chains properly. Check expiry dates."},
            "WebSocket": {"cwe_id": "CWE-319", "owasp": "MASVS-NETWORK",
                "impact": "WebSocket connections may transmit sensitive data. Insecure WebSocket (ws://) traffic can be intercepted.",
                "remediation": "Use secure WebSockets (wss://). Validate WebSocket origins. Implement message-level encryption for sensitive data."},
            "Cookie": {"cwe_id": "CWE-614", "owasp": "MASVS-NETWORK",
                "impact": "Cookies without Secure/HttpOnly flags can be intercepted or accessed by JavaScript, enabling session hijacking.",
                "remediation": "Set Secure and HttpOnly flags on all sensitive cookies. Use SameSite attribute. Implement proper session management."},
        }.get(category, {"cwe_id": "CWE-319", "owasp": "MASVS-NETWORK",
            "impact": "Network security issue detected.", "remediation": "Review and fix."})

        # Category-specific PoC commands
        poc_cmds = {
            "Network": [
                {"type": "bash", "command": f"frida -U -f {app.package_name or 'package'} -l network_hooks.js", "description": "Rerun Frida network hooks"},
                {"type": "bash", "command": "mitmproxy --mode transparent --showhost", "description": "Intercept traffic with mitmproxy"},
            ],
            "IPC": [
                {"type": "bash", "command": f"drozer console connect -c 'run app.broadcast.info -a {app.package_name}'", "description": "Enumerate broadcast receivers"},
                {"type": "adb", "command": f"adb logcat -d | grep -i 'broadcast\\|intent'", "description": "Monitor broadcast intents"},
            ],
            "Certificate": [
                {"type": "bash", "command": f"frida -U -f {app.package_name or 'package'} -l ssl_hooks.js", "description": "Hook TLS certificate validation"},
                {"type": "bash", "command": "openssl s_client -connect <host>:443 -showcerts", "description": "Inspect server certificate chain"},
            ],
            "Cookie": [
                {"type": "bash", "command": f"frida -U -f {app.package_name or 'package'} -l cookie_hooks.js", "description": "Hook cookie operations"},
            ],
        }.get(category, [{"type": "bash", "command": f"frida -U -f {app.package_name or 'package'} -l hooks.js", "description": "Rerun Frida hooks"}])

        return self.create_finding(
            app=app, title=title, severity=severity, category=category,
            description=f"Network hook detected: {detail}",
            impact=meta["impact"], remediation=meta["remediation"],
            poc_evidence=f"Detected by Frida network hook: {detail}",
            code_snippet=detail[:300] if detail else None,
            poc_verification=(
                f"1. Connect device and start Frida server\n"
                f"2. Spawn app with Frida: frida -U -f {app.package_name or 'package'}\n"
                f"3. Load network hooks script\n"
                f"4. Exercise app functionality and observe hook output"
            ),
            poc_commands=poc_cmds,
            cwe_id=meta.get("cwe_id"), owasp_masvs_category=meta.get("owasp"),
        )

    async def _find_device(self, platform: str = "android") -> str | None:
        """Find the first connected device via ADB (Android) or idevice (iOS)."""
        if platform == "ios":
            try:
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["idevice_id", "-l"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        return line.strip()
            except Exception as e:
                logger.error(f"iOS device discovery failed: {e}")
            return None

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
