"""Built-in Frida scripts for Mobilicustos.

Each script is a complete, ready-to-inject JavaScript string targeting
either Android (Java.perform) or iOS (ObjC.classes) runtimes.
Console markers: [+] success, [-] failure/block, [*] info/monitor.
"""

BUILTIN_SCRIPTS: list[dict] = [
    # =========================================================================
    # 1. bypass/root - Generic Root Detection Bypass (Android)
    # =========================================================================
    {
        "script_name": "root_bypass_generic",
        "category": "bypass",
        "subcategory": "root",
        "description": (
            "Generic Android root-detection bypass. Hooks java.io.File.exists() "
            "to hide su/magisk/busybox paths, Runtime.exec() to block 'which su' "
            "and 'id' commands, and SystemProperties.get() for ro.debuggable/ro.secure."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'root_bypass_generic';

    // --- Paths that indicate a rooted device ---
    var rootIndicators = [
        '/system/app/Superuser.apk',
        '/system/xbin/su',
        '/system/bin/su',
        '/sbin/su',
        '/data/local/xbin/su',
        '/data/local/bin/su',
        '/data/local/su',
        '/su/bin/su',
        '/system/bin/.ext/.su',
        '/system/usr/we-need-root/su-backup',
        '/system/xbin/mu',
        '/system/app/Superuser/',
        '/system/etc/init.d/99telecom',
        '/data/adb/magisk',
        '/sbin/.magisk',
        '/cache/.disable_magisk',
        '/dev/.magisk.unblock',
        '/data/adb/modules',
        '/system/xbin/busybox',
        '/system/bin/busybox',
        '/sbin/busybox',
        '/data/local/xbin/busybox',
        '/data/local/bin/busybox',
        '/system/sd/xbin/busybox',
        '/system/xbin/daemonsu',
        '/system/bin/failsafe/su',
    ];

    // --- 1. Hook File.exists() ---
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootIndicators.length; i++) {
            if (path === rootIndicators[i]) {
                console.log('[+] ' + TAG + ': File.exists("' + path + '") -> false');
                return false;
            }
        }
        // Also check for su binary in common directories
        if (path.endsWith('/su') && path.indexOf('sugar') === -1 && path.indexOf('surf') === -1) {
            console.log('[+] ' + TAG + ': File.exists("' + path + '") -> false (su binary)');
            return false;
        }
        return this.exists.call(this);
    };

    // --- 2. Hook Runtime.exec() variants ---
    var Runtime = Java.use('java.lang.Runtime');

    var blockedCommands = ['which su', 'su', 'id', '/system/xbin/which su', 'busybox'];

    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        for (var i = 0; i < blockedCommands.length; i++) {
            if (cmd.indexOf(blockedCommands[i]) !== -1) {
                console.log('[+] ' + TAG + ': Runtime.exec("' + cmd + '") -> blocked');
                throw Java.use('java.io.IOException').$new('Permission denied');
            }
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
        var joined = '';
        for (var j = 0; j < cmdArray.length; j++) {
            joined += cmdArray[j] + ' ';
        }
        for (var i = 0; i < blockedCommands.length; i++) {
            if (joined.indexOf(blockedCommands[i]) !== -1) {
                console.log('[+] ' + TAG + ': Runtime.exec([' + joined.trim() + ']) -> blocked');
                throw Java.use('java.io.IOException').$new('Permission denied');
            }
        }
        return this.exec(cmdArray);
    };

    // --- 3. Hook SystemProperties.get() ---
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            if (key === 'ro.debuggable') {
                console.log('[+] ' + TAG + ': SystemProperties.get("ro.debuggable") -> "0"');
                return '0';
            }
            if (key === 'ro.secure') {
                console.log('[+] ' + TAG + ': SystemProperties.get("ro.secure") -> "1"');
                return '1';
            }
            if (key === 'ro.build.selinux') {
                console.log('[+] ' + TAG + ': SystemProperties.get("ro.build.selinux") -> "1"');
                return '1';
            }
            if (key === 'ro.build.tags') {
                console.log('[+] ' + TAG + ': SystemProperties.get("ro.build.tags") -> "release-keys"');
                return 'release-keys';
            }
            return this.get(key);
        };

        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
            if (key === 'ro.debuggable') {
                console.log('[+] ' + TAG + ': SystemProperties.get("ro.debuggable", def) -> "0"');
                return '0';
            }
            if (key === 'ro.secure') {
                console.log('[+] ' + TAG + ': SystemProperties.get("ro.secure", def) -> "1"');
                return '1';
            }
            if (key === 'ro.build.tags') {
                return 'release-keys';
            }
            return this.get(key, def);
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': SystemProperties hook failed: ' + e);
    }

    // --- 4. Hook Build.TAGS ---
    try {
        var Build = Java.use('android.os.Build');
        var tags = Build.TAGS.value;
        if (tags && tags.indexOf('test-keys') !== -1) {
            Build.TAGS.value = 'release-keys';
            console.log('[+] ' + TAG + ': Build.TAGS patched to "release-keys"');
        }
    } catch (e) {
        console.log('[-] ' + TAG + ': Build.TAGS patch failed: ' + e);
    }

    // --- 5. Hook PackageManager for root app detection ---
    try {
        var ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
        var rootPackages = [
            'com.topjohnwu.magisk',
            'eu.chainfire.supersu',
            'com.koushikdutta.superuser',
            'com.noshufou.android.su',
            'com.thirdparty.superuser',
            'com.yellowes.su',
            'com.zachspong.temprootremovejb',
            'com.ramdroid.appquarantine',
            'com.amphoras.hidemyroot',
            'com.saurik.substrate',
            'de.robv.android.xposed.installer',
        ];
        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (pkg === rootPackages[i]) {
                    console.log('[+] ' + TAG + ': getPackageInfo("' + pkg + '") -> NameNotFoundException');
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
                }
            }
            return this.getPackageInfo(pkg, flags);
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': PackageManager hook failed: ' + e);
    }

    console.log('[+] ' + TAG + ': All root bypass hooks installed');
});
""",
    },

    # =========================================================================
    # 2. bypass/root - RootBeer Library Bypass (Android)
    # =========================================================================
    {
        "script_name": "root_bypass_rootbeer",
        "category": "bypass",
        "subcategory": "root",
        "description": (
            "Bypass RootBeer library (com.scottyab.rootbeer.RootBeer) root "
            "detection. Hooks isRooted(), isRootedWithoutBusyBoxCheck(), "
            "detectRootManagementApps(), detectPotentiallyDangerousApps(), "
            "checkForBinary(), checkForDangerousProps() to return false."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": ["com.scottyab.rootbeer"],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'root_bypass_rootbeer';

    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');

        RootBeer.isRooted.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.isRooted() -> false');
            return false;
        };

        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.isRootedWithoutBusyBoxCheck() -> false');
            return false;
        };

        RootBeer.detectRootManagementApps.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.detectRootManagementApps() -> false');
            return false;
        };

        RootBeer.detectPotentiallyDangerousApps.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.detectPotentiallyDangerousApps() -> false');
            return false;
        };

        RootBeer.detectTestKeys.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.detectTestKeys() -> false');
            return false;
        };

        RootBeer.checkForBinary.overload('java.lang.String').implementation = function (filename) {
            console.log('[+] ' + TAG + ': RootBeer.checkForBinary("' + filename + '") -> false');
            return false;
        };

        RootBeer.checkForDangerousProps.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.checkForDangerousProps() -> false');
            return false;
        };

        RootBeer.checkForRWPaths.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.checkForRWPaths() -> false');
            return false;
        };

        RootBeer.detectRootCloakingApps.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.detectRootCloakingApps() -> false');
            return false;
        };

        RootBeer.checkSuExists.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.checkSuExists() -> false');
            return false;
        };

        RootBeer.checkForRootNative.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.checkForRootNative() -> false');
            return false;
        };

        RootBeer.checkForMagiskBinary.implementation = function () {
            console.log('[+] ' + TAG + ': RootBeer.checkForMagiskBinary() -> false');
            return false;
        };

        console.log('[+] ' + TAG + ': All RootBeer hooks installed');
    } catch (e) {
        console.log('[-] ' + TAG + ': RootBeer class not found - library not present: ' + e);
    }

    // Also try the native RootBeerNative class
    try {
        var RootBeerNative = Java.use('com.scottyab.rootbeer.RootBeerNative');
        RootBeerNative.checkForRoot.overload('[Ljava.lang.Object;').implementation = function (pathArray) {
            console.log('[+] ' + TAG + ': RootBeerNative.checkForRoot() -> 0');
            return 0;
        };
        console.log('[+] ' + TAG + ': RootBeerNative hooks installed');
    } catch (e) {
        console.log('[-] ' + TAG + ': RootBeerNative class not found: ' + e);
    }
});
""",
    },

    # =========================================================================
    # 3. bypass/root - SafetyNet/Play Integrity Bypass (Android)
    # =========================================================================
    {
        "script_name": "root_bypass_safetynet",
        "category": "bypass",
        "subcategory": "root",
        "description": (
            "Bypass Google SafetyNet/Play Integrity attestation by hooking the "
            "response parsing to modify ctsProfileMatch and basicIntegrity to "
            "true. Also hooks Build fields commonly checked by SafetyNet."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": ["com.google.android.gms.safetynet"],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'root_bypass_safetynet';

    // --- Patch Build fields that SafetyNet checks ---
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
        Build.FINGERPRINT.value = Build.FINGERPRINT.value.replace('test-keys', 'release-keys');
        Build.TYPE.value = 'user';
        console.log('[+] ' + TAG + ': Build fields patched');
    } catch (e) {
        console.log('[-] ' + TAG + ': Build field patching failed: ' + e);
    }

    // --- Hook SafetyNetApi response ---
    try {
        var SafetyNetResponse = Java.use('com.google.android.gms.safetynet.SafetyNetApi$AttestationResponse');
        SafetyNetResponse.getJwsResult.implementation = function () {
            console.log('[*] ' + TAG + ': getJwsResult() called, intercepting...');
            var originalJws = this.getJwsResult();
            // Log original for analysis; actual modification happens at JSON parse level
            console.log('[*] ' + TAG + ': Original JWS length: ' + (originalJws ? originalJws.length : 'null'));
            return originalJws;
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': SafetyNetApi.AttestationResponse not found: ' + e);
    }

    // --- Hook JSONObject to intercept SafetyNet response parsing ---
    try {
        var JSONObject = Java.use('org.json.JSONObject');
        JSONObject.getBoolean.implementation = function (key) {
            var result = this.getBoolean(key);
            if (key === 'ctsProfileMatch' || key === 'basicIntegrity') {
                console.log('[+] ' + TAG + ': JSONObject.getBoolean("' + key + '") ' + result + ' -> true');
                return true;
            }
            return result;
        };

        JSONObject.optBoolean.overload('java.lang.String').implementation = function (key) {
            var result = this.optBoolean(key);
            if (key === 'ctsProfileMatch' || key === 'basicIntegrity') {
                console.log('[+] ' + TAG + ': JSONObject.optBoolean("' + key + '") ' + result + ' -> true');
                return true;
            }
            return result;
        };

        JSONObject.optBoolean.overload('java.lang.String', 'boolean').implementation = function (key, fallback) {
            var result = this.optBoolean(key, fallback);
            if (key === 'ctsProfileMatch' || key === 'basicIntegrity') {
                console.log('[+] ' + TAG + ': JSONObject.optBoolean("' + key + '", ' + fallback + ') ' + result + ' -> true');
                return true;
            }
            return result;
        };

        console.log('[+] ' + TAG + ': JSONObject boolean hooks installed for SafetyNet fields');
    } catch (e) {
        console.log('[-] ' + TAG + ': JSONObject hooks failed: ' + e);
    }

    // --- Hook DroidGuard (if present) ---
    try {
        var DroidGuard = Java.use('com.google.android.gms.droidguard.DroidGuardHelper');
        DroidGuard.init.implementation = function () {
            console.log('[+] ' + TAG + ': DroidGuardHelper.init() intercepted');
            return this.init();
        };
    } catch (e) {
        // DroidGuard not present, that's fine
    }

    // --- Ensure properties look clean ---
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
            if (key === 'ro.boot.verifiedbootstate') {
                console.log('[+] ' + TAG + ': SystemProperties.get("ro.boot.verifiedbootstate") -> "green"');
                return 'green';
            }
            if (key === 'ro.boot.flash.locked') {
                return '1';
            }
            if (key === 'ro.boot.vbmeta.device_state') {
                return 'locked';
            }
            return this.get(key, def);
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': SystemProperties hook failed: ' + e);
    }

    console.log('[+] ' + TAG + ': SafetyNet bypass hooks installed');
});
""",
    },

    # =========================================================================
    # 4. bypass/ssl_pinning - OkHttp3 SSL Pinning Bypass (Android)
    # =========================================================================
    {
        "script_name": "ssl_bypass_okhttp3",
        "category": "bypass",
        "subcategory": "ssl_pinning",
        "description": (
            "Bypass OkHttp3 certificate pinning by hooking "
            "okhttp3.CertificatePinner.check() and check$okhttp() to no-op."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": ["okhttp3"],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'ssl_bypass_okhttp3';

    // --- OkHttp3 CertificatePinner ---
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');

        // Hook check(String hostname, List peerCertificates)
        try {
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCerts) {
                console.log('[+] ' + TAG + ': CertificatePinner.check("' + hostname + '") -> bypassed');
                return;
            };
        } catch (e) {
            console.log('[-] ' + TAG + ': check(String, List) not found: ' + e);
        }

        // Hook check$okhttp - Kotlin variant
        try {
            CertificatePinner.check$okhttp.implementation = function (hostname, cleanedPeerCertificatesFn) {
                console.log('[+] ' + TAG + ': CertificatePinner.check$okhttp("' + hostname + '") -> bypassed');
                return;
            };
        } catch (e) {
            console.log('[-] ' + TAG + ': check$okhttp not found: ' + e);
        }

        console.log('[+] ' + TAG + ': OkHttp3 CertificatePinner hooks installed');
    } catch (e) {
        console.log('[-] ' + TAG + ': OkHttp3 CertificatePinner class not found: ' + e);
    }

    // --- OkHttp (legacy v2) ---
    try {
        var OkHttpClient = Java.use('com.squareup.okhttp.OkHttpClient');
        OkHttpClient.setCertificatePinner.implementation = function (pinner) {
            console.log('[+] ' + TAG + ': OkHttpClient.setCertificatePinner() -> bypassed');
            return this;
        };
        console.log('[+] ' + TAG + ': OkHttp v2 hooks installed');
    } catch (e) {
        // OkHttp v2 not present
    }

    console.log('[+] ' + TAG + ': OkHttp3 SSL pinning bypass active');
});
""",
    },

    # =========================================================================
    # 5. bypass/ssl_pinning - TrustManager Bypass (Android)
    # =========================================================================
    {
        "script_name": "ssl_bypass_trustmanager",
        "category": "bypass",
        "subcategory": "ssl_pinning",
        "description": (
            "Bypass Android SSL/TLS certificate validation by hooking "
            "X509TrustManager.checkServerTrusted(), checkClientTrusted() "
            "to no-op, and SSLContext.init() to use a permissive TrustManager."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'ssl_bypass_trustmanager';

    // --- Create a permissive TrustManager ---
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // --- Hook SSLContext.init() to inject permissive TrustManager ---
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (keyManagers, trustManagers, secureRandom) {
        console.log('[+] ' + TAG + ': SSLContext.init() intercepted, injecting permissive TrustManager');

        var TrustManagerImpl = Java.registerClass({
            name: 'com.mobilicustos.PermissiveTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {
                    console.log('[+] ' + TAG + ': checkClientTrusted() -> allowed');
                },
                checkServerTrusted: function (chain, authType) {
                    console.log('[+] ' + TAG + ': checkServerTrusted() -> allowed');
                },
                getAcceptedIssuers: function () {
                    return [];
                },
            },
        });

        var permissiveTm = TrustManagerImpl.$new();
        var tmArray = Java.array('javax.net.ssl.TrustManager', [permissiveTm]);
        this.init(keyManagers, tmArray, secureRandom);
    };

    // --- Hook TrustManagerFactory ---
    try {
        var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        TrustManagerFactory.getTrustManagers.implementation = function () {
            console.log('[+] ' + TAG + ': TrustManagerFactory.getTrustManagers() -> intercepted');
            var tms = this.getTrustManagers();
            return tms;
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': TrustManagerFactory hook failed: ' + e);
    }

    // --- Hook specific X509TrustManager implementations (Conscrypt) ---
    try {
        var PlatformTrustManager = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        PlatformTrustManager.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] ' + TAG + ': TrustManagerImpl.verifyChain("' + host + '") -> bypassed');
            return untrustedChain;
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': TrustManagerImpl (Conscrypt) not found: ' + e);
    }

    console.log('[+] ' + TAG + ': TrustManager SSL bypass hooks installed');
});
""",
    },

    # =========================================================================
    # 6. bypass/ssl_pinning - Universal Android SSL Bypass (Android)
    # =========================================================================
    {
        "script_name": "ssl_bypass_universal_android",
        "category": "bypass",
        "subcategory": "ssl_pinning",
        "description": (
            "Universal Android SSL pinning bypass combining: OkHttp3 "
            "CertificatePinner, X509TrustManager, SSLContext, "
            "HttpsURLConnection.setDefaultHostnameVerifier, "
            "and WebViewClient.onReceivedSslError."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'ssl_bypass_universal';

    // =================================================================
    // 1. SSLContext.init() - inject permissive TrustManager
    // =================================================================
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

    var PermissiveTM = Java.registerClass({
        name: 'com.mobilicustos.UniversalPermissiveTM',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; },
        },
    });

    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (km, tm, sr) {
        console.log('[+] ' + TAG + ': SSLContext.init() -> permissive TrustManager');
        var ptm = PermissiveTM.$new();
        var tmArr = Java.array('javax.net.ssl.TrustManager', [ptm]);
        this.init(km, tmArr, sr);
    };

    // =================================================================
    // 2. OkHttp3 CertificatePinner
    // =================================================================
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        try {
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, certs) {
                console.log('[+] ' + TAG + ': CertificatePinner.check("' + host + '") -> bypassed');
            };
        } catch (e) {}
        try {
            CertificatePinner.check$okhttp.implementation = function (host, fn) {
                console.log('[+] ' + TAG + ': CertificatePinner.check$okhttp("' + host + '") -> bypassed');
            };
        } catch (e) {}
    } catch (e) {}

    // =================================================================
    // 3. HttpsURLConnection - default HostnameVerifier
    // =================================================================
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');

        var PermissiveHV = Java.registerClass({
            name: 'com.mobilicustos.UniversalPermissiveHV',
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) {
                    console.log('[+] ' + TAG + ': HostnameVerifier.verify("' + hostname + '") -> true');
                    return true;
                },
            },
        });

        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            console.log('[+] ' + TAG + ': setDefaultHostnameVerifier() -> permissive');
            this.setDefaultHostnameVerifier(PermissiveHV.$new());
        };

        HttpsURLConnection.setHostnameVerifier.implementation = function (verifier) {
            console.log('[+] ' + TAG + ': setHostnameVerifier() -> permissive');
            this.setHostnameVerifier(PermissiveHV.$new());
        };

        HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function (factory) {
            console.log('[+] ' + TAG + ': setDefaultSSLSocketFactory() -> intercepted');
            this.setDefaultSSLSocketFactory(factory);
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': HttpsURLConnection hooks failed: ' + e);
    }

    // =================================================================
    // 4. WebViewClient.onReceivedSslError
    // =================================================================
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log('[+] ' + TAG + ': WebViewClient.onReceivedSslError() -> proceed');
            handler.proceed();
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': WebViewClient hook failed: ' + e);
    }

    // =================================================================
    // 5. Conscrypt / Platform TrustManager
    // =================================================================
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrusted, trustAnchors, host, clientAuth, ocsp, tlsSct) {
            console.log('[+] ' + TAG + ': TrustManagerImpl.verifyChain("' + host + '") -> bypassed');
            return untrusted;
        };
    } catch (e) {}

    // =================================================================
    // 6. Apache HttpClient (legacy)
    // =================================================================
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function (host, cns, subjectAlts, strictWithSubDomains) {
            console.log('[+] ' + TAG + ': AbstractVerifier.verify("' + host + '") -> bypassed');
        };
    } catch (e) {}

    console.log('[+] ' + TAG + ': Universal Android SSL pinning bypass active');
});
""",
    },

    # =========================================================================
    # 7. bypass/ssl_pinning - NSURLSession SSL Bypass (iOS)
    # =========================================================================
    {
        "script_name": "ssl_bypass_nsurlsession",
        "category": "bypass",
        "subcategory": "ssl_pinning",
        "description": (
            "Bypass iOS SSL pinning via NSURLSession by hooking "
            "URLSession:didReceiveChallenge:completionHandler: to accept "
            "all server certificates. Handles NSURLAuthenticationMethodServerTrust."
        ),
        "platforms": ["ios"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

if (ObjC.available) {
    var TAG = 'ssl_bypass_nsurlsession';

    // --- Hook NSURLSessionDelegate methods ---
    // Find all classes that implement URLSession:didReceiveChallenge:completionHandler:
    var resolver = new ApiResolver('objc');
    var matches = resolver.enumerateMatches('-[* URLSession:didReceiveChallenge:completionHandler:]');

    matches.forEach(function (match) {
        var className = match.name.split(' ')[0].substring(2);

        try {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    // args[2] = self, args[3] = _cmd
                    // args[4] = session, args[5] = challenge, args[6] = completionHandler
                    var challenge = new ObjC.Object(args[5]);
                    var protectionSpace = challenge.protectionSpace();
                    var authMethod = protectionSpace.authenticationMethod().toString();

                    if (authMethod === 'NSURLAuthenticationMethodServerTrust') {
                        var serverTrust = protectionSpace.serverTrust();
                        var host = protectionSpace.host().toString();
                        console.log('[+] ' + TAG + ': Bypassing SSL for ' + host + ' in ' + className);

                        // Call completionHandler with UseCredential disposition
                        var NSURLCredential = ObjC.classes.NSURLCredential;
                        var credential = NSURLCredential.credentialForTrust_(serverTrust);

                        // Invoke the completion handler block
                        // disposition = NSURLSessionAuthChallengeUseCredential (0)
                        var completionHandler = new ObjC.Block(args[6]);
                        completionHandler.invoke(0, credential);

                        // Prevent the original implementation from running
                        this.shouldSkip = true;
                    } else {
                        this.shouldSkip = false;
                    }
                },
                onLeave: function (retval) {
                    // No-op; the block was already called if needed
                },
            });
            console.log('[+] ' + TAG + ': Hooked ' + match.name);
        } catch (e) {
            console.log('[-] ' + TAG + ': Failed to hook ' + match.name + ': ' + e);
        }
    });

    // --- Also hook SecTrustEvaluate and SecTrustEvaluateWithError ---
    try {
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onLeave: function (retval) {
                    console.log('[+] ' + TAG + ': SecTrustEvaluate() -> errSecSuccess');
                    retval.replace(0); // errSecSuccess
                },
            });
        }
    } catch (e) {
        console.log('[-] ' + TAG + ': SecTrustEvaluate hook failed: ' + e);
    }

    try {
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onLeave: function (retval) {
                    console.log('[+] ' + TAG + ': SecTrustEvaluateWithError() -> true');
                    retval.replace(1); // true = trusted
                },
            });
        }
    } catch (e) {
        console.log('[-] ' + TAG + ': SecTrustEvaluateWithError hook failed: ' + e);
    }

    // --- Hook NSURLSession dataTaskWithRequest to log requests ---
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
            onEnter: function (args) {
                var request = new ObjC.Object(args[2]);
                console.log('[*] ' + TAG + ': NSURLSession request to ' + request.URL().absoluteString());
            },
        });
    } catch (e) {
        // Not critical
    }

    console.log('[+] ' + TAG + ': NSURLSession SSL pinning bypass active');
} else {
    console.log('[-] ssl_bypass_nsurlsession: ObjC runtime not available');
}
""",
    },

    # =========================================================================
    # 8. bypass/ssl_pinning - Alamofire SSL Bypass (iOS)
    # =========================================================================
    {
        "script_name": "ssl_bypass_alamofire",
        "category": "bypass",
        "subcategory": "ssl_pinning",
        "description": (
            "Bypass Alamofire SSL pinning by hooking ServerTrustEvaluating "
            "evaluate methods and the ServerTrustManager to accept all certs."
        ),
        "platforms": ["ios"],
        "target_frameworks": [],
        "target_libraries": ["Alamofire"],
        "is_builtin": True,
        "script_content": r"""'use strict';

if (ObjC.available) {
    var TAG = 'ssl_bypass_alamofire';
    var resolver = new ApiResolver('objc');

    // --- Alamofire 5.x: Hook ServerTrustManager.evaluate ---
    try {
        var evalMatches = resolver.enumerateMatches('-[*ServerTrustManager evaluate*]');
        evalMatches.forEach(function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    console.log('[+] ' + TAG + ': Hooked ' + match.name);
                },
                onLeave: function (retval) {
                    // Return no error (nil)
                    retval.replace(NULL);
                    console.log('[+] ' + TAG + ': ' + match.name + ' -> nil (bypass)');
                },
            });
            console.log('[+] ' + TAG + ': Attached to ' + match.name);
        });
    } catch (e) {
        console.log('[-] ' + TAG + ': ServerTrustManager.evaluate not found: ' + e);
    }

    // --- Hook ServerTrustEvaluating protocol implementations ---
    try {
        var defaultEvalMatches = resolver.enumerateMatches('-[*DefaultTrustEvaluator evaluate*]');
        defaultEvalMatches.forEach(function (match) {
            Interceptor.attach(match.address, {
                onLeave: function (retval) {
                    console.log('[+] ' + TAG + ': DefaultTrustEvaluator -> bypass');
                },
            });
        });
    } catch (e) {}

    try {
        var revocationMatches = resolver.enumerateMatches('-[*RevocationTrustEvaluator evaluate*]');
        revocationMatches.forEach(function (match) {
            Interceptor.attach(match.address, {
                onLeave: function (retval) {
                    console.log('[+] ' + TAG + ': RevocationTrustEvaluator -> bypass');
                },
            });
        });
    } catch (e) {}

    try {
        var pinnedCertMatches = resolver.enumerateMatches('-[*PinnedCertificatesTrustEvaluator evaluate*]');
        pinnedCertMatches.forEach(function (match) {
            Interceptor.attach(match.address, {
                onLeave: function (retval) {
                    console.log('[+] ' + TAG + ': PinnedCertificatesTrustEvaluator -> bypass');
                },
            });
        });
    } catch (e) {}

    try {
        var pubKeyMatches = resolver.enumerateMatches('-[*PublicKeysTrustEvaluator evaluate*]');
        pubKeyMatches.forEach(function (match) {
            Interceptor.attach(match.address, {
                onLeave: function (retval) {
                    console.log('[+] ' + TAG + ': PublicKeysTrustEvaluator -> bypass');
                },
            });
        });
    } catch (e) {}

    // --- Also hook SecTrust for completeness ---
    try {
        var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onLeave: function (retval) {
                    retval.replace(1);
                    console.log('[+] ' + TAG + ': SecTrustEvaluateWithError -> true');
                },
            });
        }
    } catch (e) {}

    console.log('[+] ' + TAG + ': Alamofire SSL pinning bypass active');
} else {
    console.log('[-] ssl_bypass_alamofire: ObjC runtime not available');
}
""",
    },

    # =========================================================================
    # 9. bypass/jailbreak - Generic Jailbreak Detection Bypass (iOS)
    # =========================================================================
    {
        "script_name": "jailbreak_bypass_generic",
        "category": "bypass",
        "subcategory": "jailbreak",
        "description": (
            "Generic iOS jailbreak detection bypass. Hooks NSFileManager "
            "fileExistsAtPath: for Cydia, substrate, bash, sshd, apt paths. "
            "Hooks UIApplication canOpenURL: for cydia://. Hides fork/popen."
        ),
        "platforms": ["ios"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

if (ObjC.available) {
    var TAG = 'jailbreak_bypass_generic';

    var jailbreakPaths = [
        '/Applications/Cydia.app',
        '/Applications/Sileo.app',
        '/Applications/Zebra.app',
        '/Applications/blackrain.app',
        '/Applications/FakeCarrier.app',
        '/Applications/Icy.app',
        '/Applications/IntelliScreen.app',
        '/Applications/MxTube.app',
        '/Applications/RockApp.app',
        '/Applications/SBSettings.app',
        '/Applications/WinterBoard.app',
        '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/Library/MobileSubstrate/DynamicLibraries',
        '/bin/bash',
        '/bin/sh',
        '/usr/sbin/sshd',
        '/usr/bin/sshd',
        '/usr/libexec/sftp-server',
        '/usr/sbin/frida-server',
        '/usr/bin/cycript',
        '/usr/local/bin/cycript',
        '/usr/lib/libcycript.dylib',
        '/etc/apt',
        '/etc/apt/sources.list.d/cydia.list',
        '/private/var/lib/apt/',
        '/private/var/lib/cydia',
        '/private/var/tmp/cydia.log',
        '/private/var/stash',
        '/private/var/mobile/Library/SBSettings/Themes',
        '/var/cache/apt',
        '/var/lib/apt',
        '/var/lib/cydia',
        '/var/log/syslog',
        '/System/Library/LaunchDaemons/com.ikey.bbot.plist',
        '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
    ];

    // --- 1. Hook NSFileManager fileExistsAtPath: ---
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter: function (args) {
            this.path = new ObjC.Object(args[2]).toString();
        },
        onLeave: function (retval) {
            for (var i = 0; i < jailbreakPaths.length; i++) {
                if (this.path === jailbreakPaths[i]) {
                    console.log('[+] ' + TAG + ': fileExistsAtPath("' + this.path + '") -> NO');
                    retval.replace(0);
                    return;
                }
            }
        },
    });

    // --- 2. Hook NSFileManager fileExistsAtPath:isDirectory: ---
    Interceptor.attach(NSFileManager['- fileExistsAtPath:isDirectory:'].implementation, {
        onEnter: function (args) {
            this.path = new ObjC.Object(args[2]).toString();
        },
        onLeave: function (retval) {
            for (var i = 0; i < jailbreakPaths.length; i++) {
                if (this.path === jailbreakPaths[i]) {
                    console.log('[+] ' + TAG + ': fileExistsAtPath:isDirectory:("' + this.path + '") -> NO');
                    retval.replace(0);
                    return;
                }
            }
        },
    });

    // --- 3. Hook UIApplication canOpenURL: ---
    try {
        var UIApplication = ObjC.classes.UIApplication;
        Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
            onEnter: function (args) {
                this.url = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                if (this.url.indexOf('cydia://') !== -1 ||
                    this.url.indexOf('sileo://') !== -1 ||
                    this.url.indexOf('zbra://') !== -1 ||
                    this.url.indexOf('filza://') !== -1) {
                    console.log('[+] ' + TAG + ': canOpenURL("' + this.url + '") -> NO');
                    retval.replace(0);
                }
            },
        });
    } catch (e) {
        console.log('[-] ' + TAG + ': UIApplication hook failed: ' + e);
    }

    // --- 4. Hook fork() to prevent fork-based detection ---
    try {
        var fork = Module.findExportByName('libSystem.B.dylib', 'fork');
        if (fork) {
            Interceptor.attach(fork, {
                onLeave: function (retval) {
                    console.log('[+] ' + TAG + ': fork() -> -1 (pretend failure)');
                    retval.replace(-1);
                },
            });
        }
    } catch (e) {}

    // --- 5. Hook popen() ---
    try {
        var popen = Module.findExportByName('libSystem.B.dylib', 'popen');
        if (popen) {
            Interceptor.attach(popen, {
                onEnter: function (args) {
                    this.cmd = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.cmd && (this.cmd.indexOf('which') !== -1 || this.cmd.indexOf('su') !== -1)) {
                        console.log('[+] ' + TAG + ': popen("' + this.cmd + '") -> NULL');
                        retval.replace(NULL);
                    }
                },
            });
        }
    } catch (e) {}

    // --- 6. Hook access() for path checks ---
    try {
        var access = Module.findExportByName('libSystem.B.dylib', 'access');
        if (access) {
            Interceptor.attach(access, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.path) {
                        for (var i = 0; i < jailbreakPaths.length; i++) {
                            if (this.path === jailbreakPaths[i]) {
                                console.log('[+] ' + TAG + ': access("' + this.path + '") -> -1');
                                retval.replace(-1);
                                return;
                            }
                        }
                    }
                },
            });
        }
    } catch (e) {}

    // --- 7. Hook stat/lstat ---
    try {
        var stat = Module.findExportByName('libSystem.B.dylib', 'stat');
        if (stat) {
            Interceptor.attach(stat, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.path) {
                        for (var i = 0; i < jailbreakPaths.length; i++) {
                            if (this.path === jailbreakPaths[i]) {
                                console.log('[+] ' + TAG + ': stat("' + this.path + '") -> -1');
                                retval.replace(-1);
                                return;
                            }
                        }
                    }
                },
            });
        }
    } catch (e) {}

    console.log('[+] ' + TAG + ': Generic jailbreak bypass active');
} else {
    console.log('[-] jailbreak_bypass_generic: ObjC runtime not available');
}
""",
    },

    # =========================================================================
    # 10. bypass/jailbreak - URL Scheme Jailbreak Bypass (iOS)
    # =========================================================================
    {
        "script_name": "jailbreak_bypass_urlscheme",
        "category": "bypass",
        "subcategory": "jailbreak",
        "description": (
            "Bypass jailbreak detection via URL scheme checks. Hooks "
            "UIApplication canOpenURL: for cydia://, sileo://, zbra://, "
            "filza://, and other jailbreak-related URL schemes."
        ),
        "platforms": ["ios"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

if (ObjC.available) {
    var TAG = 'jailbreak_bypass_urlscheme';

    var jailbreakSchemes = [
        'cydia://',
        'sileo://',
        'zbra://',
        'filza://',
        'undecimus://',
        'activator://',
        'ssh://',
    ];

    // --- Hook canOpenURL: on UIApplication ---
    try {
        var UIApplication = ObjC.classes.UIApplication;
        Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
            onEnter: function (args) {
                var url = new ObjC.Object(args[2]);
                this.urlString = url.absoluteString ? url.absoluteString().toString() : url.toString();
                this.scheme = url.scheme ? url.scheme().toString() : '';
            },
            onLeave: function (retval) {
                for (var i = 0; i < jailbreakSchemes.length; i++) {
                    if (this.urlString.indexOf(jailbreakSchemes[i]) === 0 ||
                        this.scheme + '://' === jailbreakSchemes[i]) {
                        console.log('[+] ' + TAG + ': canOpenURL("' + this.urlString + '") -> NO');
                        retval.replace(0);
                        return;
                    }
                }
            },
        });
        console.log('[+] ' + TAG + ': canOpenURL hook installed');
    } catch (e) {
        console.log('[-] ' + TAG + ': UIApplication canOpenURL hook failed: ' + e);
    }

    // --- Hook openURL: (deprecated but still used) ---
    try {
        Interceptor.attach(ObjC.classes.UIApplication['- openURL:'].implementation, {
            onEnter: function (args) {
                var url = new ObjC.Object(args[2]);
                this.urlString = url.absoluteString ? url.absoluteString().toString() : url.toString();
            },
            onLeave: function (retval) {
                for (var i = 0; i < jailbreakSchemes.length; i++) {
                    if (this.urlString.indexOf(jailbreakSchemes[i]) === 0) {
                        console.log('[+] ' + TAG + ': openURL("' + this.urlString + '") -> NO');
                        retval.replace(0);
                        return;
                    }
                }
            },
        });
    } catch (e) {}

    // --- Hook openURL:options:completionHandler: (iOS 10+) ---
    try {
        Interceptor.attach(ObjC.classes.UIApplication['- openURL:options:completionHandler:'].implementation, {
            onEnter: function (args) {
                var url = new ObjC.Object(args[2]);
                this.urlString = url.absoluteString ? url.absoluteString().toString() : url.toString();
                this.blocked = false;
                for (var i = 0; i < jailbreakSchemes.length; i++) {
                    if (this.urlString.indexOf(jailbreakSchemes[i]) === 0) {
                        console.log('[+] ' + TAG + ': openURL:options:completionHandler:("' + this.urlString + '") -> blocked');
                        this.blocked = true;
                        break;
                    }
                }
            },
        });
    } catch (e) {}

    // --- Also hook LSApplicationWorkspace for canOpenURL fallback ---
    try {
        var LSAppWorkspace = ObjC.classes.LSApplicationWorkspace;
        if (LSAppWorkspace) {
            Interceptor.attach(LSAppWorkspace['- applicationIsInstalled:'].implementation, {
                onEnter: function (args) {
                    this.bundleId = new ObjC.Object(args[2]).toString();
                },
                onLeave: function (retval) {
                    var jailbreakApps = [
                        'com.saurik.Cydia',
                        'org.coolstar.SileoStore',
                        'xyz.willy.Zebra',
                        'com.tigisoftware.Filza',
                    ];
                    for (var i = 0; i < jailbreakApps.length; i++) {
                        if (this.bundleId === jailbreakApps[i]) {
                            console.log('[+] ' + TAG + ': applicationIsInstalled("' + this.bundleId + '") -> NO');
                            retval.replace(0);
                            return;
                        }
                    }
                },
            });
        }
    } catch (e) {}

    console.log('[+] ' + TAG + ': URL scheme jailbreak bypass active');
} else {
    console.log('[-] jailbreak_bypass_urlscheme: ObjC runtime not available');
}
""",
    },

    # =========================================================================
    # 11. bypass/frida - Frida Detection Bypass (Android + iOS)
    # =========================================================================
    {
        "script_name": "frida_bypass_generic",
        "category": "bypass",
        "subcategory": "frida",
        "description": (
            "Hide Frida presence from detection. Hides port 27042 listener, "
            "hides frida thread names (gum-js-loop, gmain, linjector, etc.), "
            "hooks open() to filter frida strings from /proc/self/maps, "
            "and hides frida named pipes."
        ),
        "platforms": ["android", "ios"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

var TAG = 'frida_bypass_generic';

// =====================================================================
// 1. Hide /proc/self/maps frida references (Android)
// =====================================================================
if (Java && Java.available) {
    // Hook libc open/read to filter frida from /proc/self/maps
    var libc = Process.findModuleByName('libc.so');

    if (libc) {
        var openPtr = Module.findExportByName('libc.so', 'open');
        var readPtr = Module.findExportByName('libc.so', 'read');
        var mapsFds = {};

        if (openPtr) {
            Interceptor.attach(openPtr, {
                onEnter: function (args) {
                    try {
                        var path = args[0].readUtf8String();
                        if (path && (path.indexOf('/proc/self/maps') !== -1 ||
                                     path.indexOf('/proc/' + Process.id + '/maps') !== -1)) {
                            this.isMaps = true;
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.isMaps) {
                        var fd = retval.toInt32();
                        if (fd > 0) {
                            mapsFds[fd] = true;
                            console.log('[+] ' + TAG + ': Tracking maps fd ' + fd);
                        }
                    }
                },
            });
        }

        // Filter frida strings from read() on /proc/self/maps
        if (readPtr) {
            Interceptor.attach(readPtr, {
                onEnter: function (args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    this.size = args[2].toInt32();
                },
                onLeave: function (retval) {
                    if (mapsFds[this.fd]) {
                        var bytesRead = retval.toInt32();
                        if (bytesRead > 0) {
                            try {
                                var content = this.buf.readUtf8String(bytesRead);
                                if (content.indexOf('frida') !== -1 ||
                                    content.indexOf('gadget') !== -1 ||
                                    content.indexOf('linjector') !== -1) {
                                    var lines = content.split('\n');
                                    var filtered = [];
                                    for (var i = 0; i < lines.length; i++) {
                                        if (lines[i].indexOf('frida') === -1 &&
                                            lines[i].indexOf('gadget') === -1 &&
                                            lines[i].indexOf('linjector') === -1) {
                                            filtered.push(lines[i]);
                                        }
                                    }
                                    var newContent = filtered.join('\n');
                                    this.buf.writeUtf8String(newContent);
                                    retval.replace(newContent.length);
                                    console.log('[+] ' + TAG + ': Filtered frida from /proc/self/maps');
                                }
                            } catch (e) {
                                // binary data, skip
                            }
                        }
                    }
                },
            });
        }
    }
}

// =====================================================================
// 2. Hide port 27042 (default Frida server port)
// =====================================================================
try {
    var connectPtr = Module.findExportByName(null, 'connect');
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                var sockAddr = args[1];
                // sockaddr_in: family(2) + port(2) + addr(4)
                var family = sockAddr.readU16();
                if (family === 2) { // AF_INET
                    var port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
                    if (port === 27042) {
                        console.log('[+] ' + TAG + ': connect() to port 27042 -> ECONNREFUSED');
                        this.blockConnect = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.blockConnect) {
                    retval.replace(-1);
                }
            },
        });
    }
} catch (e) {
    console.log('[-] ' + TAG + ': Port hiding hook failed: ' + e);
}

// =====================================================================
// 3. Hide frida named pipes and tmp files
// =====================================================================
try {
    var openat = Module.findExportByName(null, 'openat');
    if (openat) {
        Interceptor.attach(openat, {
            onEnter: function (args) {
                try {
                    var path = args[1].readUtf8String();
                    if (path && (path.indexOf('frida') !== -1 ||
                                 path.indexOf('linjector') !== -1 ||
                                 path.indexOf('gadget') !== -1)) {
                        console.log('[+] ' + TAG + ': openat("' + path + '") -> blocked');
                        this.blockOpen = true;
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (this.blockOpen) {
                    retval.replace(-1);
                }
            },
        });
    }
} catch (e) {}

// =====================================================================
// 4. Android-specific: Hook Java-level detection methods
// =====================================================================
if (Java && Java.available) {
    Java.perform(function () {
        // Hide frida-server from running process checks
        try {
            var BufferedReader = Java.use('java.io.BufferedReader');
            BufferedReader.readLine.overload().implementation = function () {
                var line = this.readLine();
                if (line && (line.indexOf('frida') !== -1 || line.indexOf('27042') !== -1)) {
                    console.log('[+] ' + TAG + ': BufferedReader.readLine() filtered frida line');
                    return this.readLine(); // skip to next line
                }
                return line;
            };
        } catch (e) {}
    });
}

console.log('[+] ' + TAG + ': Frida detection bypass active');
""",
    },

    # =========================================================================
    # 12. monitor/ - Crypto Operations Monitor (Android)
    # =========================================================================
    {
        "script_name": "crypto_monitor",
        "category": "monitor",
        "subcategory": None,
        "description": (
            "Monitor cryptographic operations by hooking javax.crypto.Cipher "
            "init/doFinal, MessageDigest update/digest, and Mac init/doFinal. "
            "Logs algorithm, key size, IV, and data snippets."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'crypto_monitor';

    function bytesToHex(bytes) {
        if (!bytes) return 'null';
        var hex = '';
        var len = bytes.length;
        for (var i = 0; i < Math.min(len, 32); i++) {
            var b = bytes[i] & 0xff;
            hex += ('0' + b.toString(16)).slice(-2);
        }
        if (len > 32) hex += '... (' + len + ' bytes)';
        return hex;
    }

    // --- 1. javax.crypto.Cipher ---
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
        var mode = opmode === 1 ? 'ENCRYPT' : opmode === 2 ? 'DECRYPT' : 'MODE_' + opmode;
        var algo = this.getAlgorithm();
        console.log('[*] ' + TAG + ': Cipher.init(' + mode + ')');
        console.log('    Algorithm: ' + algo);
        console.log('    Key algo:  ' + key.getAlgorithm());
        console.log('    Key size:  ' + key.getEncoded().length * 8 + ' bits');
        console.log('    Key hex:   ' + bytesToHex(key.getEncoded()));
        return this.init(opmode, key);
    };

    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
        var mode = opmode === 1 ? 'ENCRYPT' : opmode === 2 ? 'DECRYPT' : 'MODE_' + opmode;
        var algo = this.getAlgorithm();
        console.log('[*] ' + TAG + ': Cipher.init(' + mode + ', params)');
        console.log('    Algorithm: ' + algo);
        console.log('    Key algo:  ' + key.getAlgorithm());
        console.log('    Key size:  ' + key.getEncoded().length * 8 + ' bits');
        console.log('    Key hex:   ' + bytesToHex(key.getEncoded()));
        try {
            var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
            var ivSpec = Java.cast(params, IvParameterSpec);
            console.log('    IV hex:    ' + bytesToHex(ivSpec.getIV()));
        } catch (e) {
            console.log('    Params:    ' + params.toString());
        }
        return this.init(opmode, key, params);
    };

    Cipher.doFinal.overload('[B').implementation = function (input) {
        var algo = this.getAlgorithm();
        console.log('[*] ' + TAG + ': Cipher.doFinal()');
        console.log('    Algorithm: ' + algo);
        console.log('    Input:     ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('    Output:    ' + bytesToHex(result));
        return result;
    };

    Cipher.doFinal.overload().implementation = function () {
        var algo = this.getAlgorithm();
        console.log('[*] ' + TAG + ': Cipher.doFinal() [no args]');
        console.log('    Algorithm: ' + algo);
        var result = this.doFinal();
        console.log('    Output:    ' + bytesToHex(result));
        return result;
    };

    // --- 2. java.security.MessageDigest ---
    var MessageDigest = Java.use('java.security.MessageDigest');

    MessageDigest.update.overload('[B').implementation = function (input) {
        console.log('[*] ' + TAG + ': MessageDigest.update()');
        console.log('    Algorithm: ' + this.getAlgorithm());
        console.log('    Input:     ' + bytesToHex(input));
        return this.update(input);
    };

    MessageDigest.digest.overload().implementation = function () {
        var result = this.digest();
        console.log('[*] ' + TAG + ': MessageDigest.digest()');
        console.log('    Algorithm: ' + this.getAlgorithm());
        console.log('    Hash:      ' + bytesToHex(result));
        return result;
    };

    MessageDigest.digest.overload('[B').implementation = function (input) {
        console.log('[*] ' + TAG + ': MessageDigest.digest(input)');
        console.log('    Algorithm: ' + this.getAlgorithm());
        console.log('    Input:     ' + bytesToHex(input));
        var result = this.digest(input);
        console.log('    Hash:      ' + bytesToHex(result));
        return result;
    };

    // --- 3. javax.crypto.Mac ---
    var Mac = Java.use('javax.crypto.Mac');

    Mac.init.overload('java.security.Key').implementation = function (key) {
        console.log('[*] ' + TAG + ': Mac.init()');
        console.log('    Algorithm: ' + this.getAlgorithm());
        console.log('    Key algo:  ' + key.getAlgorithm());
        console.log('    Key hex:   ' + bytesToHex(key.getEncoded()));
        return this.init(key);
    };

    Mac.doFinal.overload('[B').implementation = function (input) {
        console.log('[*] ' + TAG + ': Mac.doFinal()');
        console.log('    Algorithm: ' + this.getAlgorithm());
        console.log('    Input:     ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('    HMAC:      ' + bytesToHex(result));
        return result;
    };

    Mac.doFinal.overload().implementation = function () {
        var result = this.doFinal();
        console.log('[*] ' + TAG + ': Mac.doFinal() [no args]');
        console.log('    Algorithm: ' + this.getAlgorithm());
        console.log('    HMAC:      ' + bytesToHex(result));
        return result;
    };

    // --- 4. java.security.Signature ---
    try {
        var Signature = Java.use('java.security.Signature');
        Signature.sign.overload().implementation = function () {
            var result = this.sign();
            console.log('[*] ' + TAG + ': Signature.sign()');
            console.log('    Algorithm: ' + this.getAlgorithm());
            console.log('    Signature: ' + bytesToHex(result));
            return result;
        };
    } catch (e) {}

    // --- 5. SecretKeySpec construction (key material) ---
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algo) {
            console.log('[*] ' + TAG + ': SecretKeySpec("' + algo + '")');
            console.log('    Key hex:   ' + bytesToHex(keyBytes));
            console.log('    Key size:  ' + keyBytes.length * 8 + ' bits');
            return this.$init(keyBytes, algo);
        };
    } catch (e) {}

    console.log('[+] ' + TAG + ': Crypto monitoring active');
});
""",
    },

    # =========================================================================
    # 13. monitor/ - Network Monitor (Android)
    # =========================================================================
    {
        "script_name": "network_monitor",
        "category": "monitor",
        "subcategory": None,
        "description": (
            "Monitor network operations by hooking URL.openConnection(), "
            "OkHttpClient.newCall(), HttpURLConnection connect/getOutputStream. "
            "Logs URLs, HTTP methods, request headers, and response codes."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'network_monitor';

    // --- 1. java.net.URL.openConnection() ---
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function () {
        var url = this.toString();
        console.log('[*] ' + TAG + ': URL.openConnection()');
        console.log('    URL:      ' + url);
        console.log('    Protocol: ' + this.getProtocol());
        console.log('    Host:     ' + this.getHost());
        console.log('    Path:     ' + this.getPath());
        return this.openConnection();
    };

    URL.openConnection.overload('java.net.Proxy').implementation = function (proxy) {
        console.log('[*] ' + TAG + ': URL.openConnection(proxy)');
        console.log('    URL:   ' + this.toString());
        console.log('    Proxy: ' + proxy.toString());
        return this.openConnection(proxy);
    };

    // --- 2. HttpURLConnection ---
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.setRequestMethod.implementation = function (method) {
            console.log('[*] ' + TAG + ': HttpURLConnection.setRequestMethod("' + method + '")');
            console.log('    URL: ' + this.getURL().toString());
            return this.setRequestMethod(method);
        };

        HttpURLConnection.connect.implementation = function () {
            console.log('[*] ' + TAG + ': HttpURLConnection.connect()');
            console.log('    URL:    ' + this.getURL().toString());
            console.log('    Method: ' + this.getRequestMethod());
            this.connect();
        };

        HttpURLConnection.getResponseCode.implementation = function () {
            var code = this.getResponseCode();
            console.log('[*] ' + TAG + ': HttpURLConnection.getResponseCode()');
            console.log('    URL:    ' + this.getURL().toString());
            console.log('    Status: ' + code);
            return code;
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': HttpURLConnection hooks failed: ' + e);
    }

    // --- 3. HttpsURLConnection ---
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.connect.implementation = function () {
            console.log('[*] ' + TAG + ': HttpsURLConnection.connect()');
            console.log('    URL:    ' + this.getURL().toString());
            console.log('    Method: ' + this.getRequestMethod());
            this.connect();
        };
    } catch (e) {}

    // --- 4. OkHttp3 ---
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function (request) {
            console.log('[*] ' + TAG + ': OkHttpClient.newCall()');
            console.log('    URL:    ' + request.url().toString());
            console.log('    Method: ' + request.method());
            var headers = request.headers();
            var headerCount = headers.size();
            for (var i = 0; i < Math.min(headerCount, 20); i++) {
                console.log('    Header: ' + headers.name(i) + ': ' + headers.value(i));
            }
            return this.newCall(request);
        };
    } catch (e) {}

    // --- 5. OkHttp3 Response ---
    try {
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function () {
            var response = this.execute();
            var request = this.request();
            console.log('[*] ' + TAG + ': OkHttp3 Response');
            console.log('    URL:    ' + request.url().toString());
            console.log('    Status: ' + response.code() + ' ' + response.message());
            var respHeaders = response.headers();
            for (var i = 0; i < Math.min(respHeaders.size(), 10); i++) {
                console.log('    R-Header: ' + respHeaders.name(i) + ': ' + respHeaders.value(i));
            }
            return response;
        };
    } catch (e) {}

    // --- 6. WebView URL loading ---
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
            console.log('[*] ' + TAG + ': WebView.loadUrl("' + url + '")');
            return this.loadUrl(url);
        };
        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
            console.log('[*] ' + TAG + ': WebView.loadUrl("' + url + '") with headers');
            return this.loadUrl(url, headers);
        };
    } catch (e) {}

    // --- 7. Socket connections ---
    try {
        var Socket = Java.use('java.net.Socket');
        Socket.$init.overload('java.lang.String', 'int').implementation = function (host, port) {
            console.log('[*] ' + TAG + ': Socket("' + host + '", ' + port + ')');
            return this.$init(host, port);
        };
    } catch (e) {}

    console.log('[+] ' + TAG + ': Network monitoring active');
});
""",
    },

    # =========================================================================
    # 14. monitor/ - Filesystem Monitor (Android)
    # =========================================================================
    {
        "script_name": "filesystem_monitor",
        "category": "monitor",
        "subcategory": None,
        "description": (
            "Monitor filesystem operations by hooking File constructors, "
            "FileInputStream/FileOutputStream, and SharedPreferences "
            "getString/putString/edit. Logs file paths and operations."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'filesystem_monitor';

    // --- 1. File constructors ---
    var File = Java.use('java.io.File');

    File.$init.overload('java.lang.String').implementation = function (path) {
        console.log('[*] ' + TAG + ': new File("' + path + '")');
        return this.$init(path);
    };

    File.$init.overload('java.lang.String', 'java.lang.String').implementation = function (parent, child) {
        console.log('[*] ' + TAG + ': new File("' + parent + '", "' + child + '")');
        return this.$init(parent, child);
    };

    File.$init.overload('java.io.File', 'java.lang.String').implementation = function (parent, child) {
        var parentPath = parent ? parent.getAbsolutePath() : 'null';
        console.log('[*] ' + TAG + ': new File(' + parentPath + ', "' + child + '")');
        return this.$init(parent, child);
    };

    // --- 2. FileInputStream ---
    var FileInputStream = Java.use('java.io.FileInputStream');

    FileInputStream.$init.overload('java.io.File').implementation = function (file) {
        console.log('[*] ' + TAG + ': FileInputStream("' + file.getAbsolutePath() + '")');
        return this.$init(file);
    };

    FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
        console.log('[*] ' + TAG + ': FileInputStream("' + path + '")');
        return this.$init(path);
    };

    // --- 3. FileOutputStream ---
    var FileOutputStream = Java.use('java.io.FileOutputStream');

    FileOutputStream.$init.overload('java.io.File').implementation = function (file) {
        console.log('[*] ' + TAG + ': FileOutputStream("' + file.getAbsolutePath() + '")');
        return this.$init(file);
    };

    FileOutputStream.$init.overload('java.lang.String').implementation = function (path) {
        console.log('[*] ' + TAG + ': FileOutputStream("' + path + '")');
        return this.$init(path);
    };

    FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function (file, append) {
        console.log('[*] ' + TAG + ': FileOutputStream("' + file.getAbsolutePath() + '", append=' + append + ')');
        return this.$init(file, append);
    };

    // --- 4. SharedPreferences ---
    try {
        var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
        SharedPreferencesImpl.getString.implementation = function (key, defValue) {
            var result = this.getString(key, defValue);
            console.log('[*] ' + TAG + ': SharedPreferences.getString("' + key + '") -> "' +
                (result ? result.substring(0, Math.min(result.length, 100)) : 'null') + '"');
            return result;
        };

        SharedPreferencesImpl.getInt.implementation = function (key, defValue) {
            var result = this.getInt(key, defValue);
            console.log('[*] ' + TAG + ': SharedPreferences.getInt("' + key + '") -> ' + result);
            return result;
        };

        SharedPreferencesImpl.getBoolean.implementation = function (key, defValue) {
            var result = this.getBoolean(key, defValue);
            console.log('[*] ' + TAG + ': SharedPreferences.getBoolean("' + key + '") -> ' + result);
            return result;
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': SharedPreferencesImpl hooks failed: ' + e);
    }

    // --- 5. SharedPreferences.Editor ---
    try {
        var EditorImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        EditorImpl.putString.implementation = function (key, value) {
            console.log('[*] ' + TAG + ': SharedPreferences.Editor.putString("' + key + '", "' +
                (value ? value.substring(0, Math.min(value.length, 100)) : 'null') + '")');
            return this.putString(key, value);
        };

        EditorImpl.putInt.implementation = function (key, value) {
            console.log('[*] ' + TAG + ': SharedPreferences.Editor.putInt("' + key + '", ' + value + ')');
            return this.putInt(key, value);
        };

        EditorImpl.putBoolean.implementation = function (key, value) {
            console.log('[*] ' + TAG + ': SharedPreferences.Editor.putBoolean("' + key + '", ' + value + ')');
            return this.putBoolean(key, value);
        };

        EditorImpl.remove.implementation = function (key) {
            console.log('[*] ' + TAG + ': SharedPreferences.Editor.remove("' + key + '")');
            return this.remove(key);
        };

        EditorImpl.commit.implementation = function () {
            console.log('[*] ' + TAG + ': SharedPreferences.Editor.commit()');
            return this.commit();
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': SharedPreferences.Editor hooks failed: ' + e);
    }

    // --- 6. ContentResolver (content:// URIs) ---
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload(
            'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String'
        ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            console.log('[*] ' + TAG + ': ContentResolver.query("' + uri.toString() + '")');
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };

        ContentResolver.insert.implementation = function (uri, values) {
            console.log('[*] ' + TAG + ': ContentResolver.insert("' + uri.toString() + '")');
            return this.insert(uri, values);
        };
    } catch (e) {}

    // --- 7. SQLiteDatabase ---
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.openDatabase.overload(
            'java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int'
        ).implementation = function (path, factory, flags) {
            console.log('[*] ' + TAG + ': SQLiteDatabase.openDatabase("' + path + '")');
            return this.openDatabase(path, factory, flags);
        };

        SQLiteDatabase.rawQuery.implementation = function (sql, selectionArgs) {
            console.log('[*] ' + TAG + ': SQLiteDatabase.rawQuery("' + sql.substring(0, Math.min(sql.length, 200)) + '")');
            return this.rawQuery(sql, selectionArgs);
        };

        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
            console.log('[*] ' + TAG + ': SQLiteDatabase.execSQL("' + sql.substring(0, Math.min(sql.length, 200)) + '")');
            return this.execSQL(sql);
        };
    } catch (e) {}

    console.log('[+] ' + TAG + ': Filesystem monitoring active');
});
""",
    },

    # =========================================================================
    # 15. monitor/ - Clipboard Monitor (Android)
    # =========================================================================
    {
        "script_name": "clipboard_monitor",
        "category": "monitor",
        "subcategory": None,
        "description": (
            "Monitor clipboard operations by hooking ClipboardManager "
            "setPrimaryClip/getPrimaryClip. Logs clipboard data content "
            "including text, URIs, and intents."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'clipboard_monitor';

    // --- 1. ClipboardManager.setPrimaryClip ---
    var ClipboardManager = Java.use('android.content.ClipboardManager');

    ClipboardManager.setPrimaryClip.implementation = function (clip) {
        console.log('[*] ' + TAG + ': setPrimaryClip()');
        try {
            var itemCount = clip.getItemCount();
            console.log('    Label:      ' + clip.getDescription().getLabel());
            console.log('    Item count: ' + itemCount);
            for (var i = 0; i < itemCount; i++) {
                var item = clip.getItemAt(i);
                var text = item.getText();
                var uri = item.getUri();
                var intent = item.getIntent();
                if (text) {
                    var textStr = text.toString();
                    console.log('    Text[' + i + ']:  "' + textStr.substring(0, Math.min(textStr.length, 500)) + '"');
                }
                if (uri) {
                    console.log('    URI[' + i + ']:   ' + uri.toString());
                }
                if (intent) {
                    console.log('    Intent[' + i + ']: ' + intent.toString());
                }
            }
        } catch (e) {
            console.log('    [parse error]: ' + e);
        }

        // Log stack trace to find the caller
        console.log('    Caller:');
        var stack = Java.use('java.lang.Thread').currentThread().getStackTrace();
        for (var s = 2; s < Math.min(stack.length, 8); s++) {
            console.log('      ' + stack[s].toString());
        }

        return this.setPrimaryClip(clip);
    };

    // --- 2. ClipboardManager.getPrimaryClip ---
    ClipboardManager.getPrimaryClip.implementation = function () {
        var clip = this.getPrimaryClip();
        console.log('[*] ' + TAG + ': getPrimaryClip()');
        if (clip) {
            try {
                var itemCount = clip.getItemCount();
                console.log('    Item count: ' + itemCount);
                for (var i = 0; i < itemCount; i++) {
                    var item = clip.getItemAt(i);
                    var text = item.getText();
                    if (text) {
                        var textStr = text.toString();
                        console.log('    Text[' + i + ']: "' + textStr.substring(0, Math.min(textStr.length, 500)) + '"');
                    }
                }
            } catch (e) {
                console.log('    [parse error]: ' + e);
            }
        } else {
            console.log('    Clipboard is empty');
        }

        // Log caller
        console.log('    Caller:');
        var stack = Java.use('java.lang.Thread').currentThread().getStackTrace();
        for (var s = 2; s < Math.min(stack.length, 8); s++) {
            console.log('      ' + stack[s].toString());
        }

        return clip;
    };

    // --- 3. ClipboardManager.getPrimaryClipDescription ---
    try {
        ClipboardManager.getPrimaryClipDescription.implementation = function () {
            var desc = this.getPrimaryClipDescription();
            if (desc) {
                console.log('[*] ' + TAG + ': getPrimaryClipDescription()');
                console.log('    Label:     ' + desc.getLabel());
                console.log('    MimeTypes: ' + desc.getMimeTypeCount() + ' types');
            }
            return desc;
        };
    } catch (e) {}

    // --- 4. ClipboardManager.hasPrimaryClip ---
    ClipboardManager.hasPrimaryClip.implementation = function () {
        var has = this.hasPrimaryClip();
        console.log('[*] ' + TAG + ': hasPrimaryClip() -> ' + has);
        return has;
    };

    // --- 5. ClipData.newPlainText (static creation) ---
    try {
        var ClipData = Java.use('android.content.ClipData');
        ClipData.newPlainText.implementation = function (label, text) {
            console.log('[*] ' + TAG + ': ClipData.newPlainText("' + label + '", "' +
                (text ? text.toString().substring(0, Math.min(text.toString().length, 200)) : 'null') + '")');
            return this.newPlainText(label, text);
        };
    } catch (e) {}

    console.log('[+] ' + TAG + ': Clipboard monitoring active');
});
""",
    },

    # =========================================================================
    # 16. exploit/ - Intent Intercept (Android)
    # =========================================================================
    {
        "script_name": "intent_intercept",
        "category": "exploit",
        "subcategory": None,
        "description": (
            "Intercept and log Android Intent operations: startActivity(), "
            "sendBroadcast(), startService(). Logs intent action, data URI, "
            "extras bundle, component name, and flags."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'intent_intercept';

    function dumpIntent(intent) {
        var info = {};
        try {
            var action = intent.getAction();
            if (action) info.action = action.toString();

            var data = intent.getData();
            if (data) info.data = data.toString();

            var type = intent.getType();
            if (type) info.type = type.toString();

            var component = intent.getComponent();
            if (component) info.component = component.flattenToString();

            var categories = intent.getCategories();
            if (categories) {
                var catArray = [];
                var iter = categories.iterator();
                while (iter.hasNext()) {
                    catArray.push(iter.next().toString());
                }
                info.categories = catArray;
            }

            var flags = intent.getFlags();
            info.flags = '0x' + (flags >>> 0).toString(16);

            // Dump extras
            var extras = intent.getExtras();
            if (extras) {
                var keys = extras.keySet();
                var iter = keys.iterator();
                var extrasObj = {};
                while (iter.hasNext()) {
                    var key = iter.next().toString();
                    try {
                        var value = extras.get(key);
                        extrasObj[key] = value ? value.toString().substring(0, 200) : 'null';
                    } catch (e) {
                        extrasObj[key] = '[error reading]';
                    }
                }
                info.extras = extrasObj;
            }
        } catch (e) {
            info.error = e.toString();
        }
        return JSON.stringify(info, null, 2);
    }

    // --- 1. Activity.startActivity ---
    var Activity = Java.use('android.app.Activity');

    Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
        console.log('[*] ' + TAG + ': startActivity()');
        console.log(dumpIntent(intent));
        return this.startActivity(intent);
    };

    Activity.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function (intent, options) {
        console.log('[*] ' + TAG + ': startActivity(intent, options)');
        console.log(dumpIntent(intent));
        return this.startActivity(intent, options);
    };

    // --- 2. Activity.startActivityForResult ---
    Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function (intent, requestCode) {
        console.log('[*] ' + TAG + ': startActivityForResult(requestCode=' + requestCode + ')');
        console.log(dumpIntent(intent));
        return this.startActivityForResult(intent, requestCode);
    };

    // --- 3. Context.sendBroadcast ---
    try {
        var ContextWrapper = Java.use('android.content.ContextWrapper');
        ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function (intent) {
            console.log('[*] ' + TAG + ': sendBroadcast()');
            console.log(dumpIntent(intent));
            return this.sendBroadcast(intent);
        };

        ContextWrapper.sendBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function (intent, receiverPermission) {
            console.log('[*] ' + TAG + ': sendBroadcast(permission="' + receiverPermission + '")');
            console.log(dumpIntent(intent));
            return this.sendBroadcast(intent, receiverPermission);
        };

        // --- 4. Context.startService ---
        ContextWrapper.startService.implementation = function (intent) {
            console.log('[*] ' + TAG + ': startService()');
            console.log(dumpIntent(intent));
            return this.startService(intent);
        };

        // --- 5. Context.sendOrderedBroadcast ---
        ContextWrapper.sendOrderedBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function (intent, receiverPermission) {
            console.log('[*] ' + TAG + ': sendOrderedBroadcast()');
            console.log(dumpIntent(intent));
            return this.sendOrderedBroadcast(intent, receiverPermission);
        };
    } catch (e) {
        console.log('[-] ' + TAG + ': ContextWrapper hooks failed: ' + e);
    }

    // --- 6. Context.startForegroundService (API 26+) ---
    try {
        var ContextWrapper = Java.use('android.content.ContextWrapper');
        ContextWrapper.startForegroundService.implementation = function (intent) {
            console.log('[*] ' + TAG + ': startForegroundService()');
            console.log(dumpIntent(intent));
            return this.startForegroundService(intent);
        };
    } catch (e) {
        // API level may not support this
    }

    // --- 7. PendingIntent creation ---
    try {
        var PendingIntent = Java.use('android.app.PendingIntent');
        PendingIntent.getActivity.overload('android.content.Context', 'int', 'android.content.Intent', 'int').implementation = function (ctx, requestCode, intent, flags) {
            console.log('[*] ' + TAG + ': PendingIntent.getActivity(requestCode=' + requestCode + ')');
            console.log(dumpIntent(intent));
            return this.getActivity(ctx, requestCode, intent, flags);
        };

        PendingIntent.getBroadcast.overload('android.content.Context', 'int', 'android.content.Intent', 'int').implementation = function (ctx, requestCode, intent, flags) {
            console.log('[*] ' + TAG + ': PendingIntent.getBroadcast(requestCode=' + requestCode + ')');
            console.log(dumpIntent(intent));
            return this.getBroadcast(ctx, requestCode, intent, flags);
        };

        PendingIntent.getService.overload('android.content.Context', 'int', 'android.content.Intent', 'int').implementation = function (ctx, requestCode, intent, flags) {
            console.log('[*] ' + TAG + ': PendingIntent.getService(requestCode=' + requestCode + ')');
            console.log(dumpIntent(intent));
            return this.getService(ctx, requestCode, intent, flags);
        };
    } catch (e) {}

    console.log('[+] ' + TAG + ': Intent interception active');
});
""",
    },

    # =========================================================================
    # 17. recon/ - App Recon (Android)
    # =========================================================================
    {
        "script_name": "app_recon",
        "category": "recon",
        "subcategory": None,
        "description": (
            "Enumerate loaded classes and app components. Find classes matching "
            "patterns (Activity, Service, Receiver, Provider, WebView). "
            "List registered content providers. Get app info and permissions."
        ),
        "platforms": ["android"],
        "target_frameworks": [],
        "target_libraries": [],
        "is_builtin": True,
        "script_content": r"""'use strict';

Java.perform(function () {
    var TAG = 'app_recon';

    // --- Get application context ---
    var context = null;
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var currentApp = ActivityThread.currentApplication();
        context = currentApp.getApplicationContext();
    } catch (e) {
        console.log('[-] ' + TAG + ': Could not get application context: ' + e);
    }

    // --- 1. App Info ---
    if (context) {
        try {
            var pm = context.getPackageManager();
            var packageName = context.getPackageName();
            var appInfo = pm.getApplicationInfo(packageName, 0);
            var pkgInfo = pm.getPackageInfo(packageName, 0);

            console.log('[*] ' + TAG + ': === Application Info ===');
            console.log('    Package:     ' + packageName);
            console.log('    Version:     ' + pkgInfo.versionName + ' (' + pkgInfo.versionCode + ')');
            console.log('    Target SDK:  ' + appInfo.targetSdkVersion);
            console.log('    Min SDK:     ' + appInfo.minSdkVersion);
            console.log('    Source Dir:  ' + appInfo.sourceDir);
            console.log('    Data Dir:    ' + appInfo.dataDir);
            console.log('    Native Dir:  ' + appInfo.nativeLibraryDir);
            console.log('    UID:         ' + appInfo.uid);
            console.log('    Debuggable:  ' + ((appInfo.flags & 0x2) !== 0));
            console.log('    Backup:      ' + ((appInfo.flags & 0x8000) !== 0));
        } catch (e) {
            console.log('[-] ' + TAG + ': App info failed: ' + e);
        }
    }

    // --- 2. Permissions ---
    if (context) {
        try {
            var PackageManager = Java.use('android.content.pm.PackageManager');
            var pm = context.getPackageManager();
            var pkgInfo = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_PERMISSIONS.value);
            var permissions = pkgInfo.requestedPermissions.value;

            console.log('[*] ' + TAG + ': === Requested Permissions (' + permissions.length + ') ===');
            for (var i = 0; i < permissions.length; i++) {
                console.log('    ' + permissions[i]);
            }
        } catch (e) {
            console.log('[-] ' + TAG + ': Permissions enumeration failed: ' + e);
        }
    }

    // --- 3. Enumerate Activities, Services, Receivers, Providers ---
    if (context) {
        try {
            var PackageManager = Java.use('android.content.pm.PackageManager');
            var pm = context.getPackageManager();
            var flags = PackageManager.GET_ACTIVITIES.value |
                        PackageManager.GET_SERVICES.value |
                        PackageManager.GET_RECEIVERS.value |
                        PackageManager.GET_PROVIDERS.value;
            var pkgInfo = pm.getPackageInfo(context.getPackageName(), flags);

            // Activities
            var activities = pkgInfo.activities.value;
            if (activities) {
                console.log('[*] ' + TAG + ': === Activities (' + activities.length + ') ===');
                for (var i = 0; i < activities.length; i++) {
                    var exported = activities[i].exported.value ? ' [EXPORTED]' : '';
                    console.log('    ' + activities[i].name.value + exported);
                }
            }

            // Services
            var services = pkgInfo.services.value;
            if (services) {
                console.log('[*] ' + TAG + ': === Services (' + services.length + ') ===');
                for (var i = 0; i < services.length; i++) {
                    var exported = services[i].exported.value ? ' [EXPORTED]' : '';
                    console.log('    ' + services[i].name.value + exported);
                }
            }

            // Receivers
            var receivers = pkgInfo.receivers.value;
            if (receivers) {
                console.log('[*] ' + TAG + ': === Broadcast Receivers (' + receivers.length + ') ===');
                for (var i = 0; i < receivers.length; i++) {
                    var exported = receivers[i].exported.value ? ' [EXPORTED]' : '';
                    console.log('    ' + receivers[i].name.value + exported);
                }
            }

            // Content Providers
            var providers = pkgInfo.providers.value;
            if (providers) {
                console.log('[*] ' + TAG + ': === Content Providers (' + providers.length + ') ===');
                for (var i = 0; i < providers.length; i++) {
                    var exported = providers[i].exported.value ? ' [EXPORTED]' : '';
                    var authority = providers[i].authority.value || 'unknown';
                    console.log('    ' + providers[i].name.value + ' (authority: ' + authority + ')' + exported);
                }
            }
        } catch (e) {
            console.log('[-] ' + TAG + ': Component enumeration failed: ' + e);
        }
    }

    // --- 4. Loaded classes matching common patterns ---
    console.log('[*] ' + TAG + ': === Loaded Classes (interesting patterns) ===');

    var patterns = [
        { name: 'Activities', regex: /Activity$/ },
        { name: 'Services', regex: /Service$/ },
        { name: 'Receivers', regex: /Receiver$/ },
        { name: 'Providers', regex: /Provider$/ },
        { name: 'WebView', regex: /WebView/ },
        { name: 'Crypto', regex: /Cipher|Crypto|Encrypt|Decrypt|AES|RSA|DES/ },
        { name: 'Network', regex: /Http|Socket|Volley|Retrofit|OkHttp/ },
        { name: 'Database', regex: /SQLite|Database|Realm|Room/ },
    ];

    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            // Only log classes from the app package (skip android.*, java.*, etc.)
            if (context) {
                var packageName = context.getPackageName();
                if (className.indexOf(packageName.split('.').slice(0, 2).join('.')) === 0) {
                    for (var p = 0; p < patterns.length; p++) {
                        if (patterns[p].regex.test(className)) {
                            console.log('    [' + patterns[p].name + '] ' + className);
                            break;
                        }
                    }
                }
            }
        },
        onComplete: function () {
            console.log('[*] ' + TAG + ': Class enumeration complete');
        },
    });

    // --- 5. Native libraries ---
    console.log('[*] ' + TAG + ': === Loaded Native Libraries ===');
    Process.enumerateModules({
        onMatch: function (module) {
            // Filter to app-specific native libs
            if (module.path.indexOf('/data/') !== -1) {
                console.log('    ' + module.name + ' (' + module.path + ') base=' + module.base + ' size=' + module.size);
            }
        },
        onComplete: function () {
            console.log('[*] ' + TAG + ': Native library enumeration complete');
        },
    });

    console.log('[+] ' + TAG + ': App reconnaissance complete');
});
""",
    },
]
