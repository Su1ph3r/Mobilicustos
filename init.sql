-- Mobilicustos Database Schema
-- Mobile Security Penetration Testing Platform

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Mobile Applications
CREATE TABLE mobile_apps (
    app_id VARCHAR(256) PRIMARY KEY,
    package_name VARCHAR(512) NOT NULL,
    app_name VARCHAR(512),
    version_name VARCHAR(64),
    version_code INTEGER,
    platform VARCHAR(16) NOT NULL CHECK (platform IN ('android', 'ios')),

    -- File Info
    file_path VARCHAR(1024),
    file_hash_sha256 VARCHAR(64),
    file_size_bytes BIGINT,

    -- Framework Detection
    framework VARCHAR(64), -- native, flutter, react_native, xamarin, maui, cordova, unity
    framework_version VARCHAR(64),
    framework_details JSONB DEFAULT '{}',

    -- Signing Info
    signing_info JSONB DEFAULT '{}',
    -- Android: signing scheme, certificate info
    -- iOS: provisioning profile, entitlements

    -- Extracted Metadata
    min_sdk_version INTEGER,  -- Android
    target_sdk_version INTEGER,  -- Android
    min_ios_version VARCHAR(16),  -- iOS

    -- Analysis State
    status VARCHAR(32) DEFAULT 'pending' CHECK (status IN ('pending', 'analyzing', 'completed', 'failed')),
    upload_date TIMESTAMP DEFAULT NOW(),
    last_analyzed TIMESTAMP,

    -- Additional Metadata
    app_metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_mobile_apps_platform ON mobile_apps(platform);
CREATE INDEX idx_mobile_apps_framework ON mobile_apps(framework);
CREATE INDEX idx_mobile_apps_package ON mobile_apps(package_name);
CREATE INDEX idx_mobile_apps_status ON mobile_apps(status);

-- Scans
CREATE TABLE scans (
    scan_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,

    -- Scan Configuration
    scan_type VARCHAR(32) NOT NULL CHECK (scan_type IN ('static', 'dynamic', 'full')),
    analyzers_enabled JSONB DEFAULT '[]',  -- List of analyzer names

    -- Status
    status VARCHAR(32) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    current_analyzer VARCHAR(128),

    -- Results Summary
    findings_count JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}',

    -- Timing
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),

    -- Error Tracking
    error_message TEXT,
    analyzer_errors JSONB DEFAULT '[]'
);

CREATE INDEX idx_scans_app_id ON scans(app_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);

-- Findings (Critical - Rich Content)
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    finding_id VARCHAR(256) UNIQUE NOT NULL,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,

    -- Source
    tool VARCHAR(64) NOT NULL,
    platform VARCHAR(16) CHECK (platform IN ('android', 'ios', 'cross-platform')),

    -- Classification
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status VARCHAR(32) DEFAULT 'open' CHECK (status IN ('open', 'confirmed', 'false_positive', 'accepted_risk', 'remediated', 'new', 'in_progress', 'fixed', 'verified', 'closed', 'ignored', 'wont_fix')),
    category VARCHAR(128),

    -- Core Content (MUST be high quality)
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    impact TEXT NOT NULL,
    remediation TEXT NOT NULL,

    -- Location
    resource_type VARCHAR(128),
    file_path VARCHAR(1024),
    line_number INTEGER,
    code_snippet TEXT,

    -- PoC Evidence (CRITICAL)
    poc_evidence TEXT,
    poc_verification TEXT,
    poc_commands JSONB DEFAULT '[]',
    poc_frida_script TEXT,
    poc_screenshot_path TEXT,

    -- Remediation Details
    remediation_commands JSONB DEFAULT '[]',
    remediation_code JSONB DEFAULT '{}',
    remediation_resources JSONB DEFAULT '[]',

    -- Risk Scoring
    risk_score DECIMAL(4,2),
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(128),
    cwe_id VARCHAR(32),
    cwe_name VARCHAR(256),

    -- OWASP Mapping
    owasp_masvs_category VARCHAR(64),
    owasp_masvs_control VARCHAR(64),
    owasp_mastg_test VARCHAR(128),

    -- Deduplication
    canonical_id VARCHAR(256),
    tool_sources JSONB DEFAULT '[]',

    -- Timestamps
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_app_id ON findings(app_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_tool ON findings(tool);
CREATE INDEX idx_findings_category ON findings(category);
CREATE INDEX idx_findings_owasp ON findings(owasp_masvs_category);
CREATE INDEX idx_findings_cwe ON findings(cwe_id);
CREATE INDEX idx_findings_title_trgm ON findings USING gin(title gin_trgm_ops);

-- Additional indexes for performance (D2, D4, D10)
CREATE INDEX idx_findings_file_path ON findings(file_path);
CREATE INDEX idx_findings_canonical_id ON findings(canonical_id);
CREATE INDEX idx_findings_finding_id ON findings(finding_id);

-- Composite indexes for common queries
CREATE INDEX idx_findings_app_status ON findings(app_id, status);
CREATE INDEX idx_findings_scan_severity ON findings(scan_id, severity);
CREATE INDEX idx_findings_created_at ON findings(created_at DESC);

-- Attack Paths (Neo4j sync reference)
CREATE TABLE attack_paths (
    path_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Path Definition
    path_name VARCHAR(256) NOT NULL,
    path_description TEXT,
    attack_vector TEXT,

    -- Chain of findings
    finding_chain JSONB NOT NULL,  -- Ordered list of finding_ids

    -- Risk Assessment
    combined_risk_score DECIMAL(4,2),
    exploitability VARCHAR(16) CHECK (exploitability IN ('trivial', 'easy', 'moderate', 'difficult', 'theoretical')),

    -- Neo4j Reference
    neo4j_path_id VARCHAR(256),

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_attack_paths_app_id ON attack_paths(app_id);

-- ============================================================================
-- MOBILE-SPECIFIC TABLES
-- ============================================================================

-- ML Models (Extracted from apps)
CREATE TABLE ml_models (
    model_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Model Info
    model_name VARCHAR(256),
    model_format VARCHAR(32) NOT NULL CHECK (model_format IN ('tflite', 'coreml', 'onnx', 'pytorch', 'other')),
    file_path VARCHAR(1024) NOT NULL,
    file_size_bytes BIGINT,
    file_hash VARCHAR(64),

    -- Analysis Results
    input_tensors JSONB DEFAULT '[]',
    output_tensors JSONB DEFAULT '[]',
    operations JSONB DEFAULT '[]',
    labels JSONB DEFAULT '[]',

    -- Security Analysis
    vulnerabilities JSONB DEFAULT '[]',
    adversarial_risk VARCHAR(16),
    model_stealing_risk VARCHAR(16),

    -- Metadata
    extracted_at TIMESTAMP DEFAULT NOW(),
    analysis_status VARCHAR(32) DEFAULT 'pending'
);

CREATE INDEX idx_ml_models_app_id ON ml_models(app_id);
CREATE INDEX idx_ml_models_format ON ml_models(model_format);

-- Secrets (Detected credentials)
CREATE TABLE secrets (
    secret_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id VARCHAR(256) REFERENCES findings(finding_id) ON DELETE SET NULL,

    -- Secret Info
    secret_type VARCHAR(64) NOT NULL,  -- api_key, token, password, certificate, etc.
    provider VARCHAR(128),  -- aws, google, firebase, stripe, etc.

    -- Location
    file_path VARCHAR(1024),
    line_number INTEGER,
    context TEXT,  -- Surrounding code/text

    -- Secret Value (encrypted or redacted)
    secret_value_redacted VARCHAR(256),  -- Partially masked
    secret_hash VARCHAR(64),  -- For dedup

    -- Validation
    is_valid BOOLEAN,  -- If we could verify it works
    validation_error TEXT,
    last_validated TIMESTAMP,

    -- Risk
    exposure_risk VARCHAR(16) CHECK (exposure_risk IN ('critical', 'high', 'medium', 'low')),

    detected_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_secrets_app_id ON secrets(app_id);
CREATE INDEX idx_secrets_type ON secrets(secret_type);
CREATE INDEX idx_secrets_provider ON secrets(provider);
CREATE INDEX idx_secrets_hash ON secrets(secret_hash);

-- Devices (Physical/Emulator/Corellium)
CREATE TABLE devices (
    device_id VARCHAR(128) PRIMARY KEY,
    device_type VARCHAR(32) NOT NULL CHECK (device_type IN ('physical', 'emulator', 'corellium')),
    platform VARCHAR(16) NOT NULL CHECK (platform IN ('android', 'ios')),

    -- Device Info
    device_name VARCHAR(256),
    model VARCHAR(128),
    os_version VARCHAR(32),

    -- Connection
    connection_type VARCHAR(32),  -- adb, usb, wifi, corellium_api
    connection_string VARCHAR(512),  -- IP:port, serial, etc.

    -- Corellium Specific
    corellium_instance_id VARCHAR(128),
    corellium_project_id VARCHAR(128),

    -- Status
    status VARCHAR(32) DEFAULT 'disconnected' CHECK (status IN ('connected', 'disconnected', 'busy', 'error')),
    last_seen TIMESTAMP,

    -- Capabilities
    is_rooted BOOLEAN DEFAULT FALSE,
    is_jailbroken BOOLEAN DEFAULT FALSE,
    frida_server_version VARCHAR(32),
    frida_server_status VARCHAR(32),

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_devices_platform ON devices(platform);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_type ON devices(device_type);

-- Frida Scripts
CREATE TABLE frida_scripts (
    script_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Script Info
    script_name VARCHAR(256) NOT NULL,
    category VARCHAR(64) NOT NULL,  -- bypass, monitor, exploit, utility
    subcategory VARCHAR(64),  -- ssl_pinning, root_detection, anti_frida, etc.

    -- Content
    script_content TEXT NOT NULL,
    description TEXT,

    -- Compatibility
    platforms JSONB DEFAULT '["android", "ios"]',
    min_frida_version VARCHAR(32),

    -- Targeting
    target_frameworks JSONB DEFAULT '[]',  -- flutter, react_native, etc.
    target_libraries JSONB DEFAULT '[]',  -- OkHttp, Alamofire, etc.

    -- Metadata
    author VARCHAR(128),
    source_url VARCHAR(512),
    is_builtin BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_frida_scripts_category ON frida_scripts(category);
CREATE INDEX idx_frida_scripts_subcategory ON frida_scripts(subcategory);

-- Bypass Results (Anti-detection tracking)
CREATE TABLE bypass_results (
    result_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,

    -- Detection Info
    detection_type VARCHAR(64) NOT NULL,  -- frida, root, jailbreak, emulator, debugger, ssl_pinning
    detection_method VARCHAR(128),  -- file_check, port_scan, memory_scan, etc.
    detection_library VARCHAR(128),  -- Which lib implements detection

    -- Detection Details
    detection_signature TEXT,
    detection_location VARCHAR(512),  -- File/class where detection occurs

    -- Bypass Info
    bypass_script_id UUID REFERENCES frida_scripts(script_id) ON DELETE SET NULL,
    bypass_status VARCHAR(32) CHECK (bypass_status IN ('not_attempted', 'success', 'partial', 'failed')),
    bypass_notes TEXT,

    -- Evidence
    poc_evidence TEXT,
    screenshot_path TEXT,

    attempted_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_bypass_results_app_id ON bypass_results(app_id);
CREATE INDEX idx_bypass_results_detection_type ON bypass_results(detection_type);
CREATE INDEX idx_bypass_results_status ON bypass_results(bypass_status);

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Findings summary by app
CREATE VIEW v_app_findings_summary AS
SELECT
    a.app_id,
    a.package_name,
    a.app_name,
    a.platform,
    a.framework,
    COUNT(f.id) as total_findings,
    COUNT(CASE WHEN f.severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN f.severity = 'high' THEN 1 END) as high_count,
    COUNT(CASE WHEN f.severity = 'medium' THEN 1 END) as medium_count,
    COUNT(CASE WHEN f.severity = 'low' THEN 1 END) as low_count,
    COUNT(CASE WHEN f.severity = 'info' THEN 1 END) as info_count,
    MAX(f.created_at) as last_finding_date
FROM mobile_apps a
LEFT JOIN findings f ON a.app_id = f.app_id AND f.status = 'open'
GROUP BY a.app_id, a.package_name, a.app_name, a.platform, a.framework;

-- MASVS compliance summary
CREATE VIEW v_masvs_compliance AS
SELECT
    a.app_id,
    a.package_name,
    f.owasp_masvs_category,
    COUNT(CASE WHEN f.status = 'open' THEN 1 END) as open_findings,
    COUNT(CASE WHEN f.status = 'remediated' THEN 1 END) as remediated_findings,
    COUNT(CASE WHEN f.severity IN ('critical', 'high') THEN 1 END) as high_severity_count
FROM mobile_apps a
LEFT JOIN findings f ON a.app_id = f.app_id
WHERE f.owasp_masvs_category IS NOT NULL
GROUP BY a.app_id, a.package_name, f.owasp_masvs_category;

-- Recent scans
CREATE VIEW v_recent_scans AS
SELECT
    s.scan_id,
    s.app_id,
    a.package_name,
    a.app_name,
    a.platform,
    s.scan_type,
    s.status,
    s.progress,
    s.findings_count,
    s.started_at,
    s.completed_at,
    s.created_at
FROM scans s
JOIN mobile_apps a ON s.app_id = a.app_id
ORDER BY s.created_at DESC;

-- ============================================================================
-- SEED DATA: Built-in Frida Scripts
-- ============================================================================

INSERT INTO frida_scripts (script_name, category, subcategory, script_content, description, platforms, is_builtin) VALUES

-- SSL Pinning Bypass (Universal)
('Universal SSL Pinning Bypass', 'bypass', 'ssl_pinning',
'// Universal SSL Pinning Bypass
// Supports: OkHttp, TrustManager, NSURLSession, Alamofire

Java.perform(function() {
    // Android: OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use(''okhttp3.CertificatePinner'');
        CertificatePinner.check.overload(''java.lang.String'', ''java.util.List'').implementation = function(hostname, peerCertificates) {
            console.log(''[+] OkHttp CertificatePinner.check() bypassed for: '' + hostname);
            return;
        };
    } catch(e) {}

    // Android: TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use(''com.android.org.conscrypt.TrustManagerImpl'');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, authType, session, params) {
            console.log(''[+] TrustManagerImpl.verifyChain() bypassed'');
            return untrustedChain;
        };
    } catch(e) {}
});

// iOS: NSURLSession
if (ObjC.available) {
    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        Interceptor.attach(NSURLSessionConfiguration[''- setHTTPAdditionalHeaders:''].implementation, {
            onEnter: function(args) {
                console.log(''[+] NSURLSessionConfiguration intercepted'');
            }
        });
    } catch(e) {}
}',
'Bypasses SSL certificate pinning in OkHttp, TrustManager (Android), and NSURLSession (iOS)',
'["android", "ios"]', TRUE),

-- Root Detection Bypass
('Root Detection Bypass', 'bypass', 'root_detection',
'// Root Detection Bypass for Android

Java.perform(function() {
    // RootBeer bypass
    try {
        var RootBeer = Java.use(''com.scottyab.rootbeer.RootBeer'');
        RootBeer.isRooted.implementation = function() {
            console.log(''[+] RootBeer.isRooted() bypassed'');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            return false;
        };
    } catch(e) {}

    // File.exists() for su binary
    var File = Java.use(''java.io.File'');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf(''su'') !== -1 || path.indexOf(''Superuser'') !== -1 ||
            path.indexOf(''magisk'') !== -1 || path.indexOf(''busybox'') !== -1) {
            console.log(''[+] File.exists() bypassed for: '' + path);
            return false;
        }
        return this.exists.call(this);
    };
});',
'Bypasses common root detection methods including RootBeer, file checks, and command execution',
'["android"]', TRUE),

-- Anti-Frida Bypass
('Anti-Frida Bypass', 'bypass', 'anti_frida',
'// Anti-Frida Detection Bypass

Java.perform(function() {
    // Hide frida-server port (27042)
    var Socket = Java.use(''java.net.Socket'');
    Socket.$init.overload(''java.lang.String'', ''int'').implementation = function(host, port) {
        if (port === 27042 || port === 27043) {
            console.log(''[+] Blocking connection to Frida port: '' + port);
            throw new Error(''Connection refused'');
        }
        return this.$init(host, port);
    };

    // Hide /data/local/tmp/frida-server
    var File = Java.use(''java.io.File'');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf(''frida'') !== -1 || path.indexOf(''linjector'') !== -1) {
            console.log(''[+] Hiding Frida file: '' + path);
            return false;
        }
        return this.exists.call(this);
    };

    // Hide frida thread names
    var Thread = Java.use(''java.lang.Thread'');
    Thread.getName.implementation = function() {
        var name = this.getName.call(this);
        if (name.indexOf(''frida'') !== -1 || name.indexOf(''gum-js'') !== -1) {
            return ''main'';
        }
        return name;
    };
});

// Native anti-debugging bypass
Interceptor.attach(Module.findExportByName(null, ''ptrace''), {
    onEnter: function(args) {
        console.log(''[+] ptrace() called, blocking anti-debug'');
        args[0] = ptr(0);
    }
});',
'Bypasses Frida detection methods including port scanning, file checks, and thread enumeration',
'["android"]', TRUE),

-- Jailbreak Detection Bypass (iOS)
('Jailbreak Detection Bypass', 'bypass', 'jailbreak_detection',
'// Jailbreak Detection Bypass for iOS

if (ObjC.available) {
    // Common jailbreak file paths
    var jbPaths = [
        ''/Applications/Cydia.app'',
        ''/Library/MobileSubstrate/MobileSubstrate.dylib'',
        ''/bin/bash'',
        ''/usr/sbin/sshd'',
        ''/etc/apt'',
        ''/private/var/lib/apt/'',
        ''/private/var/lib/cydia'',
        ''/private/var/stash''
    ];

    // Hook NSFileManager fileExistsAtPath:
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager[''- fileExistsAtPath:''].implementation, {
        onEnter: function(args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            for (var i = 0; i < jbPaths.length; i++) {
                if (this.path.indexOf(jbPaths[i]) !== -1) {
                    console.log(''[+] Hiding jailbreak file: '' + this.path);
                    retval.replace(0);
                    return;
                }
            }
        }
    });

    // Hook canOpenURL for Cydia
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication[''- canOpenURL:''].implementation, {
        onEnter: function(args) {
            this.url = ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (this.url.indexOf(''cydia'') !== -1) {
                console.log(''[+] Blocking canOpenURL for Cydia'');
                retval.replace(0);
            }
        }
    });

    // Hook fork() - jailbreak detection via fork
    Interceptor.attach(Module.findExportByName(null, ''fork''), {
        onLeave: function(retval) {
            console.log(''[+] fork() called, returning -1'');
            retval.replace(-1);
        }
    });
}',
'Bypasses iOS jailbreak detection including file checks, URL schemes, and fork detection',
'["ios"]', TRUE),

-- Method Tracer
('Method Tracer', 'monitor', 'tracing',
'// Universal Method Tracer
// Usage: trace(''com.example.ClassName'', ''methodName'')

function trace(className, methodName) {
    Java.perform(function() {
        var clazz = Java.use(className);
        var methods = clazz[methodName].overloads;

        methods.forEach(function(method) {
            method.implementation = function() {
                console.log(''\\n[TRACE] '' + className + ''.'' + methodName);
                console.log(''[ARGS] '' + JSON.stringify(arguments));

                var result = method.apply(this, arguments);
                console.log(''[RETURN] '' + result);
                return result;
            };
        });
    });
}

function traceClass(className) {
    Java.perform(function() {
        var clazz = Java.use(className);
        var methods = clazz.class.getDeclaredMethods();

        methods.forEach(function(method) {
            var methodName = method.getName();
            trace(className, methodName);
        });
    });
}',
'Traces method calls with arguments and return values for debugging and analysis',
'["android"]', TRUE),

-- Crypto Monitor
('Crypto Monitor', 'monitor', 'crypto',
'// Cryptographic Operations Monitor

Java.perform(function() {
    // AES Cipher
    var Cipher = Java.use(''javax.crypto.Cipher'');

    Cipher.getInstance.overload(''java.lang.String'').implementation = function(transformation) {
        console.log(''\\n[CRYPTO] Cipher.getInstance: '' + transformation);
        return this.getInstance(transformation);
    };

    Cipher.init.overload(''int'', ''java.security.Key'').implementation = function(mode, key) {
        var modeStr = mode === 1 ? ''ENCRYPT'' : ''DECRYPT'';
        console.log(''[CRYPTO] Cipher.init mode='' + modeStr);
        console.log(''[CRYPTO] Key algorithm: '' + key.getAlgorithm());
        console.log(''[CRYPTO] Key bytes: '' + bytesToHex(key.getEncoded()));
        return this.init(mode, key);
    };

    Cipher.doFinal.overload(''[B'').implementation = function(input) {
        console.log(''[CRYPTO] Cipher.doFinal input: '' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log(''[CRYPTO] Cipher.doFinal output: '' + bytesToHex(result));
        return result;
    };

    // Helper function
    function bytesToHex(bytes) {
        var hex = '''';
        for (var i = 0; i < bytes.length; i++) {
            hex += (''0'' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }
});',
'Monitors cryptographic operations including AES encryption with key and data logging',
'["android"]', TRUE),

-- Emulator Detection Bypass
('Emulator Detection Bypass', 'bypass', 'emulator_detection',
'// Emulator Detection Bypass for Android
// Spoofs device properties to hide emulator indicators

Java.perform(function() {
    // Spoof Build properties
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
    Build.MODEL.value = "Pixel 2";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.PRODUCT.value = "walleye";
    Build.DEVICE.value = "walleye";
    Build.HARDWARE.value = "walleye";
    Build.BOARD.value = "walleye";
    Build.HOST.value = "wphr1.hot.corp.google.com";
    Build.SERIAL.value = "FA6AA0301234";

    // Spoof Telephony info
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.overload().implementation = function() {
            console.log("[+] getDeviceId() - returning spoofed IMEI");
            return "352099001761481";
        };
        TelephonyManager.getSimSerialNumber.implementation = function() {
            console.log("[+] getSimSerialNumber() - returning spoofed value");
            return "89014103211118510720";
        };
        TelephonyManager.getSubscriberId.implementation = function() {
            console.log("[+] getSubscriberId() - returning spoofed IMSI");
            return "310260000000000";
        };
        TelephonyManager.getNetworkOperatorName.implementation = function() {
            return "T-Mobile";
        };
    } catch(e) {}

    // Hide qemu/emulator files
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var emuIndicators = [
            "qemu_pipe", "goldfish", "qemu", "genymotion",
            "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace", "/system/bin/qemu-props", "init.goldfish.rc"
        ];
        for (var i = 0; i < emuIndicators.length; i++) {
            if (path.indexOf(emuIndicators[i]) !== -1) {
                console.log("[+] Hiding emulator file: " + path);
                return false;
            }
        }
        return this.exists.call(this);
    };

    // Spoof system properties
    var SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload("java.lang.String").implementation = function(key) {
        var emuProps = ["ro.hardware", "ro.product.model", "ro.kernel.qemu", "ro.hardware.audio.primary"];
        if (emuProps.indexOf(key) !== -1) {
            console.log("[+] Spoofing system property: " + key);
            if (key === "ro.kernel.qemu") return "0";
            if (key === "ro.hardware") return "walleye";
        }
        return this.get(key);
    };
});',
'Bypasses emulator detection by spoofing Build properties, Telephony info, and hiding emulator files',
'["android"]', TRUE),

-- Debugger Detection Bypass
('Debugger Detection Bypass', 'bypass', 'debugger_detection',
'// Debugger Detection Bypass
// Bypasses ptrace, isDebuggerConnected, and TracerPid checks

Java.perform(function() {
    // Bypass Debug.isDebuggerConnected()
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[+] Debug.isDebuggerConnected() bypassed");
        return false;
    };
    Debug.waitingForDebugger.implementation = function() {
        console.log("[+] Debug.waitingForDebugger() bypassed");
        return false;
    };

    // Bypass ApplicationInfo.FLAG_DEBUGGABLE check
    var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    ApplicationInfo.flags.value = 0;
});

// Native anti-debugging bypass
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        var request = args[0].toInt32();
        if (request === 0) { // PTRACE_TRACEME
            console.log("[+] ptrace(PTRACE_TRACEME) blocked");
            args[0] = ptr(-1); // Invalid request
        }
    },
    onLeave: function(retval) {
        retval.replace(0);
    }
});

// Hook fopen to hide TracerPid
Interceptor.attach(Module.findExportByName(null, "fopen"), {
    onEnter: function(args) {
        this.path = args[0].readCString();
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("/proc/") !== -1 && this.path.indexOf("/status") !== -1) {
            console.log("[+] Intercepted read of: " + this.path);
            // TracerPid will be read from this file
        }
    }
});

// Hook strstr for TracerPid string check
Interceptor.attach(Module.findExportByName(null, "strstr"), {
    onEnter: function(args) {
        this.needle = args[1].readCString();
    },
    onLeave: function(retval) {
        if (this.needle && this.needle === "TracerPid") {
            console.log("[+] TracerPid check bypassed");
            retval.replace(ptr(0));
        }
    }
});',
'Bypasses debugger detection including ptrace, isDebuggerConnected, and /proc/self/status TracerPid checks',
'["android"]', TRUE),

-- Biometric Bypass (Android)
('Biometric Bypass (Android)', 'bypass', 'biometric',
'// Biometric Authentication Bypass for Android
// Bypasses fingerprint and BiometricPrompt authentication

Java.perform(function() {
    // Bypass BiometricPrompt (Android 9+)
    try {
        var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
        var CryptoObject = Java.use("android.hardware.biometrics.BiometricPrompt$CryptoObject");
        var AuthenticationResult = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationResult");

        BiometricPrompt.authenticate.overload(
            "android.os.CancellationSignal",
            "java.util.concurrent.Executor",
            "android.hardware.biometrics.BiometricPrompt$AuthenticationCallback"
        ).implementation = function(cancel, executor, callback) {
            console.log("[+] BiometricPrompt.authenticate() intercepted");

            // Create fake successful result
            var result = AuthenticationResult.$new.call(AuthenticationResult, null);

            // Call success callback
            callback.onAuthenticationSucceeded(result);
            console.log("[+] Biometric authentication bypassed!");
        };
    } catch(e) {
        console.log("[-] BiometricPrompt not available: " + e);
    }

    // Bypass FingerprintManager (legacy)
    try {
        var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
        var FPAuthResult = Java.use("android.hardware.fingerprint.FingerprintManager$AuthenticationResult");

        FingerprintManager.authenticate.implementation = function(crypto, cancel, flags, callback, handler) {
            console.log("[+] FingerprintManager.authenticate() intercepted");

            // Create fake result and call success
            var result = FPAuthResult.$new.call(FPAuthResult, crypto, null, 0);
            callback.onAuthenticationSucceeded(result);
            console.log("[+] Fingerprint authentication bypassed!");
        };
    } catch(e) {
        console.log("[-] FingerprintManager not available: " + e);
    }

    // Bypass Keyguard (screen lock)
    try {
        var KeyguardManager = Java.use("android.app.KeyguardManager");
        KeyguardManager.isKeyguardSecure.implementation = function() {
            console.log("[+] isKeyguardSecure() bypassed");
            return true;
        };
        KeyguardManager.isDeviceSecure.implementation = function() {
            console.log("[+] isDeviceSecure() bypassed");
            return true;
        };
    } catch(e) {}
});',
'Bypasses Android biometric authentication including BiometricPrompt and FingerprintManager',
'["android"]', TRUE),

-- Biometric Bypass (iOS)
('Biometric Bypass (iOS)', 'bypass', 'biometric',
'// Biometric Authentication Bypass for iOS
// Bypasses Touch ID and Face ID authentication

if (ObjC.available) {
    // Bypass LAContext evaluatePolicy
    var LAContext = ObjC.classes.LAContext;

    Interceptor.attach(LAContext["- evaluatePolicy:localizedReason:reply:"].implementation, {
        onEnter: function(args) {
            console.log("[+] LAContext evaluatePolicy intercepted");

            // Get the reply block
            var reply = new ObjC.Block(args[4]);

            // Store original implementation
            this.originalReply = reply;

            // Create success block
            var successBlock = new ObjC.Block({
                retType: "void",
                argTypes: ["bool", "object"],
                implementation: function(success, error) {
                    console.log("[+] Calling success callback");
                    // Always return success
                    reply.implementation(true, null);
                }
            });

            // Replace the reply block
            args[4] = successBlock;
        },
        onLeave: function(retval) {
            console.log("[+] Biometric authentication bypassed!");
        }
    });

    // Alternative: Bypass canEvaluatePolicy to claim biometrics are available
    Interceptor.attach(LAContext["- canEvaluatePolicy:error:"].implementation, {
        onEnter: function(args) {
            // Clear any error
            if (args[3] !== null) {
                ObjC.Object(args[3]).setValue_(null);
            }
        },
        onLeave: function(retval) {
            // Return YES (biometrics available)
            retval.replace(ptr(1));
        }
    });

    // Bypass biometry type check
    try {
        Interceptor.attach(LAContext["- biometryType"].implementation, {
            onLeave: function(retval) {
                // Return LABiometryTypeFaceID (2) or LABiometryTypeTouchID (1)
                console.log("[+] biometryType spoofed to Face ID");
                retval.replace(ptr(2));
            }
        });
    } catch(e) {}

    console.log("[*] iOS Biometric bypass loaded");
}',
'Bypasses iOS biometric authentication including Touch ID and Face ID via LAContext',
'["ios"]', TRUE),

-- SSL Pinning Bypass (Advanced)
('SSL Pinning Bypass (Advanced)', 'bypass', 'ssl_pinning',
'// Advanced SSL Pinning Bypass
// Covers more libraries and edge cases

Java.perform(function() {
    console.log("[*] Loading Advanced SSL Pinning Bypass");

    // 1. OkHttp3 CertificatePinner (multiple methods)
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");

        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3 CertificatePinner.check(String, List) bypassed for: " + hostname);
            return;
        };

        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(hostname, certs) {
            console.log("[+] OkHttp3 CertificatePinner.check(String, Certificate[]) bypassed for: " + hostname);
            return;
        };
    } catch(e) {}

    // 2. TrustManagerImpl (Android)
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, authType, session, params) {
            console.log("[+] TrustManagerImpl.verifyChain() bypassed");
            return untrustedChain;
        };
    } catch(e) {}

    // 3. Retrofit/OkHttp Builder
    try {
        var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
        OkHttpClientBuilder.certificatePinner.implementation = function(pinner) {
            console.log("[+] OkHttpClient.Builder.certificatePinner() bypassed");
            return this;
        };
    } catch(e) {}

    // 4. Trustkit (Android)
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.TrustKit");
        TrustKit.getInstance.implementation = function() {
            console.log("[+] TrustKit bypassed");
            return null;
        };
    } catch(e) {}

    // 5. Appcelerator Titanium
    try {
        var PinningTrustManager = Java.use("appcelerator.https.PinningTrustManager");
        PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log("[+] Appcelerator PinningTrustManager bypassed");
            return;
        };
    } catch(e) {}

    // 6. PhoneGap/Cordova sslCertificateChecker
    try {
        var SSLCertificateChecker = Java.use("nl.xservices.plugins.SSLCertificateChecker");
        SSLCertificateChecker.execute.implementation = function(action, args, callbackContext) {
            console.log("[+] Cordova SSLCertificateChecker bypassed");
            callbackContext.success("CONNECTION_SECURE");
            return true;
        };
    } catch(e) {}

    // 7. Network Security Config (API 24+)
    try {
        var NetworkSecurityTrustManager = Java.use("android.security.net.config.NetworkSecurityTrustManager");
        NetworkSecurityTrustManager.checkPins.implementation = function(chain) {
            console.log("[+] NetworkSecurityTrustManager.checkPins() bypassed");
            return;
        };
    } catch(e) {}

    console.log("[*] Advanced SSL Pinning Bypass loaded");
});

// iOS SSL Pinning
if (ObjC.available) {
    // AFNetworking
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            Interceptor.attach(AFSecurityPolicy["- setSSLPinningMode:"].implementation, {
                onEnter: function(args) {
                    console.log("[+] AFSecurityPolicy setSSLPinningMode set to None");
                    args[2] = ptr(0); // AFSSLPinningModeNone
                }
            });
            Interceptor.attach(AFSecurityPolicy["- setAllowInvalidCertificates:"].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(1); // YES
                }
            });
        }
    } catch(e) {}

    // Alamofire (Swift)
    try {
        var Alamofire = ObjC.classes.ServerTrustPolicy;
        if (Alamofire) {
            console.log("[+] Alamofire detected - use SSL Kill Switch 2");
        }
    } catch(e) {}
}',
'Advanced SSL pinning bypass covering OkHttp, TrustKit, Cordova, AFNetworking, and Network Security Config',
'["android", "ios"]', TRUE);

-- ============================================================================
-- NEW FEATURE TABLES
-- ============================================================================

-- Teams and Workspaces
CREATE TABLE teams (
    team_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_name VARCHAR(256) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE team_members (
    member_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(team_id) ON DELETE CASCADE,
    user_id VARCHAR(256) NOT NULL,
    user_email VARCHAR(512),
    role VARCHAR(32) NOT NULL CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    joined_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_team_members_team ON team_members(team_id);
CREATE INDEX idx_team_members_user ON team_members(user_id);

CREATE TABLE workspaces (
    workspace_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(team_id) ON DELETE CASCADE,
    workspace_name VARCHAR(256) NOT NULL,
    description TEXT,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_workspaces_team ON workspaces(team_id);

-- Audit Log
CREATE TABLE audit_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(team_id) ON DELETE SET NULL,
    user_id VARCHAR(256),
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64),
    resource_id VARCHAR(256),
    details JSONB DEFAULT '{}',
    ip_address VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_log_team ON audit_log(team_id);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);

-- Dependencies
CREATE TABLE dependencies (
    dependency_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Dependency Info
    package_manager VARCHAR(32) NOT NULL, -- gradle, cocoapods, npm, pub
    package_name VARCHAR(512) NOT NULL,
    version VARCHAR(128),
    source_file VARCHAR(1024),

    -- Vulnerability Info
    is_vulnerable BOOLEAN DEFAULT FALSE,
    vulnerabilities JSONB DEFAULT '[]',
    highest_severity VARCHAR(16),
    cve_ids JSONB DEFAULT '[]',

    -- Metadata
    license VARCHAR(128),
    latest_version VARCHAR(128),
    is_outdated BOOLEAN DEFAULT FALSE,

    detected_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_dependencies_app ON dependencies(app_id);
CREATE INDEX idx_dependencies_vulnerable ON dependencies(is_vulnerable);
CREATE INDEX idx_dependencies_package ON dependencies(package_name);

-- Privacy Trackers
CREATE TABLE privacy_trackers (
    tracker_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Tracker Info
    tracker_name VARCHAR(256) NOT NULL,
    tracker_type VARCHAR(64), -- analytics, advertising, crash_reporting, social
    vendor VARCHAR(256),

    -- Detection
    detection_method VARCHAR(64), -- class_name, package_import, network_endpoint
    evidence JSONB DEFAULT '{}',

    -- Privacy Impact
    data_collected JSONB DEFAULT '[]', -- device_id, location, contacts, etc.
    shares_data_externally BOOLEAN DEFAULT FALSE,
    gdpr_compliant BOOLEAN,
    ccpa_compliant BOOLEAN,

    detected_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_privacy_trackers_app ON privacy_trackers(app_id);
CREATE INDEX idx_privacy_trackers_type ON privacy_trackers(tracker_type);

-- API Endpoints
CREATE TABLE api_endpoints (
    endpoint_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Endpoint Info
    url VARCHAR(2048) NOT NULL,
    method VARCHAR(16), -- GET, POST, PUT, DELETE, etc.
    api_type VARCHAR(32), -- rest, graphql, grpc, websocket

    -- Location
    source_file VARCHAR(1024),
    line_number INTEGER,

    -- Analysis
    is_authenticated BOOLEAN,
    uses_https BOOLEAN,
    parameters JSONB DEFAULT '[]',
    headers JSONB DEFAULT '{}',

    -- Security Concerns
    security_issues JSONB DEFAULT '[]',

    detected_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_api_endpoints_app ON api_endpoints(app_id);
CREATE INDEX idx_api_endpoints_url ON api_endpoints(url);

-- Scheduled Scans
CREATE TABLE scheduled_scans (
    schedule_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE SET NULL,

    -- Schedule Config
    schedule_name VARCHAR(256),
    cron_expression VARCHAR(128) NOT NULL,
    scan_type VARCHAR(32) NOT NULL,
    analyzers_enabled JSONB DEFAULT '[]',

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    last_scan_id UUID,

    -- Notifications
    notify_on_completion BOOLEAN DEFAULT TRUE,
    notify_on_new_findings BOOLEAN DEFAULT TRUE,
    notification_emails JSONB DEFAULT '[]',
    slack_webhook_url VARCHAR(1024),

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_scheduled_scans_app ON scheduled_scans(app_id);
CREATE INDEX idx_scheduled_scans_enabled ON scheduled_scans(is_enabled);
CREATE INDEX idx_scheduled_scans_next_run ON scheduled_scans(next_run_at);

-- Webhooks
CREATE TABLE webhooks (
    webhook_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(team_id) ON DELETE CASCADE,

    -- Webhook Config
    webhook_name VARCHAR(256) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    secret VARCHAR(256),

    -- Events
    events JSONB DEFAULT '["scan.completed", "finding.created"]',

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    last_triggered_at TIMESTAMP,
    failure_count INTEGER DEFAULT 0,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_webhooks_team ON webhooks(team_id);

-- Issue Tracker Integrations
CREATE TABLE issue_tracker_configs (
    config_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(team_id) ON DELETE CASCADE,

    -- Provider
    provider VARCHAR(32) NOT NULL, -- jira, github, gitlab, azure_devops
    provider_url VARCHAR(1024),

    -- Auth
    auth_type VARCHAR(32), -- api_key, oauth, pat
    credentials_encrypted TEXT,

    -- Mapping
    project_key VARCHAR(128),
    issue_type VARCHAR(64),
    priority_mapping JSONB DEFAULT '{}',
    severity_mapping JSONB DEFAULT '{}',
    custom_fields JSONB DEFAULT '{}',

    -- Sync Settings
    auto_create_issues BOOLEAN DEFAULT FALSE,
    sync_status_changes BOOLEAN DEFAULT TRUE,
    sync_comments BOOLEAN DEFAULT TRUE,

    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_issue_tracker_team ON issue_tracker_configs(team_id);

-- Finding Comments (for workflow)
CREATE TABLE finding_comments (
    comment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id VARCHAR(256) REFERENCES findings(finding_id) ON DELETE CASCADE,
    user_id VARCHAR(256) NOT NULL,
    user_email VARCHAR(512),

    content TEXT NOT NULL,
    mentions JSONB DEFAULT '[]',

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_finding_comments_finding ON finding_comments(finding_id);

-- Finding Assignments
CREATE TABLE finding_assignments (
    assignment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id VARCHAR(256) REFERENCES findings(finding_id) ON DELETE CASCADE,
    assigned_to VARCHAR(256) NOT NULL,
    assigned_by VARCHAR(256),

    due_date TIMESTAMP,
    sla_breach_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_finding_assignments_finding ON finding_assignments(finding_id);
CREATE INDEX idx_finding_assignments_user ON finding_assignments(assigned_to);

-- Finding History (workflow tracking)
CREATE TABLE finding_history (
    history_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    finding_id VARCHAR(256) REFERENCES findings(finding_id) ON DELETE CASCADE,
    user_id VARCHAR(256),

    field_changed VARCHAR(64),
    old_value TEXT,
    new_value TEXT,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_finding_history_finding ON finding_history(finding_id);

-- Network Captures
CREATE TABLE network_captures (
    capture_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,

    -- Capture Info
    capture_name VARCHAR(256),
    proxy_type VARCHAR(32), -- mitmproxy, burp, charles

    -- File
    capture_file_path VARCHAR(1024),
    file_size_bytes BIGINT,

    -- Stats
    request_count INTEGER DEFAULT 0,
    unique_hosts INTEGER DEFAULT 0,
    sensitive_data_found BOOLEAN DEFAULT FALSE,

    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_network_captures_app ON network_captures(app_id);

-- Network Requests (from captures)
CREATE TABLE network_requests (
    request_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    capture_id UUID REFERENCES network_captures(capture_id) ON DELETE CASCADE,

    -- Request
    method VARCHAR(16),
    url TEXT NOT NULL,
    host VARCHAR(512),
    path VARCHAR(2048),
    request_headers JSONB DEFAULT '{}',
    request_body TEXT,

    -- Response
    status_code INTEGER,
    response_headers JSONB DEFAULT '{}',
    response_body TEXT,
    response_size INTEGER,

    -- Analysis
    uses_https BOOLEAN,
    certificate_info JSONB DEFAULT '{}',
    sensitive_data JSONB DEFAULT '[]',
    security_issues JSONB DEFAULT '[]',

    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_network_requests_capture ON network_requests(capture_id);
CREATE INDEX idx_network_requests_host ON network_requests(host);

-- Fuzzing Sessions
CREATE TABLE fuzzing_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,

    -- Fuzzing Config
    fuzzing_type VARCHAR(64) NOT NULL, -- input, intent, url_scheme, ipc
    target_component VARCHAR(512),
    seed_inputs JSONB DEFAULT '[]',
    mutation_strategy VARCHAR(64),

    -- Status
    status VARCHAR(32) DEFAULT 'pending',
    iterations_completed INTEGER DEFAULT 0,
    iterations_total INTEGER DEFAULT 0,

    -- Results
    crashes_found INTEGER DEFAULT 0,
    unique_crashes INTEGER DEFAULT 0,
    crash_logs JSONB DEFAULT '[]',

    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_fuzzing_sessions_app ON fuzzing_sessions(app_id);
CREATE INDEX idx_fuzzing_sessions_status ON fuzzing_sessions(status);

-- Screenshots
CREATE TABLE screenshots (
    screenshot_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,
    finding_id VARCHAR(256) REFERENCES findings(finding_id) ON DELETE SET NULL,

    -- File
    file_path VARCHAR(1024) NOT NULL,
    file_size_bytes INTEGER,

    -- Context
    activity_name VARCHAR(512),
    description TEXT,

    -- Analysis
    contains_sensitive_data BOOLEAN DEFAULT FALSE,
    detected_text JSONB DEFAULT '[]',
    pii_detected JSONB DEFAULT '[]',

    captured_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_screenshots_app ON screenshots(app_id);
CREATE INDEX idx_screenshots_finding ON screenshots(finding_id);

-- Runtime Events (behavior monitoring)
CREATE TABLE runtime_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,

    -- Event Info
    event_type VARCHAR(64) NOT NULL, -- file_access, network, syscall, api_call
    event_category VARCHAR(64),

    -- Details
    target VARCHAR(2048),
    action VARCHAR(64),
    parameters JSONB DEFAULT '{}',
    result TEXT,

    -- Risk Assessment
    is_suspicious BOOLEAN DEFAULT FALSE,
    risk_reason TEXT,

    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_runtime_events_app ON runtime_events(app_id);
CREATE INDEX idx_runtime_events_type ON runtime_events(event_type);
CREATE INDEX idx_runtime_events_timestamp ON runtime_events(timestamp DESC);

-- App Store Connections
CREATE TABLE app_store_connections (
    connection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(team_id) ON DELETE CASCADE,

    -- Store Info
    store_type VARCHAR(32) NOT NULL, -- google_play, app_store

    -- Auth
    credentials_encrypted TEXT,

    -- Monitoring
    monitored_apps JSONB DEFAULT '[]',
    check_interval_hours INTEGER DEFAULT 24,
    last_checked_at TIMESTAMP,

    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_app_store_connections_team ON app_store_connections(team_id);

-- Corellium Instances
CREATE TABLE corellium_instances (
    instance_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(team_id) ON DELETE SET NULL,

    -- Corellium Info
    corellium_instance_id VARCHAR(128) NOT NULL,
    corellium_project_id VARCHAR(128),

    -- Device Info
    device_name VARCHAR(256),
    platform VARCHAR(16),
    os_version VARCHAR(32),
    flavor VARCHAR(64), -- jailbroken, rooted

    -- Status
    status VARCHAR(32) DEFAULT 'creating',
    ip_address VARCHAR(64),

    -- Session
    current_app_id VARCHAR(256),

    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);

CREATE INDEX idx_corellium_instances_team ON corellium_instances(team_id);
CREATE INDEX idx_corellium_instances_status ON corellium_instances(status);

-- Scan Comparisons (Diff Reports)
CREATE TABLE scan_comparisons (
    comparison_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,

    -- Scans being compared
    base_scan_id UUID REFERENCES scans(scan_id) ON DELETE SET NULL,
    target_scan_id UUID REFERENCES scans(scan_id) ON DELETE SET NULL,

    -- Results
    new_findings_count INTEGER DEFAULT 0,
    fixed_findings_count INTEGER DEFAULT 0,
    regression_findings_count INTEGER DEFAULT 0,
    unchanged_findings_count INTEGER DEFAULT 0,

    -- Details
    new_findings JSONB DEFAULT '[]',
    fixed_findings JSONB DEFAULT '[]',
    regression_findings JSONB DEFAULT '[]',

    -- Risk Delta
    risk_score_delta DECIMAL(4,2),
    severity_delta JSONB DEFAULT '{}',

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_scan_comparisons_app ON scan_comparisons(app_id);

-- SIEM Exports
CREATE TABLE siem_exports (
    export_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(team_id) ON DELETE CASCADE,

    -- Export Config
    export_format VARCHAR(32) NOT NULL, -- splunk, elastic, stix, taxii
    destination_url VARCHAR(1024),

    -- Filter
    severity_filter JSONB DEFAULT '["critical", "high"]',
    status_filter JSONB DEFAULT '["open", "confirmed"]',

    -- Status
    last_export_at TIMESTAMP,
    findings_exported INTEGER DEFAULT 0,

    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_siem_exports_team ON siem_exports(team_id);

-- Binary Protections (analysis results)
CREATE TABLE binary_protections (
    protection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Android Protections
    is_obfuscated BOOLEAN,
    obfuscation_tool VARCHAR(64), -- proguard, r8, dexguard
    has_native_code BOOLEAN,
    native_protections JSONB DEFAULT '{}',

    -- iOS Protections
    has_pie BOOLEAN,
    has_arc BOOLEAN,
    has_stack_canaries BOOLEAN,
    has_bitcode BOOLEAN,

    -- RASP Detection
    rasp_detected BOOLEAN DEFAULT FALSE,
    rasp_vendor VARCHAR(128),
    rasp_features JSONB DEFAULT '[]',

    -- Anti-Tampering
    has_integrity_checks BOOLEAN,
    has_debugger_detection BOOLEAN,
    has_emulator_detection BOOLEAN,
    has_root_jailbreak_detection BOOLEAN,

    analyzed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_binary_protections_app ON binary_protections(app_id);

-- Crypto Operations (audit results)
CREATE TABLE crypto_operations (
    operation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Operation Info
    operation_type VARCHAR(64), -- encryption, decryption, hashing, signing, key_generation
    algorithm VARCHAR(128),

    -- Location
    source_file VARCHAR(1024),
    line_number INTEGER,
    class_name VARCHAR(512),
    method_name VARCHAR(256),

    -- Analysis
    key_size INTEGER,
    is_weak BOOLEAN DEFAULT FALSE,
    weakness_reason TEXT,

    -- Evidence
    code_snippet TEXT,

    detected_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_crypto_operations_app ON crypto_operations(app_id);
CREATE INDEX idx_crypto_operations_weak ON crypto_operations(is_weak);

-- IPC Components (for IPC vulnerability scanner)
CREATE TABLE ipc_components (
    component_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Component Info
    component_type VARCHAR(64) NOT NULL, -- activity, service, receiver, provider, url_scheme
    component_name VARCHAR(512) NOT NULL,

    -- Export Status
    is_exported BOOLEAN DEFAULT FALSE,
    permission_required VARCHAR(256),

    -- Intent Filters (Android)
    intent_filters JSONB DEFAULT '[]',

    -- URL Schemes (iOS)
    url_schemes JSONB DEFAULT '[]',

    -- Vulnerabilities
    is_vulnerable BOOLEAN DEFAULT FALSE,
    vulnerabilities JSONB DEFAULT '[]',

    analyzed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ipc_components_app ON ipc_components(app_id);
CREATE INDEX idx_ipc_components_type ON ipc_components(component_type);
CREATE INDEX idx_ipc_components_vulnerable ON ipc_components(is_vulnerable);

-- Secure Storage Analysis
CREATE TABLE secure_storage_analysis (
    analysis_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- Storage Type
    storage_type VARCHAR(64) NOT NULL, -- keystore, keychain, shared_prefs, user_defaults, sqlite, files

    -- Location
    file_path VARCHAR(1024),

    -- Analysis
    is_encrypted BOOLEAN,
    encryption_type VARCHAR(64),
    contains_sensitive_data BOOLEAN DEFAULT FALSE,
    sensitive_data_types JSONB DEFAULT '[]',

    -- Issues
    security_issues JSONB DEFAULT '[]',

    analyzed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_secure_storage_app ON secure_storage_analysis(app_id);
CREATE INDEX idx_secure_storage_type ON secure_storage_analysis(storage_type);

-- WebView Analysis
CREATE TABLE webview_analysis (
    analysis_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(scan_id) ON DELETE CASCADE,

    -- WebView Info
    webview_class VARCHAR(256),
    source_file VARCHAR(1024),
    line_number INTEGER,

    -- Settings
    javascript_enabled BOOLEAN,
    file_access_enabled BOOLEAN,
    universal_file_access BOOLEAN,
    allow_content_access BOOLEAN,
    dom_storage_enabled BOOLEAN,

    -- JS Interface
    js_interfaces JSONB DEFAULT '[]',

    -- Security Issues
    has_mixed_content BOOLEAN,
    has_insecure_settings BOOLEAN,
    security_issues JSONB DEFAULT '[]',

    analyzed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_webview_analysis_app ON webview_analysis(app_id);

-- Burp Suite Integration
CREATE TABLE burp_connections (
    connection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID REFERENCES teams(team_id) ON DELETE CASCADE,

    -- Burp REST API
    connection_name VARCHAR(256) NOT NULL,
    api_url VARCHAR(1024) NOT NULL, -- e.g., http://localhost:1337
    api_key VARCHAR(512),

    -- Status
    is_connected BOOLEAN DEFAULT FALSE,
    last_connected_at TIMESTAMP,
    burp_version VARCHAR(64),

    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_burp_connections_team ON burp_connections(team_id);

-- Burp Scan Tasks
CREATE TABLE burp_scan_tasks (
    task_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connection_id UUID REFERENCES burp_connections(connection_id) ON DELETE CASCADE,
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE SET NULL,

    -- Burp Task Info
    burp_task_id VARCHAR(128),
    scan_type VARCHAR(32), -- active, passive, crawl

    -- Target
    target_urls JSONB DEFAULT '[]',
    scope_config JSONB DEFAULT '{}',

    -- Status
    status VARCHAR(32) DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    issues_found INTEGER DEFAULT 0,

    -- Config
    scan_config JSONB DEFAULT '{}',

    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_burp_scan_tasks_connection ON burp_scan_tasks(connection_id);
CREATE INDEX idx_burp_scan_tasks_app ON burp_scan_tasks(app_id);

-- Burp Issues (imported)
CREATE TABLE burp_issues (
    issue_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    task_id UUID REFERENCES burp_scan_tasks(task_id) ON DELETE CASCADE,
    finding_id VARCHAR(256) REFERENCES findings(finding_id) ON DELETE SET NULL,

    -- Burp Issue Info
    burp_issue_type_id INTEGER,
    issue_name VARCHAR(512),
    severity VARCHAR(16),
    confidence VARCHAR(16),

    -- Location
    url VARCHAR(2048),
    host VARCHAR(512),
    path VARCHAR(1024),

    -- Details
    issue_background TEXT,
    remediation_background TEXT,
    issue_detail TEXT,
    remediation_detail TEXT,

    -- Evidence
    request TEXT,
    response TEXT,
    evidence JSONB DEFAULT '[]',

    imported_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_burp_issues_task ON burp_issues(task_id);
CREATE INDEX idx_burp_issues_severity ON burp_issues(severity);

-- Burp Proxy History
CREATE TABLE burp_proxy_history (
    history_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connection_id UUID REFERENCES burp_connections(connection_id) ON DELETE CASCADE,
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE SET NULL,

    -- Request/Response
    method VARCHAR(16),
    url TEXT,
    host VARCHAR(512),
    request_headers JSONB DEFAULT '{}',
    request_body TEXT,
    status_code INTEGER,
    response_headers JSONB DEFAULT '{}',
    response_body TEXT,

    -- Analysis
    highlighted BOOLEAN DEFAULT FALSE,
    comment TEXT,
    color VARCHAR(32),

    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_burp_proxy_history_connection ON burp_proxy_history(connection_id);
CREATE INDEX idx_burp_proxy_history_host ON burp_proxy_history(host);

-- User Preferences (for dark mode, etc.)
CREATE TABLE user_preferences (
    preference_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(256) NOT NULL UNIQUE,

    -- Theme
    theme VARCHAR(16) DEFAULT 'system', -- light, dark, system

    -- Keyboard
    vim_mode_enabled BOOLEAN DEFAULT FALSE,
    custom_shortcuts JSONB DEFAULT '{}',

    -- Notifications
    email_notifications BOOLEAN DEFAULT TRUE,
    browser_notifications BOOLEAN DEFAULT TRUE,

    -- Display
    default_page_size INTEGER DEFAULT 20,
    default_severity_filter JSONB DEFAULT '[]',

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_user_preferences_user ON user_preferences(user_id);

-- ============================================================================
-- ADDITIONAL TABLES FOR NEW SERVICES
-- ============================================================================

-- Screen Captures (for screenshot_service.py)
CREATE TABLE screen_captures (
    capture_id VARCHAR(256) PRIMARY KEY,
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    finding_id VARCHAR(256) REFERENCES findings(finding_id) ON DELETE SET NULL,

    capture_type VARCHAR(32) DEFAULT 'screenshot' CHECK (capture_type IN ('screenshot', 'recording', 'ui_dump')),
    file_path VARCHAR(1024) NOT NULL,
    description TEXT,

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_screen_captures_device ON screen_captures(device_id);
CREATE INDEX idx_screen_captures_app ON screen_captures(app_id);
CREATE INDEX idx_screen_captures_finding ON screen_captures(finding_id);

-- Screen Recordings (for screenshot_service.py)
CREATE TABLE screen_recordings (
    recording_id VARCHAR(256) PRIMARY KEY,
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,

    file_path VARCHAR(1024) NOT NULL,
    max_duration INTEGER DEFAULT 180,
    status VARCHAR(32) DEFAULT 'pending' CHECK (status IN ('pending', 'recording', 'completed', 'failed')),

    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_screen_recordings_device ON screen_recordings(device_id);
CREATE INDEX idx_screen_recordings_status ON screen_recordings(status);

-- Corellium Connections (for corellium_service.py)
CREATE TABLE corellium_connections (
    connection_id VARCHAR(256) PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    api_url VARCHAR(1024) NOT NULL,
    api_token_encrypted TEXT NOT NULL,

    is_active BOOLEAN DEFAULT TRUE,
    last_connected_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Corellium Virtual Devices (for corellium_service.py)
CREATE TABLE corellium_virtual_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connection_id VARCHAR(256) REFERENCES corellium_connections(connection_id) ON DELETE CASCADE,
    instance_id VARCHAR(256) NOT NULL,
    project_id VARCHAR(256),

    name VARCHAR(256),
    flavor VARCHAR(64),
    os_version VARCHAR(32),
    platform VARCHAR(16) CHECK (platform IN ('android', 'ios')),

    status VARCHAR(32) DEFAULT 'creating',
    ip_address VARCHAR(64),

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_corellium_devices_connection ON corellium_virtual_devices(connection_id);
CREATE INDEX idx_corellium_devices_status ON corellium_virtual_devices(status);

-- Traffic Capture Sessions (for network_traffic_service.py)
CREATE TABLE traffic_capture_sessions (
    session_id VARCHAR(256) PRIMARY KEY,
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,

    proxy_host VARCHAR(256),
    proxy_port INTEGER,
    status VARCHAR(32) DEFAULT 'active' CHECK (status IN ('active', 'stopped', 'analyzing', 'completed')),

    request_count INTEGER DEFAULT 0,
    sensitive_data_found INTEGER DEFAULT 0,

    started_at TIMESTAMP DEFAULT NOW(),
    stopped_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_traffic_sessions_app ON traffic_capture_sessions(app_id);
CREATE INDEX idx_traffic_sessions_status ON traffic_capture_sessions(status);

-- Captured HTTP Requests (for network_traffic_service.py)
CREATE TABLE captured_requests (
    request_id VARCHAR(256) PRIMARY KEY,
    session_id VARCHAR(256) REFERENCES traffic_capture_sessions(session_id) ON DELETE CASCADE,

    method VARCHAR(16),
    url TEXT NOT NULL,
    host VARCHAR(512),
    path VARCHAR(2048),
    request_headers JSONB DEFAULT '{}',
    request_body TEXT,

    status_code INTEGER,
    response_headers JSONB DEFAULT '{}',
    response_body TEXT,
    response_time_ms INTEGER,

    uses_https BOOLEAN DEFAULT TRUE,
    sensitive_data JSONB DEFAULT '[]',
    security_issues JSONB DEFAULT '[]',

    captured_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_captured_requests_session ON captured_requests(session_id);
CREATE INDEX idx_captured_requests_host ON captured_requests(host);

-- Runtime Monitor Sessions (for runtime_monitor_service.py)
CREATE TABLE runtime_monitor_sessions (
    session_id VARCHAR(256) PRIMARY KEY,
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,

    monitor_types JSONB DEFAULT '[]', -- filesystem, network, permissions, crypto
    frida_script TEXT,

    status VARCHAR(32) DEFAULT 'active' CHECK (status IN ('active', 'stopped', 'completed')),
    event_count INTEGER DEFAULT 0,
    suspicious_count INTEGER DEFAULT 0,

    started_at TIMESTAMP DEFAULT NOW(),
    stopped_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_runtime_sessions_app ON runtime_monitor_sessions(app_id);
CREATE INDEX idx_runtime_sessions_status ON runtime_monitor_sessions(status);

-- SIEM Configurations (for siem_service.py - matches service expectations)
-- Note: This is separate from siem_exports which has different schema
CREATE TABLE siem_configs (
    config_id VARCHAR(256) PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    siem_type VARCHAR(32) NOT NULL CHECK (siem_type IN ('splunk', 'elastic', 'sentinel', 'qradar', 'sumo_logic')),
    config JSONB NOT NULL, -- Contains connection details (encrypted in production)

    is_active BOOLEAN DEFAULT TRUE,
    auto_export BOOLEAN DEFAULT FALSE,
    export_severity JSONB DEFAULT '["critical", "high"]',

    last_export_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_siem_configs_type ON siem_configs(siem_type);
CREATE INDEX idx_siem_configs_active ON siem_configs(is_active);

-- Drozer Sessions (for drozer_service.py)
CREATE TABLE drozer_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,

    package_name VARCHAR(512),
    status VARCHAR(32) DEFAULT 'active' CHECK (status IN ('active', 'stopped', 'error')),

    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

CREATE INDEX idx_drozer_sessions_device ON drozer_sessions(device_id);
CREATE INDEX idx_drozer_sessions_status ON drozer_sessions(status);

-- Drozer Results (for drozer_service.py)
CREATE TABLE drozer_results (
    result_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID REFERENCES drozer_sessions(session_id) ON DELETE CASCADE,

    module_name VARCHAR(128) NOT NULL,
    result_type VARCHAR(32) CHECK (result_type IN ('finding', 'info', 'error')),
    result_data JSONB DEFAULT '{}',

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_drozer_results_session ON drozer_results(session_id);

-- Objection Sessions (for objection_service.py)
CREATE TABLE objection_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id VARCHAR(128) REFERENCES devices(device_id) ON DELETE SET NULL,
    app_id VARCHAR(256) REFERENCES mobile_apps(app_id) ON DELETE CASCADE,

    package_name VARCHAR(512),
    platform VARCHAR(16) CHECK (platform IN ('android', 'ios')),
    status VARCHAR(32) DEFAULT 'active' CHECK (status IN ('active', 'stopped', 'error')),

    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

CREATE INDEX idx_objection_sessions_device ON objection_sessions(device_id);
CREATE INDEX idx_objection_sessions_status ON objection_sessions(status);

-- Grant privileges
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mobilicustos;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO mobilicustos;
