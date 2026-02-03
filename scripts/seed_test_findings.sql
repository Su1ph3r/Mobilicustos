-- Seed script for test findings data
-- Run after database is initialized

-- Clear existing test data first
DELETE FROM findings WHERE app_id = 'com.example.testapp-1.0.0';
DELETE FROM scans WHERE app_id = 'com.example.testapp-1.0.0';
DELETE FROM mobile_apps WHERE app_id = 'com.example.testapp-1.0.0';

-- Insert a test app
INSERT INTO mobile_apps (app_id, package_name, app_name, version_name, version_code, platform, framework, status)
VALUES
    ('com.example.testapp-1.0.0', 'com.example.testapp', 'Test Application', '1.0.0', 1, 'android', 'native', 'completed')
ON CONFLICT (app_id) DO NOTHING;

-- Insert a test scan
INSERT INTO scans (scan_id, app_id, scan_type, status, findings_count, started_at, completed_at, created_at)
VALUES
    ('11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0', 'static', 'completed',
     '{"critical": 2, "high": 3, "medium": 5, "low": 4, "info": 3}',
     NOW() - INTERVAL '1 hour', NOW(), NOW())
ON CONFLICT (scan_id) DO NOTHING;

-- Insert diverse test findings using actual tool names
INSERT INTO findings (finding_id, scan_id, app_id, tool, platform, severity, status, category, title, description, impact, file_path, line_number, code_snippet, remediation, cwe_id, cvss_score, owasp_masvs_category, owasp_masvs_control, first_seen, last_seen)
VALUES
    -- Critical findings
    ('finding-001', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'crypto_auditor', 'android', 'critical', 'open', 'Cryptography',
     'Hardcoded Encryption Key',
     'The application contains a hardcoded AES encryption key in the source code. This allows attackers to decrypt sensitive data if they obtain access to the APK.',
     'Attackers can decrypt all encrypted data stored by the application, potentially exposing sensitive user information, credentials, and private data.',
     'com/example/testapp/crypto/CryptoManager.java', 45,
     'private static final String AES_KEY = "1234567890123456";',
     'Use Android Keystore to generate and store encryption keys securely. Never hardcode cryptographic keys in source code.',
     'CWE-321', 9.1, 'MASVS-CRYPTO', 'MSTG-CRYPTO-1', NOW() - INTERVAL '2 days', NOW()),

    ('finding-002', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'dex_analyzer', 'android', 'critical', 'confirmed', 'Data Storage',
     'SQL Injection Vulnerability',
     'User input is directly concatenated into SQL queries without proper sanitization, allowing SQL injection attacks.',
     'Attackers can execute arbitrary SQL commands, potentially reading, modifying, or deleting all database contents.',
     'com/example/testapp/database/UserDao.java', 78,
     'String query = "SELECT * FROM users WHERE id = " + userId;',
     'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
     'CWE-89', 9.8, 'MASVS-STORAGE', 'MSTG-STORAGE-14', NOW() - INTERVAL '3 days', NOW()),

    -- High findings
    ('finding-003', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'network_security_config_analyzer', 'android', 'high', 'open', 'Network Security',
     'Certificate Pinning Not Implemented',
     'The application does not implement certificate pinning, making it vulnerable to man-in-the-middle attacks.',
     'Attackers on the same network can intercept and modify all HTTPS traffic between the app and backend servers.',
     'res/xml/network_security_config.xml', 1,
     '<!-- No certificate pinning configured -->',
     'Implement certificate pinning using Network Security Config with pin-set elements.',
     'CWE-295', 7.5, 'MASVS-NETWORK', 'MSTG-NETWORK-4', NOW() - INTERVAL '1 day', NOW()),

    ('finding-004', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'manifest_analyzer', 'android', 'high', 'confirmed', 'Code Quality',
     'Debug Mode Enabled in Production',
     'The android:debuggable flag is set to true in the AndroidManifest.xml, allowing debugging in production.',
     'Attackers can attach debuggers to the running application, inspect memory, and bypass security controls.',
     'AndroidManifest.xml', 12,
     '<application android:debuggable="true">',
     'Set android:debuggable to false in release builds or remove the attribute entirely.',
     'CWE-489', 7.2, 'MASVS-RESILIENCE', 'MSTG-RESILIENCE-2', NOW() - INTERVAL '4 days', NOW()),

    ('finding-005', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'binary_protection_analyzer', 'android', 'high', 'open', 'Authentication',
     'Weak Biometric Authentication Implementation',
     'The biometric authentication can be bypassed as it relies solely on boolean return values without cryptographic binding.',
     'Attackers can bypass biometric authentication entirely, gaining unauthorized access to protected features.',
     'com/example/testapp/auth/BiometricHelper.java', 89,
     'if (biometricResult == BiometricPrompt.AUTHENTICATION_SUCCEEDED)',
     'Implement CryptoObject-based biometric authentication and tie authentication to cryptographic operations.',
     'CWE-287', 8.1, 'MASVS-AUTH', 'MSTG-AUTH-8', NOW() - INTERVAL '2 days', NOW()),

    -- Medium findings
    ('finding-006', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'secret_scanner', 'android', 'medium', 'open', 'Logging',
     'Sensitive Data in Logs',
     'User credentials and authentication tokens are being logged to logcat in debug builds.',
     'Sensitive data may be exposed to other applications with READ_LOGS permission or via ADB.',
     'com/example/testapp/auth/LoginActivity.java', 156,
     'Log.d(TAG, "User token: " + authToken);',
     'Remove all logging statements that contain sensitive data. Use ProGuard to strip logging in release builds.',
     'CWE-532', 5.5, 'MASVS-STORAGE', 'MSTG-STORAGE-3', NOW() - INTERVAL '5 days', NOW()),

    ('finding-007', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'manifest_analyzer', 'android', 'medium', 'false_positive', 'Permissions',
     'Excessive Permissions Requested',
     'The application requests more permissions than necessary for its functionality.',
     'Excessive permissions increase the attack surface and potential impact of application compromise.',
     'AndroidManifest.xml', 8,
     '<uses-permission android:name="android.permission.READ_CONTACTS"/>',
     'Review and remove unnecessary permissions. Follow the principle of least privilege.',
     'CWE-250', 4.3, 'MASVS-PLATFORM', 'MSTG-PLATFORM-1', NOW() - INTERVAL '6 days', NOW()),

    ('finding-008', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'secure_storage_analyzer', 'android', 'medium', 'open', 'Data Storage',
     'Insecure SharedPreferences Usage',
     'Sensitive user data is stored in SharedPreferences without encryption.',
     'Data stored in SharedPreferences can be accessed by attackers with root access or via backup extraction.',
     'com/example/testapp/prefs/UserPreferences.java', 34,
     'prefs.edit().putString("auth_token", token).apply();',
     'Use EncryptedSharedPreferences from AndroidX Security library for storing sensitive data.',
     'CWE-312', 5.3, 'MASVS-STORAGE', 'MSTG-STORAGE-2', NOW() - INTERVAL '3 days', NOW()),

    ('finding-009', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'webview_auditor', 'android', 'medium', 'remediated', 'Input Validation',
     'WebView JavaScript Interface Vulnerability',
     'A JavaScript interface is exposed to WebView content without proper origin validation.',
     'Malicious web content loaded in WebView could execute arbitrary Java code through the interface.',
     'com/example/testapp/web/WebViewActivity.java', 67,
     'webView.addJavascriptInterface(new JsInterface(), "Android");',
     'Implement origin checks in JavaScript interface methods and use @JavascriptInterface annotation.',
     'CWE-749', 6.1, 'MASVS-PLATFORM', 'MSTG-PLATFORM-7', NOW() - INTERVAL '7 days', NOW()),

    ('finding-010', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'binary_protection_analyzer', 'android', 'medium', 'open', 'Anti-Tampering',
     'Root Detection Bypass Possible',
     'The root detection mechanism can be bypassed by hooking the isRooted() method.',
     'Security controls that depend on root detection can be bypassed on rooted devices.',
     'com/example/testapp/security/RootChecker.java', 23,
     'public boolean isRooted() { return checkSuBinary() || checkTestKeys(); }',
     'Implement multiple layers of root detection and integrity checks. Use native code for critical security checks.',
     'CWE-693', 5.9, 'MASVS-RESILIENCE', 'MSTG-RESILIENCE-1', NOW() - INTERVAL '4 days', NOW()),

    -- Low findings
    ('finding-011', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'manifest_analyzer', 'android', 'low', 'open', 'Configuration',
     'Backup Flag Enabled',
     'The application allows backups which may expose sensitive data through ADB backup.',
     'Users or attackers with physical access can extract application data via ADB backup.',
     'AndroidManifest.xml', 15,
     '<application android:allowBackup="true">',
     'Set android:allowBackup to false or implement a custom BackupAgent to exclude sensitive data.',
     'CWE-530', 3.3, 'MASVS-STORAGE', 'MSTG-STORAGE-8', NOW() - INTERVAL '8 days', NOW()),

    ('finding-012', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'privacy_analyzer', 'android', 'low', 'accepted_risk', 'Code Quality',
     'Unused Permission Declared',
     'The VIBRATE permission is declared but never used in the application.',
     'Unused permissions unnecessarily increase the application attack surface.',
     'AndroidManifest.xml', 10,
     '<uses-permission android:name="android.permission.VIBRATE"/>',
     'Remove unused permissions from the manifest to reduce attack surface.',
     'CWE-250', 2.1, 'MASVS-PLATFORM', 'MSTG-PLATFORM-1', NOW() - INTERVAL '10 days', NOW()),

    ('finding-013', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'ipc_scanner', 'android', 'low', 'open', 'Configuration',
     'Task Affinity Not Set',
     'Activities do not specify taskAffinity, using default package name which could allow task hijacking.',
     'Malicious applications could potentially hijack the application task stack.',
     'AndroidManifest.xml', 20,
     '<activity android:name=".MainActivity">',
     'Set taskAffinity to empty string for sensitive activities.',
     'CWE-923', 3.7, 'MASVS-PLATFORM', 'MSTG-PLATFORM-5', NOW() - INTERVAL '9 days', NOW()),

    ('finding-014', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'binary_protection_analyzer', 'android', 'low', 'open', 'Obfuscation',
     'Code Not Obfuscated',
     'The application code is not obfuscated, making reverse engineering easier.',
     'Attackers can easily understand application logic and identify vulnerabilities.',
     NULL, NULL, NULL,
     'Enable ProGuard or R8 code shrinking and obfuscation in the build configuration.',
     'CWE-656', 3.1, 'MASVS-RESILIENCE', 'MSTG-RESILIENCE-3', NOW() - INTERVAL '11 days', NOW()),

    -- Info findings
    ('finding-015', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'dependency_analyzer', 'android', 'info', 'open', 'Metadata',
     'Third-party Libraries Detected',
     'The application uses several third-party libraries that should be kept updated.',
     'Outdated libraries may contain known vulnerabilities.',
     NULL, NULL, NULL,
     'Regularly update dependencies and monitor for known vulnerabilities.',
     NULL, NULL, 'MASVS-CODE', 'MSTG-CODE-5', NOW() - INTERVAL '12 days', NOW()),

    ('finding-016', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'dex_analyzer', 'android', 'info', 'open', 'Code Quality',
     'Deprecated API Usage',
     'The application uses deprecated Android APIs that may be removed in future versions.',
     'Future Android versions may not support deprecated APIs, causing app failures.',
     'com/example/testapp/utils/DeviceUtils.java', 45,
     'String deviceId = Settings.Secure.getString(resolver, Settings.Secure.ANDROID_ID);',
     'Update to use recommended alternatives for better compatibility.',
     NULL, NULL, 'MASVS-CODE', 'MSTG-CODE-7', NOW() - INTERVAL '13 days', NOW()),

    ('finding-017', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'manifest_analyzer', 'android', 'info', 'open', 'Permissions',
     'Internet Permission Used',
     'The application requests internet access permission.',
     'This is informational only - internet access is common for most applications.',
     'AndroidManifest.xml', 7,
     '<uses-permission android:name="android.permission.INTERNET"/>',
     'This is informational. Ensure network communications are properly secured.',
     NULL, NULL, 'MASVS-NETWORK', 'MSTG-NETWORK-1', NOW() - INTERVAL '14 days', NOW())

ON CONFLICT (finding_id) DO UPDATE SET
    tool = EXCLUDED.tool,
    description = EXCLUDED.description,
    impact = EXCLUDED.impact,
    remediation = EXCLUDED.remediation;

-- Update scan counts to match
UPDATE scans
SET findings_count = (
    SELECT json_build_object(
        'critical', COUNT(*) FILTER (WHERE severity = 'critical'),
        'high', COUNT(*) FILTER (WHERE severity = 'high'),
        'medium', COUNT(*) FILTER (WHERE severity = 'medium'),
        'low', COUNT(*) FILTER (WHERE severity = 'low'),
        'info', COUNT(*) FILTER (WHERE severity = 'info')
    )
    FROM findings
    WHERE findings.scan_id = scans.scan_id
)
WHERE scan_id = '11111111-1111-1111-1111-111111111111';

-- Verify the data
SELECT 'Test data seeded successfully!' as message;
SELECT severity, COUNT(*) as count FROM findings WHERE app_id = 'com.example.testapp-1.0.0' GROUP BY severity ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;
SELECT tool, COUNT(*) as count FROM findings WHERE app_id = 'com.example.testapp-1.0.0' GROUP BY tool ORDER BY count DESC;
