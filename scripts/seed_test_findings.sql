-- Seed script for test findings data
-- Run after database is initialized
-- Updated with Nubicustos-parity structured evidence fields

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

-- Insert diverse test findings using actual tool names with structured evidence
INSERT INTO findings (
    finding_id, scan_id, app_id, tool, tool_sources, platform, severity, status, category,
    title, description, impact, file_path, line_number, code_snippet, remediation,
    cwe_id, cwe_name, cvss_score, cvss_vector, owasp_masvs_category, owasp_masvs_control, owasp_mastg_test,
    poc_evidence, poc_verification, poc_commands, poc_frida_script,
    remediation_commands, remediation_code, remediation_resources,
    canonical_id, first_seen, last_seen
)
VALUES
    -- Critical findings
    ('finding-001', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'crypto_auditor', '["crypto_auditor"]', 'android', 'critical', 'open', 'Cryptography',
     'Hardcoded Encryption Key',
     'The application contains a hardcoded AES encryption key in the source code. This allows attackers to decrypt sensitive data if they obtain access to the APK.',
     'Attackers can decrypt all encrypted data stored by the application, potentially exposing sensitive user information, credentials, and private data.',
     'com/example/testapp/crypto/CryptoManager.java', 45,
     'private static final String AES_KEY = "1234567890123456";',
     'Use Android Keystore to generate and store encryption keys securely. Never hardcode cryptographic keys in source code.',
     'CWE-321', 'Use of Hard-coded Cryptographic Key', 9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
     'MASVS-CRYPTO', 'MSTG-CRYPTO-1', 'MASTG-TEST-0013',
     'Found hardcoded AES key: 1234****3456',
     'jadx -d decompiled app.apk && grep -rn "SecretKeySpec\|AES_KEY" decompiled/',
     '[{"type": "bash", "command": "jadx -d decompiled app.apk", "description": "Decompile APK to extract source"}, {"type": "bash", "command": "grep -rn ''AES_KEY\\|SecretKeySpec'' decompiled/", "description": "Search for hardcoded keys"}]',
     E'Java.perform(function() {\n    var SecretKeySpec = Java.use(''javax.crypto.spec.SecretKeySpec'');\n    SecretKeySpec.$init.overload(''[B'', ''java.lang.String'').implementation = function(key, algo) {\n        console.log("[*] SecretKeySpec: " + algo);\n        console.log("    Key: " + bytesToHex(key));\n        return this.$init(key, algo);\n    };\n});',
     '[{"type": "android", "command": "KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, \"AndroidKeyStore\")", "description": "Use KeyStore for key generation"}]',
     '{"kotlin": "val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, \"AndroidKeyStore\")\nkeyGenerator.init(KeyGenParameterSpec.Builder(\"my_key\", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).build())\nval secretKey = keyGenerator.generateKey()"}',
     '[{"title": "OWASP MASTG - Testing for Hardcoded Cryptographic Keys", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/", "type": "documentation"}, {"title": "Android KeyStore System", "url": "https://developer.android.com/training/articles/keystore", "type": "documentation"}]',
     'cryptography_hardcoded_encryption_key_com.example.testapp-1.0.0_android',
     NOW() - INTERVAL '2 days', NOW()),

    -- Critical: SQL Injection with structured evidence
    ('finding-002', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'dex_analyzer', '["dex_analyzer"]', 'android', 'critical', 'confirmed', 'Data Storage',
     'SQL Injection Vulnerability',
     'User input is directly concatenated into SQL queries without proper sanitization, allowing SQL injection attacks.',
     'Attackers can execute arbitrary SQL commands, potentially reading, modifying, or deleting all database contents.',
     'com/example/testapp/database/UserDao.java', 78,
     'String query = "SELECT * FROM users WHERE id = " + userId;',
     'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
     'CWE-89', 'Improper Neutralization of Special Elements used in an SQL Command', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
     'MASVS-STORAGE', 'MSTG-STORAGE-14', 'MASTG-TEST-0001',
     'SQL query constructed with user input concatenation. Vulnerable to injection.',
     'grep -rn "SELECT.*+.*userId" decompiled/',
     '[{"type": "adb", "command": "adb shell am start -n com.example.testapp/.UserActivity -e user_id \"1 OR 1=1\"", "description": "Test SQL injection via intent"}, {"type": "frida", "command": "frida -U -f com.example.testapp -l sqli_hook.js", "description": "Hook database queries to observe injection"}]',
     E'Java.perform(function() {\n    var SQLiteDatabase = Java.use(''android.database.sqlite.SQLiteDatabase'');\n    SQLiteDatabase.rawQuery.overload(''java.lang.String'', ''[Ljava.lang.String;'').implementation = function(sql, args) {\n        console.log("[*] rawQuery: " + sql);\n        return this.rawQuery(sql, args);\n    };\n});',
     '[{"type": "android", "command": "db.query(table, columns, \"id = ?\", new String[]{userId}, ...)", "description": "Use parameterized query"}]',
     '{"kotlin": "val cursor = db.query(\n    \"users\",\n    arrayOf(\"id\", \"name\"),\n    \"id = ?\",\n    arrayOf(userId),\n    null, null, null\n)", "java": "Cursor cursor = db.query(\"users\", new String[]{\"id\", \"name\"}, \"id = ?\", new String[]{userId}, null, null, null);"}',
     '[{"title": "OWASP - SQL Injection", "url": "https://owasp.org/www-community/attacks/SQL_Injection", "type": "documentation"}, {"title": "Android Room Database", "url": "https://developer.android.com/training/data-storage/room", "type": "documentation"}]',
     'data_storage_sql_injection_vulnerability_com.example.testapp-1.0.0_android',
     NOW() - INTERVAL '3 days', NOW()),

    -- High: Certificate Pinning with structured evidence
    ('finding-003', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'network_security_config_analyzer', '["network_security_config_analyzer"]', 'android', 'high', 'open', 'Network Security',
     'Certificate Pinning Not Implemented',
     'The application does not implement certificate pinning, making it vulnerable to man-in-the-middle attacks.',
     'Attackers on the same network can intercept and modify all HTTPS traffic between the app and backend servers.',
     'res/xml/network_security_config.xml', 1,
     '<!-- No certificate pinning configured -->',
     'Implement certificate pinning using Network Security Config with pin-set elements.',
     'CWE-295', 'Improper Certificate Validation', 7.5, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
     'MASVS-NETWORK', 'MSTG-NETWORK-4', 'MASTG-TEST-0022',
     'Network Security Config does not contain pin-set configuration.',
     'objection -g com.example.testapp explore --startup-command "android sslpinning disable"',
     '[{"type": "objection", "command": "objection -g com.example.testapp explore --startup-command \"android sslpinning disable\"", "description": "Test if SSL pinning can be bypassed (should fail if properly implemented)"}, {"type": "frida", "command": "frida -U -f com.example.testapp -l ssl_pinning_bypass.js", "description": "Attempt to bypass SSL pinning"}]',
     E'// SSL Pinning Bypass Test\nJava.perform(function() {\n    var TrustManagerImpl = Java.use(''com.android.org.conscrypt.TrustManagerImpl'');\n    TrustManagerImpl.verifyChain.implementation = function() {\n        console.log("[!] SSL Pinning bypassed!");\n        return Java.use(''java.util.ArrayList'').$new();\n    };\n});',
     '[{"type": "android", "command": "Add pin-set to network_security_config.xml", "description": "Configure certificate pinning"}]',
     '{"xml": "<network-security-config>\n    <domain-config>\n        <domain includeSubdomains=\"true\">api.example.com</domain>\n        <pin-set expiration=\"2025-01-01\">\n            <pin digest=\"SHA-256\">BASE64_ENCODED_PIN=</pin>\n            <pin digest=\"SHA-256\">BACKUP_PIN=</pin>\n        </pin-set>\n    </domain-config>\n</network-security-config>"}',
     '[{"title": "OWASP MASTG - Testing Custom Certificate Stores and Certificate Pinning", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0022/", "type": "documentation"}, {"title": "Android Network Security Config", "url": "https://developer.android.com/training/articles/security-config", "type": "documentation"}]',
     'network_security_certificate_pinning_not_implemented_com.example.testapp-1.0.0_android',
     NOW() - INTERVAL '1 day', NOW()),

    -- High: Debug Mode with structured evidence
    ('finding-004', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'manifest_analyzer', '["manifest_analyzer"]', 'android', 'high', 'confirmed', 'Configuration',
     'Debug Mode Enabled in Production',
     'The android:debuggable flag is set to true in the AndroidManifest.xml, allowing debugging in production.',
     'Attackers can attach debuggers to the running application, inspect memory, and bypass security controls.',
     'AndroidManifest.xml', 12,
     '<application android:debuggable="true">',
     'Set android:debuggable to false in release builds or remove the attribute entirely.',
     'CWE-489', 'Active Debug Code', 7.2, 'CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N',
     'MASVS-RESILIENCE', 'MSTG-RESILIENCE-2', 'MASTG-TEST-0039',
     'Manifest contains android:debuggable="true"',
     'adb shell run-as com.example.testapp ls /data/data/com.example.testapp',
     '[{"type": "adb", "command": "adb jdwp", "description": "List debuggable processes"}, {"type": "adb", "command": "adb shell run-as com.example.testapp ls /data/data/com.example.testapp", "description": "Access app private data (debuggable apps only)"}]',
     E'Java.perform(function() {\n    var context = Java.use(''android.app.ActivityThread'').currentApplication().getApplicationContext();\n    var appInfo = context.getApplicationInfo();\n    console.log("[*] Debuggable: " + ((appInfo.flags.value & 2) != 0));\n});',
     '[{"type": "android", "command": "android:debuggable=\"false\"", "description": "Set in AndroidManifest.xml"}]',
     '{"gradle": "android {\n    buildTypes {\n        release {\n            debuggable false\n        }\n    }\n}"}',
     '[{"title": "OWASP MASTG - Testing for Debugging Symbols", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039/", "type": "documentation"}]',
     'configuration_debug_mode_enabled_in_production_com.example.testapp-1.0.0_android',
     NOW() - INTERVAL '4 days', NOW()),

    -- High: Weak Biometric with structured evidence
    ('finding-005', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'binary_protection_analyzer', '["binary_protection_analyzer"]', 'android', 'high', 'open', 'Authentication',
     'Weak Biometric Authentication Implementation',
     'The biometric authentication can be bypassed as it relies solely on boolean return values without cryptographic binding.',
     'Attackers can bypass biometric authentication entirely, gaining unauthorized access to protected features.',
     'com/example/testapp/auth/BiometricHelper.java', 89,
     'if (biometricResult == BiometricPrompt.AUTHENTICATION_SUCCEEDED)',
     'Implement CryptoObject-based biometric authentication and tie authentication to cryptographic operations.',
     'CWE-287', 'Improper Authentication', 8.1, 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
     'MASVS-AUTH', 'MSTG-AUTH-8', 'MASTG-TEST-0015',
     'Biometric check uses boolean result without CryptoObject binding.',
     'frida -U -f com.example.testapp -l biometric_bypass.js',
     '[{"type": "frida", "command": "frida -U -f com.example.testapp -l biometric_bypass.js", "description": "Bypass biometric authentication"}, {"type": "objection", "command": "objection -g com.example.testapp explore -c \"android hooking watch class_method android.hardware.biometrics.BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded\"", "description": "Monitor biometric callbacks"}]',
     E'// Bypass biometric authentication\nJava.perform(function() {\n    var BiometricPrompt = Java.use(''androidx.biometric.BiometricPrompt$AuthenticationCallback'');\n    BiometricPrompt.onAuthenticationSucceeded.implementation = function(result) {\n        console.log("[*] Forcing biometric success!");\n        this.onAuthenticationSucceeded(result);\n    };\n});',
     '[{"type": "android", "command": "Use CryptoObject with BiometricPrompt", "description": "Bind biometric to cryptographic operation"}]',
     '{"kotlin": "val cipher = Cipher.getInstance(\"AES/GCM/NoPadding\")\ncipher.init(Cipher.ENCRYPT_MODE, secretKey)\nval cryptoObject = BiometricPrompt.CryptoObject(cipher)\nbiometricPrompt.authenticate(promptInfo, cryptoObject)"}',
     '[{"title": "OWASP MASTG - Testing Local Authentication", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-AUTH/MASTG-TEST-0015/", "type": "documentation"}, {"title": "Android Biometric Authentication", "url": "https://developer.android.com/training/sign-in/biometric-auth", "type": "documentation"}]',
     'authentication_weak_biometric_authentication_implementation_com.example.testapp-1.0.0_android',
     NOW() - INTERVAL '2 days', NOW()),

    -- Medium: Sensitive Logs (simplified structure)
    ('finding-006', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'secret_scanner', '["secret_scanner"]', 'android', 'medium', 'open', 'Logging',
     'Sensitive Data in Logs',
     'User credentials and authentication tokens are being logged to logcat in debug builds.',
     'Sensitive data may be exposed to other applications with READ_LOGS permission or via ADB.',
     'com/example/testapp/auth/LoginActivity.java', 156,
     'Log.d(TAG, "User token: " + authToken);',
     'Remove all logging statements that contain sensitive data. Use ProGuard to strip logging in release builds.',
     'CWE-532', 'Insertion of Sensitive Information into Log File', 5.5, 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
     'MASVS-STORAGE', 'MSTG-STORAGE-3', 'MASTG-TEST-0003',
     'Log.d statement outputs authentication token',
     'adb logcat | grep -i "token\|password\|secret"',
     '[{"type": "adb", "command": "adb logcat | grep -i \"token\\|password\\|secret\"", "description": "Monitor logcat for sensitive data"}, {"type": "frida", "command": "frida -U -f com.example.testapp -l log_hook.js", "description": "Hook Log class to capture all logging"}]',
     NULL,
     '[{"type": "android", "command": "-assumenosideeffects class android.util.Log { *; }", "description": "ProGuard rule to strip logs"}]',
     '{"proguard": "-assumenosideeffects class android.util.Log {\n    public static *** d(...);\n    public static *** v(...);\n    public static *** i(...);\n}"}',
     '[{"title": "OWASP MASTG - Testing Logs for Sensitive Data", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0003/", "type": "documentation"}]',
     'logging_sensitive_data_in_logs_com.example.testapp-1.0.0_android',
     NOW() - INTERVAL '5 days', NOW()),

    -- Medium: Insecure Storage (simplified)
    ('finding-008', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'secure_storage_analyzer', '["secure_storage_analyzer"]', 'android', 'medium', 'open', 'Data Storage',
     'Insecure SharedPreferences Usage',
     'Sensitive user data is stored in SharedPreferences without encryption.',
     'Data stored in SharedPreferences can be accessed by attackers with root access or via backup extraction.',
     'com/example/testapp/prefs/UserPreferences.java', 34,
     'prefs.edit().putString("auth_token", token).apply();',
     'Use EncryptedSharedPreferences from AndroidX Security library for storing sensitive data.',
     'CWE-312', 'Cleartext Storage of Sensitive Information', 5.3, 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N',
     'MASVS-STORAGE', 'MSTG-STORAGE-2', 'MASTG-TEST-0002',
     'SharedPreferences stores auth_token in plaintext',
     'adb shell run-as com.example.testapp cat shared_prefs/*.xml',
     '[{"type": "adb", "command": "adb shell run-as com.example.testapp cat shared_prefs/*.xml", "description": "Read SharedPreferences files (debuggable apps)"}, {"type": "adb", "command": "adb backup -f backup.ab com.example.testapp && abe unpack backup.ab backup.tar", "description": "Extract via backup"}]',
     NULL,
     '[{"type": "android", "command": "EncryptedSharedPreferences.create(...)", "description": "Use encrypted storage"}]',
     '{"kotlin": "val masterKey = MasterKey.Builder(context)\n    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)\n    .build()\nval prefs = EncryptedSharedPreferences.create(\n    context, \"secret_prefs\", masterKey,\n    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n)"}',
     '[{"title": "EncryptedSharedPreferences", "url": "https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences", "type": "documentation"}]',
     'data_storage_insecure_sharedpreferences_usage_com.example.testapp-1.0.0_android',
     NOW() - INTERVAL '3 days', NOW()),

    -- Low: Backup Enabled
    ('finding-011', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'manifest_analyzer', '["manifest_analyzer"]', 'android', 'low', 'open', 'Configuration',
     'Backup Flag Enabled',
     'The application allows backups which may expose sensitive data through ADB backup.',
     'Users or attackers with physical access can extract application data via ADB backup.',
     'AndroidManifest.xml', 15,
     '<application android:allowBackup="true">',
     'Set android:allowBackup to false or implement a custom BackupAgent to exclude sensitive data.',
     'CWE-530', 'Exposure of Backup File to an Unauthorized Control Sphere', 3.3, 'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
     'MASVS-STORAGE', 'MSTG-STORAGE-8', 'MASTG-TEST-0008',
     'allowBackup is true (or default)',
     'adb backup -f backup.ab -apk com.example.testapp',
     '[{"type": "adb", "command": "adb backup -f backup.ab -apk com.example.testapp", "description": "Create backup"}]',
     NULL,
     '[{"type": "android", "command": "android:allowBackup=\"false\"", "description": "Disable backups"}]',
     '{"xml": "<application android:allowBackup=\"false\">"}',
     '[{"title": "OWASP MASTG - Testing Backups", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0008/", "type": "documentation"}]',
     'configuration_backup_flag_enabled_com.example.testapp-1.0.0_android',
     NOW() - INTERVAL '8 days', NOW()),

    -- Info: Third-party Libraries (with specific library list)
    ('finding-015', '11111111-1111-1111-1111-111111111111', 'com.example.testapp-1.0.0',
     'dependency_analyzer', '["dependency_analyzer"]', 'android', 'info', 'open', 'Dependencies',
     'Third-party Libraries Detected (7 libraries)',
     'The application includes 7 third-party libraries. These dependencies should be regularly updated to patch security vulnerabilities and maintained to ensure compatibility. See the Evidence tab for the complete list of detected libraries with versions.',
     'Outdated libraries may contain known vulnerabilities. Regular dependency updates are essential for security.',
     'build.gradle', 28,
     E'implementation ''com.squareup.retrofit2:retrofit:2.9.0''\nimplementation ''com.squareup.okhttp3:okhttp:4.10.0''\nimplementation ''com.google.code.gson:gson:2.9.1''',
     E'1. Run dependency vulnerability scan using OWASP Dependency-Check or Snyk\n2. Update outdated libraries to latest stable versions\n3. Configure Dependabot or Renovate for automated updates\n4. Review release notes for security-related changes',
     'CWE-1395', 'Dependency on Vulnerable Third-Party Component', 3.0, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
     'MASVS-CODE', 'MSTG-CODE-5', 'MASTG-TEST-0027',
     '[{"package": "com.squareup.retrofit2:retrofit", "version": "2.9.0", "description": "HTTP client"}, {"package": "com.squareup.okhttp3:okhttp", "version": "4.10.0", "description": "Network layer"}, {"package": "com.google.code.gson:gson", "version": "2.9.1", "description": "JSON serialization"}, {"package": "io.reactivex.rxjava3:rxjava", "version": "3.1.5", "description": "Reactive extensions"}, {"package": "com.jakewharton.timber:timber", "version": "5.0.1", "description": "Logging framework"}, {"package": "org.jetbrains.kotlinx:kotlinx-coroutines-android", "version": "1.6.4", "description": "Coroutines"}, {"package": "com.google.dagger:hilt-android", "version": "2.44", "description": "Dependency injection"}]',
     E'1. Decompile APK: apktool d app.apk -o decompiled/\n2. Check build.gradle for dependencies\n3. Run: ./gradlew dependencies --configuration releaseRuntimeClasspath',
     '[{"type": "bash", "command": "apktool d app.apk -o decompiled/", "description": "Decompile APK to extract source"}, {"type": "bash", "command": "grep -rn ''implementation\\|api'' decompiled/build.gradle", "description": "Find declared dependencies"}, {"type": "bash", "command": "./gradlew dependencies --configuration releaseRuntimeClasspath", "description": "List all transitive dependencies"}, {"type": "bash", "command": "dependency-check --scan app.apk --format HTML", "description": "Run OWASP Dependency-Check"}]',
     NULL,
     '[{"type": "bash", "command": "./gradlew dependencyUpdates", "description": "Check for available updates"}, {"type": "bash", "command": "snyk test --all-projects", "description": "Scan with Snyk for vulnerabilities"}]',
     '{"gradle": "// In build.gradle - use version catalogs for centralized management\n[versions]\nretrofit = \"2.9.0\"\nokhttp = \"4.12.0\"\ngson = \"2.10.1\"\n\n[libraries]\nretrofit-core = { module = \"com.squareup.retrofit2:retrofit\", version.ref = \"retrofit\" }"}',
     '[{"title": "OWASP Dependency-Check", "url": "https://owasp.org/www-project-dependency-check/", "type": "tool"}, {"title": "Snyk - Dependency Vulnerability Scanner", "url": "https://snyk.io/", "type": "tool"}, {"title": "Gradle Version Catalogs", "url": "https://docs.gradle.org/current/userguide/platforms.html", "type": "documentation"}, {"title": "OWASP MASTG - Testing Third-Party Libraries", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-CODE/MASTG-TEST-0027/", "type": "documentation"}]',
     'dependencies_third_party_libraries_detected_com.example.testapp-1.0.0_android',
     NOW() - INTERVAL '12 days', NOW())

ON CONFLICT (finding_id) DO UPDATE SET
    tool = EXCLUDED.tool,
    tool_sources = EXCLUDED.tool_sources,
    description = EXCLUDED.description,
    impact = EXCLUDED.impact,
    remediation = EXCLUDED.remediation,
    poc_evidence = EXCLUDED.poc_evidence,
    poc_verification = EXCLUDED.poc_verification,
    poc_commands = EXCLUDED.poc_commands,
    poc_frida_script = EXCLUDED.poc_frida_script,
    remediation_commands = EXCLUDED.remediation_commands,
    remediation_code = EXCLUDED.remediation_code,
    remediation_resources = EXCLUDED.remediation_resources,
    canonical_id = EXCLUDED.canonical_id,
    cvss_score = EXCLUDED.cvss_score,
    cvss_vector = EXCLUDED.cvss_vector,
    cwe_name = EXCLUDED.cwe_name,
    owasp_mastg_test = EXCLUDED.owasp_mastg_test;

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
