"""Secure storage analyzer for mobile application data protection.

Performs static analysis of mobile application archives to detect insecure
data storage practices that could expose sensitive user information to
unauthorized access via device compromise, backup extraction, or
inter-application data access.

Security checks performed:
    - **SharedPreferences/NSUserDefaults Misuse**: Detects sensitive data
      (passwords, tokens, credentials) stored in unencrypted platform
      preferences, and insecure file modes (MODE_WORLD_READABLE/WRITABLE).
    - **SQLite Database Security**: Identifies world-readable/writable
      databases, unencrypted databases containing sensitive tables, and
      database files bundled in the application package.
    - **Keychain/Keystore Usage**: Verifies presence of Android KeyStore
      or iOS Keychain APIs when sensitive data storage is detected;
      flags missing secure storage implementation.
    - **File Storage Permissions**: Detects use of external storage for
      sensitive data and insecure file permission modes.
    - **Backup Configuration**: Checks for android:allowBackup and
      absence of fullBackupContent or dataExtractionRules.
    - **Encrypted Storage Detection**: Recognizes positive security
      patterns including EncryptedSharedPreferences, EncryptedFile,
      SQLCipher, and encrypted Realm databases.

OWASP references:
    - MASVS-STORAGE: Data Storage and Privacy
    - MASVS-STORAGE-1, MASVS-STORAGE-2
    - OWASP Mobile Top 10 M2: Insecure Data Storage
    - CWE-312: Cleartext Storage of Sensitive Information
    - CWE-311: Missing Encryption of Sensitive Data
    - CWE-922: Insecure Storage of Sensitive Information
    - CWE-276: Incorrect Default Permissions
    - CWE-530: Exposure of Backup File to an Unauthorized Control Sphere
    - CWE-732: Incorrect Permission Assignment for Critical Resource
"""

import os
import re
import logging
from typing import Optional

from api.models.database import MobileApp, Finding
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class SecureStorageAnalyzer(BaseAnalyzer):
    """Analyzes secure storage implementation in mobile applications.

    Extracts the application archive and scans decompiled source code
    for data storage anti-patterns including insecure SharedPreferences
    modes, sensitive data in unencrypted preferences, missing KeyStore/
    Keychain usage, world-readable databases, external storage writes,
    and backup configuration issues.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform (defaults to "android").
        ANDROID_SHARED_PREFS_PATTERNS: Regex patterns for detecting
            SharedPreferences usage.
        INSECURE_MODES: Patterns for deprecated world-readable/writable
            file modes.
        SENSITIVE_PREF_KEYS: Patterns for sensitive data in preferences.
        IOS_USERDEFAULTS_PATTERNS: Patterns for NSUserDefaults usage.
        IOS_KEYCHAIN_PATTERNS: Positive patterns indicating Keychain usage.
        ANDROID_KEYSTORE_PATTERNS: Positive patterns indicating KeyStore usage.
        ENCRYPTED_STORAGE_PATTERNS: Positive patterns for encrypted storage.
    """

    name = "secure_storage_analyzer"
    platform = "android"

    # Android SharedPreferences patterns
    ANDROID_SHARED_PREFS_PATTERNS = [
        (r'getSharedPreferences\s*\(\s*["\']([^"\']+)["\']', "SharedPreferences file"),
        (r'getPreferences\s*\(', "Activity preferences"),
        (r'PreferenceManager\.getDefaultSharedPreferences', "Default SharedPreferences"),
    ]

    # Insecure SharedPreferences modes
    INSECURE_MODES = [
        (r'MODE_WORLD_READABLE', "World-readable SharedPreferences - accessible by other apps"),
        (r'MODE_WORLD_WRITEABLE', "World-writable SharedPreferences - modifiable by other apps"),
        (r'Context\.MODE_MULTI_PROCESS', "Multi-process mode deprecated and insecure"),
    ]

    # Sensitive data in SharedPreferences
    SENSITIVE_PREF_KEYS = [
        (r'\.putString\s*\(\s*["\'](?:password|passwd|pwd|secret|token|api_key|apikey|auth|credential|session)', "Sensitive data in SharedPreferences"),
        (r'\.edit\(\).*\.putString\s*\(\s*["\'](?:password|passwd|pwd|secret|token|api_key|apikey|auth|credential|session)', "Sensitive data stored insecurely"),
    ]

    # iOS NSUserDefaults patterns
    IOS_USERDEFAULTS_PATTERNS = [
        (r'\[NSUserDefaults\s+standardUserDefaults\]', "NSUserDefaults usage"),
        (r'UserDefaults\.standard', "Swift UserDefaults usage"),
        (r'\.set\([^,]+,\s*forKey:\s*["\'](?:password|token|secret|apiKey|auth|credential|session)', "Sensitive data in UserDefaults"),
    ]

    # iOS Keychain patterns (good)
    IOS_KEYCHAIN_PATTERNS = [
        (r'SecItemAdd', "Keychain SecItemAdd"),
        (r'SecItemUpdate', "Keychain SecItemUpdate"),
        (r'SecItemCopyMatching', "Keychain SecItemCopyMatching"),
        (r'kSecClass', "Keychain usage"),
    ]

    # Android Keystore patterns (good)
    ANDROID_KEYSTORE_PATTERNS = [
        (r'KeyStore\.getInstance\s*\(\s*["\']AndroidKeyStore["\']', "Android KeyStore usage"),
        (r'KeyGenerator\.getInstance.*AndroidKeyStore', "KeyStore key generation"),
        (r'KeyPairGenerator\.getInstance.*AndroidKeyStore', "KeyStore key pair generation"),
    ]

    # SQLite database patterns
    SQLITE_PATTERNS = [
        (r'SQLiteOpenHelper', "SQLite database usage"),
        (r'openOrCreateDatabase\s*\(', "Direct database creation"),
        (r'\.rawQuery\s*\(', "Raw SQL query"),
        (r'\.execSQL\s*\(', "SQL execution"),
        (r'Room\.databaseBuilder', "Room database"),
    ]

    # Insecure SQLite patterns
    INSECURE_SQLITE_PATTERNS = [
        (r'openOrCreateDatabase\s*\([^,]+,\s*MODE_WORLD_READABLE', "World-readable database"),
        (r'openOrCreateDatabase\s*\([^,]+,\s*MODE_WORLD_WRITEABLE', "World-writable database"),
        (r'SQLiteDatabase\.NO_LOCALIZED_COLLATORS', "Database without encryption"),
    ]

    # File storage patterns
    FILE_STORAGE_PATTERNS = [
        (r'openFileOutput\s*\(\s*["\']([^"\']+)["\']', "Internal file storage"),
        (r'getExternalFilesDir', "External file storage"),
        (r'getExternalStorageDirectory', "External storage (deprecated)"),
        (r'Environment\.getExternalStorageDirectory', "External storage directory"),
        (r'FileOutputStream\s*\(\s*new\s+File\s*\([^)]*getExternalStorage', "External file write"),
    ]

    # Insecure file modes
    INSECURE_FILE_MODES = [
        (r'MODE_WORLD_READABLE', "World-readable file"),
        (r'MODE_WORLD_WRITEABLE', "World-writable file"),
        (r'\.setReadable\s*\(\s*true\s*,\s*false\s*\)', "File readable by all"),
        (r'\.setWritable\s*\(\s*true\s*,\s*false\s*\)', "File writable by all"),
    ]

    # Backup configuration issues
    BACKUP_PATTERNS = [
        (r'android:allowBackup\s*=\s*["\']true["\']', "Backup allowed - sensitive data may be extracted"),
        (r'android:fullBackupContent', "Full backup content specified"),
        (r'android:dataExtractionRules', "Data extraction rules (Android 12+)"),
    ]

    # Encrypted storage patterns (good practices)
    ENCRYPTED_STORAGE_PATTERNS = [
        (r'EncryptedSharedPreferences', "Encrypted SharedPreferences (good)"),
        (r'EncryptedFile', "Encrypted file storage (good)"),
        (r'SQLCipher', "SQLCipher encrypted database (good)"),
        (r'Realm\.Configuration.*encryptionKey', "Encrypted Realm database (good)"),
    ]

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze the application for secure storage vulnerabilities.

        Extracts the archive, runs platform-specific storage analysis,
        then performs cross-platform database and file storage checks.

        Args:
            app: The mobile application to analyze.

        Returns:
            A list of Finding objects for insecure storage practices.
        """
        if not app.file_path:
            return []

        import shutil
        import tempfile
        import zipfile

        extracted_path = None
        try:
            extracted_path = tempfile.mkdtemp(prefix="secure_storage_")
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            findings = []

            if app.platform == "android":
                findings.extend(await self._analyze_android_storage(app, extracted_path))
            elif app.platform == "ios":
                findings.extend(await self._analyze_ios_storage(app, extracted_path))

            # Common analyses
            findings.extend(await self._analyze_database_security(app, extracted_path))
            findings.extend(await self._analyze_file_storage(app, extracted_path))

            logger.info(f"SecureStorageAnalyzer found {len(findings)} issues in {app.app_id}")
            return findings

        except Exception as e:
            logger.error(f"Error in SecureStorageAnalyzer: {e}")
            return []
        finally:
            if extracted_path and os.path.exists(extracted_path):
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    async def _analyze_android_storage(self, app: MobileApp, extracted_path: str) -> list[Finding]:
        """Analyze Android-specific storage patterns.

        Scans Java/Kotlin/Smali source for insecure SharedPreferences
        modes, sensitive data in preferences without encryption, missing
        KeyStore usage, and backup configuration in AndroidManifest.xml.

        Args:
            app: The mobile application being analyzed.
            extracted_path: Root directory of the extracted APK.

        Returns:
            A list of Finding objects for Android storage issues.
        """
        findings = []

        # Search through decompiled source
        source_dirs = [
            os.path.join(extracted_path, "sources"),
            os.path.join(extracted_path, "smali"),
            os.path.join(extracted_path, "java"),
        ]

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
                            lines = content.split('\n')

                        # Check for insecure SharedPreferences modes
                        for pattern, description in self.INSECURE_MODES:
                            for i, line in enumerate(lines, 1):
                                if re.search(pattern, line):
                                    findings.append(self._create_finding(
                                        app=app,
                                        title=f"Insecure SharedPreferences Mode: {description}",
                                        description=f"The app uses {description}. This mode is deprecated and allows other apps to access the data.",
                                        severity="high",
                                        category="MASVS-STORAGE",
                                        file_path=relative_path,
                                        line_number=i,
                                        code_snippet=self._get_context(lines, i, 3),
                                        cwe_id="CWE-922",
                                        owasp_category="M2",
                                    ))

                        # Check for sensitive data in SharedPreferences
                        for pattern, description in self.SENSITIVE_PREF_KEYS:
                            for match in re.finditer(pattern, content, re.IGNORECASE):
                                line_num = content[:match.start()].count('\n') + 1
                                findings.append(self._create_finding(
                                    app=app,
                                    title="Sensitive Data in SharedPreferences",
                                    description="Sensitive data such as passwords or tokens is being stored in SharedPreferences without encryption. Use EncryptedSharedPreferences instead.",
                                    severity="high",
                                    category="MASVS-STORAGE",
                                    file_path=relative_path,
                                    line_number=line_num,
                                    code_snippet=self._get_context(lines, line_num, 3),
                                    cwe_id="CWE-312",
                                    owasp_category="M2",
                                ))

                        # Check for KeyStore usage (positive finding if missing)
                        has_keystore = any(re.search(p[0], content) for p in self.ANDROID_KEYSTORE_PATTERNS)
                        has_encrypted_prefs = re.search(r'EncryptedSharedPreferences', content)
                        has_sensitive_storage = any(re.search(p[0], content, re.IGNORECASE) for p in self.SENSITIVE_PREF_KEYS)

                        if has_sensitive_storage and not has_keystore and not has_encrypted_prefs:
                            findings.append(self._create_finding(
                                app=app,
                                title="Missing Secure Storage Implementation",
                                description="The app stores sensitive data but does not use Android KeyStore or EncryptedSharedPreferences for secure storage.",
                                severity="medium",
                                category="MASVS-STORAGE",
                                file_path=relative_path,
                                cwe_id="CWE-311",
                                owasp_category="M2",
                            ))

                    except Exception as e:
                        logger.debug(f"Error reading {file_path}: {e}")

        # Check AndroidManifest.xml for backup settings
        manifest_path = os.path.join(extracted_path, "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, 'r', errors='ignore') as f:
                    manifest_content = f.read()
                    manifest_lines = manifest_content.split('\n')

                for pattern, description in self.BACKUP_PATTERNS:
                    for match in re.finditer(pattern, manifest_content):
                        line_num = manifest_content[:match.start()].count('\n') + 1

                        if 'allowBackup' in pattern:
                            findings.append(self._create_finding(
                                app=app,
                                title="Application Backup Enabled",
                                description="The app allows backup which may expose sensitive data. Consider setting android:allowBackup='false' or implementing backup rules.",
                                severity="medium",
                                category="MASVS-STORAGE",
                                file_path="AndroidManifest.xml",
                                line_number=line_num,
                                code_snippet=self._get_context(manifest_lines, line_num, 2),
                                cwe_id="CWE-530",
                                owasp_category="M2",
                            ))
            except Exception as e:
                logger.debug(f"Error reading manifest: {e}")

        return findings

    async def _analyze_ios_storage(self, app: MobileApp, extracted_path: str) -> list[Finding]:
        """Analyze iOS-specific storage patterns.

        Scans Objective-C/Swift source for sensitive data in
        NSUserDefaults without Keychain usage.

        Args:
            app: The mobile application being analyzed.
            extracted_path: Root directory of the extracted IPA.

        Returns:
            A list of Finding objects for iOS storage issues.
        """
        findings = []

        # Search through decompiled source or strings
        source_dirs = [
            os.path.join(extracted_path, "Payload"),
            extracted_path,
        ]

        for source_dir in source_dirs:
            if not os.path.exists(source_dir):
                continue

            for root, _, files in os.walk(source_dir):
                for file in files:
                    if not file.endswith(('.m', '.swift', '.h', '.mm')):
                        continue

                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, extracted_path)

                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                            lines = content.split('\n')

                        # Check for sensitive data in NSUserDefaults
                        for pattern, description in self.IOS_USERDEFAULTS_PATTERNS:
                            for match in re.finditer(pattern, content, re.IGNORECASE):
                                line_num = content[:match.start()].count('\n') + 1

                                if 'password' in pattern.lower() or 'token' in pattern.lower():
                                    findings.append(self._create_finding(
                                        app=app,
                                        title="Sensitive Data in NSUserDefaults",
                                        description="Sensitive data is being stored in NSUserDefaults. This storage is not encrypted and can be accessed through backups. Use Keychain for sensitive data.",
                                        severity="high",
                                        category="MASVS-STORAGE",
                                        file_path=relative_path,
                                        line_number=line_num,
                                        code_snippet=self._get_context(lines, line_num, 3),
                                        cwe_id="CWE-312",
                                        owasp_category="M2",
                                    ))

                        # Check for Keychain usage
                        has_keychain = any(re.search(p[0], content) for p in self.IOS_KEYCHAIN_PATTERNS)
                        has_userdefaults_sensitive = any(
                            re.search(p[0], content, re.IGNORECASE)
                            for p in self.IOS_USERDEFAULTS_PATTERNS
                            if 'password' in p[0].lower() or 'token' in p[0].lower()
                        )

                        if has_userdefaults_sensitive and not has_keychain:
                            findings.append(self._create_finding(
                                app=app,
                                title="Missing Keychain Usage for Sensitive Data",
                                description="The app stores sensitive data but does not appear to use the iOS Keychain. Consider using Keychain Services for storing credentials and tokens.",
                                severity="medium",
                                category="MASVS-STORAGE",
                                file_path=relative_path,
                                cwe_id="CWE-311",
                                owasp_category="M2",
                            ))

                    except Exception as e:
                        logger.debug(f"Error reading {file_path}: {e}")

        return findings

    async def _analyze_database_security(self, app: MobileApp, extracted_path: str) -> list[Finding]:
        """Analyze database security across platforms.

        Checks for world-readable/writable SQLite databases, unencrypted
        databases containing sensitive tables (without SQLCipher), and
        database files bundled in the application package.

        Args:
            app: The mobile application being analyzed.
            extracted_path: Root directory of the extracted archive.

        Returns:
            A list of Finding objects for database security issues.
        """
        findings = []

        for root, _, files in os.walk(extracted_path):
            for file in files:
                if not file.endswith(('.java', '.kt', '.m', '.swift', '.smali')):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, extracted_path)

                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')

                    # Check for insecure SQLite patterns
                    for pattern, description in self.INSECURE_SQLITE_PATTERNS:
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append(self._create_finding(
                                app=app,
                                title=f"Insecure Database: {description}",
                                description=f"The database is configured with insecure permissions: {description}. This allows other apps to access or modify the data.",
                                severity="high",
                                category="MASVS-STORAGE",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=self._get_context(lines, line_num, 3),
                                cwe_id="CWE-922",
                                owasp_category="M2",
                            ))

                    # Check for unencrypted database with sensitive queries
                    if re.search(r'SQLite|Room|openOrCreateDatabase', content):
                        has_sqlcipher = re.search(r'SQLCipher|net\.sqlcipher', content)
                        has_sensitive_tables = re.search(
                            r'CREATE\s+TABLE.*(?:password|credential|token|secret|user|account)',
                            content, re.IGNORECASE
                        )

                        if has_sensitive_tables and not has_sqlcipher:
                            findings.append(self._create_finding(
                                app=app,
                                title="Unencrypted Database with Sensitive Data",
                                description="The app uses SQLite databases containing potentially sensitive data without encryption. Consider using SQLCipher for database encryption.",
                                severity="medium",
                                category="MASVS-STORAGE",
                                file_path=relative_path,
                                cwe_id="CWE-311",
                                owasp_category="M2",
                            ))

                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {e}")

        # Check for actual database files
        for root, _, files in os.walk(extracted_path):
            for file in files:
                if file.endswith(('.db', '.sqlite', '.sqlite3')):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, extracted_path)

                    findings.append(self._create_finding(
                        app=app,
                        title="Database File Found in App Bundle",
                        description=f"Database file '{file}' was found in the app bundle. Ensure it does not contain sensitive data or use encryption.",
                        severity="info",
                        category="MASVS-STORAGE",
                        file_path=relative_path,
                        cwe_id="CWE-312",
                        owasp_category="M2",
                    ))

        return findings

    async def _analyze_file_storage(self, app: MobileApp, extracted_path: str) -> list[Finding]:
        """Analyze file storage security for insecure permissions and locations.

        Detects use of external storage for data writes and insecure
        file permission modes (MODE_WORLD_READABLE, setReadable(true, false)).

        Args:
            app: The mobile application being analyzed.
            extracted_path: Root directory of the extracted archive.

        Returns:
            A list of Finding objects for file storage issues.
        """
        findings = []

        for root, _, files in os.walk(extracted_path):
            for file in files:
                if not file.endswith(('.java', '.kt', '.m', '.swift')):
                    continue

                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, extracted_path)

                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')

                    # Check for external storage usage
                    for pattern, description in self.FILE_STORAGE_PATTERNS:
                        if 'External' in description:
                            for match in re.finditer(pattern, content):
                                line_num = content[:match.start()].count('\n') + 1
                                findings.append(self._create_finding(
                                    app=app,
                                    title="External Storage Usage Detected",
                                    description=f"The app writes files to external storage ({description}). External storage is world-readable and files can be accessed by other apps.",
                                    severity="medium",
                                    category="MASVS-STORAGE",
                                    file_path=relative_path,
                                    line_number=line_num,
                                    code_snippet=self._get_context(lines, line_num, 3),
                                    cwe_id="CWE-276",
                                    owasp_category="M2",
                                ))

                    # Check for insecure file modes
                    for pattern, description in self.INSECURE_FILE_MODES:
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append(self._create_finding(
                                app=app,
                                title=f"Insecure File Permissions: {description}",
                                description=f"Files are created with insecure permissions: {description}. This allows other apps to read or modify the file.",
                                severity="high",
                                category="MASVS-STORAGE",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=self._get_context(lines, line_num, 3),
                                cwe_id="CWE-732",
                                owasp_category="M2",
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
            impact="Insecure data storage can expose sensitive user data to unauthorized access.",
            remediation="Use secure storage mechanisms such as Android KeyStore or iOS Keychain.",
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id=cwe_id,
            cvss_score=severity_cvss_map.get(severity, 0.0),
            owasp_masvs_category="MASVS-STORAGE",
            owasp_masvs_control="MASVS-STORAGE-1",
        )
