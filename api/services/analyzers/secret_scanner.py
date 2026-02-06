"""Secret scanner for detecting hardcoded credentials in mobile applications.

Scans application archives (APK/IPA) for hardcoded secrets, API keys, tokens,
private keys, and database connection strings using regular expression pattern
matching. Supports provider-specific detection for:

    - **Cloud providers**: AWS (access keys, secret keys), Google (API keys,
      OAuth client IDs), Firebase (URLs, server keys)
    - **Payment**: Stripe (secret keys, publishable keys)
    - **Communication**: Twilio (API keys), Slack (tokens, webhooks)
    - **Source control**: GitHub (personal tokens, OAuth tokens)
    - **Cryptographic**: RSA, EC, and SSH private keys
    - **Database**: PostgreSQL and MongoDB connection strings
    - **Generic**: Bearer tokens, Basic auth headers, hardcoded passwords,
      generic API keys

Each detected secret is redacted for safe display, hashed for deduplication,
and enriched with provider-specific remediation commands and resources.

OWASP references:
    - MASVS-STORAGE-1: Secure storage of sensitive data
    - MASTG-TEST-0001: Testing for sensitive data in local storage
    - CWE-798: Use of hard-coded credentials
"""

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

import httpx

from api.models.database import Finding, MobileApp, Secret
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


# Secret patterns with provider detection
SECRET_PATTERNS: list[dict[str, Any]] = [
    # AWS
    {
        "name": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "provider": "aws",
        "type": "api_key",
        "severity": "critical",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "provider": "aws",
        "type": "api_key",
        "severity": "critical",
    },
    # Google
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "provider": "google",
        "type": "api_key",
        "severity": "high",
    },
    {
        "name": "Google OAuth Client ID",
        "pattern": r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com",
        "provider": "google",
        "type": "oauth_secret",
        "severity": "medium",
    },
    # Firebase
    {
        "name": "Firebase URL",
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "provider": "firebase",
        "type": "api_key",
        "severity": "medium",
    },
    {
        "name": "Firebase Server Key",
        "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "provider": "firebase",
        "type": "api_key",
        "severity": "critical",
    },
    # Stripe
    {
        "name": "Stripe Secret Key",
        "pattern": r"sk_live_[0-9a-zA-Z]{24}",
        "provider": "stripe",
        "type": "api_key",
        "severity": "critical",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": r"pk_live_[0-9a-zA-Z]{24}",
        "provider": "stripe",
        "type": "api_key",
        "severity": "low",
    },
    # Twilio
    {
        "name": "Twilio API Key",
        "pattern": r"SK[0-9a-fA-F]{32}",
        "provider": "twilio",
        "type": "api_key",
        "severity": "high",
    },
    # GitHub
    {
        "name": "GitHub Token",
        "pattern": r"ghp_[0-9a-zA-Z]{36}",
        "provider": "github",
        "type": "token",
        "severity": "high",
    },
    {
        "name": "GitHub OAuth",
        "pattern": r"gho_[0-9a-zA-Z]{36}",
        "provider": "github",
        "type": "oauth_secret",
        "severity": "high",
    },
    # Slack
    {
        "name": "Slack Token",
        "pattern": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
        "provider": "slack",
        "type": "token",
        "severity": "high",
    },
    {
        "name": "Slack Webhook",
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+",
        "provider": "slack",
        "type": "api_key",
        "severity": "medium",
    },
    # Private Keys
    {
        "name": "RSA Private Key",
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "provider": "rsa",
        "type": "private_key",
        "severity": "critical",
    },
    {
        "name": "EC Private Key",
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "provider": "ec",
        "type": "private_key",
        "severity": "critical",
    },
    {
        "name": "SSH Private Key",
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "provider": "ssh",
        "type": "private_key",
        "severity": "critical",
    },
    # Database
    {
        "name": "PostgreSQL Connection String",
        "pattern": r"postgres://[^:]+:[^@]+@[^/]+/\w+",
        "provider": "postgres",
        "type": "database_url",
        "severity": "critical",
    },
    {
        "name": "MongoDB Connection String",
        "pattern": r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+",
        "provider": "mongodb",
        "type": "database_url",
        "severity": "critical",
    },
    # Generic
    {
        "name": "Bearer Token",
        "pattern": r"(?i)bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "provider": None,
        "type": "token",
        "severity": "high",
    },
    {
        "name": "Basic Auth",
        "pattern": r"(?i)basic\s+[a-zA-Z0-9+/=]{20,}",
        "provider": None,
        "type": "password",
        "severity": "high",
    },
    {
        "name": "Hardcoded Password",
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "provider": None,
        "type": "password",
        "severity": "high",
    },
    {
        "name": "API Key Generic",
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
        "provider": None,
        "type": "api_key",
        "severity": "medium",
    },
]


# Provider-prefixed patterns that are high-confidence (skip entropy check)
_HIGH_CONFIDENCE_PREFIXES = {"AKIA", "AIza", "ghp_", "gho_", "sk_live_", "pk_live_", "xox", "AAAA", "-----BEGIN"}

# False positive indicator strings — if the matched value contains any of these, skip it
_FALSE_POSITIVE_INDICATORS = [
    "example", "placeholder", "your_", "insert_", "replace_", "todo",
    "changeme", "password123", "test", "dummy", "sample", "xxxxxx",
    "000000", "111111", "aaaaaa",
]

# Files that commonly contain SDK config (not real secrets)
_SKIP_FILE_PATTERNS = [
    "google-services.json",
    "build.gradle",
    "Podfile.lock",
    "package-lock.json",
    "yarn.lock",
    "gradle-wrapper.properties",
]


class SecretScanner(BaseAnalyzer):
    """Scans mobile application archives for hardcoded secrets and credentials.

    Extracts text-based files from APK/IPA archives and applies regex-based
    pattern matching from ``SECRET_PATTERNS`` to detect hardcoded secrets.
    Detected secrets are redacted, hashed for deduplication, and enriched
    with provider-specific PoC commands and remediation guidance.

    Supports scanning of source code (.java, .kt, .swift, .dart, .js, .ts),
    configuration files (.xml, .json, .yaml, .properties, .plist), and
    documentation (.txt, .md). Files larger than 10 MB are skipped.

    Attributes:
        name: Analyzer identifier (``"secret_scanner"``).
        platform: Target platform (``"cross-platform"`` -- works on both
            Android and iOS).
    """

    name = "secret_scanner"
    platform = "cross-platform"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Scan the application archive for hardcoded secrets.

        Args:
            app: MobileApp ORM model with ``file_path`` pointing to the
                APK or IPA archive.

        Returns:
            List of Finding objects, one per detected secret. Returns an
            empty list if the file path is missing or scanning fails.
        """
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            secrets = await self._scan_archive(Path(app.file_path), app.platform)

            for secret in secrets:
                finding = self._create_secret_finding(app, secret)
                findings.append(finding)

            # Live validation of extracted secrets (safe, read-only probes)
            live_findings = await self._live_validate_secrets(app, secrets)
            findings.extend(live_findings)

        except Exception as e:
            logger.error(f"Secret scanning failed: {e}")

        return findings

    async def _scan_archive(
        self,
        archive_path: Path,
        platform: str,
    ) -> list[dict[str, Any]]:
        """Scan all text files within an archive for secret patterns.

        Iterates over files in the ZIP archive, skipping large files
        (> 10 MB) and non-text extensions. Each eligible file's content
        is decoded and scanned against ``SECRET_PATTERNS``.

        Args:
            archive_path: Filesystem path to the APK or IPA archive.
            platform: Target platform (``"android"`` or ``"ios"``).

        Returns:
            List of secret dicts, each with keys: ``name``, ``type``,
            ``provider``, ``severity``, ``file_path``, ``line_number``,
            ``context``, ``value_redacted``, ``value_hash``.
        """
        secrets: list[dict[str, Any]] = []

        # File extensions to scan
        scannable_extensions = {
            ".java", ".kt", ".xml", ".json", ".properties",
            ".plist", ".swift", ".m", ".h",
            ".js", ".ts", ".dart",
            ".txt", ".md", ".yaml", ".yml",
        }

        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                for file_info in archive.filelist:
                    # Skip large files
                    if file_info.file_size > 10 * 1024 * 1024:  # 10MB
                        continue

                    # Check extension
                    ext = Path(file_info.filename).suffix.lower()
                    if ext not in scannable_extensions:
                        continue

                    # Skip known SDK/library config files
                    basename = Path(file_info.filename).name
                    if basename in _SKIP_FILE_PATTERNS:
                        continue

                    try:
                        content = archive.read(file_info.filename).decode(
                            "utf-8", errors="ignore"
                        )
                        file_secrets = await self._scan_content(
                            content, file_info.filename
                        )
                        secrets.extend(file_secrets)
                    except Exception as e:
                        logger.debug(f"Could not scan {file_info.filename}: {e}")

        except Exception as e:
            logger.error(f"Failed to scan archive: {e}")

        return secrets

    async def _scan_content(
        self,
        content: str,
        file_path: str,
    ) -> list[dict[str, Any]]:
        """Scan a single file's content against all secret patterns.

        For each match, determines the line number, extracts surrounding
        context lines, and creates a redacted/hashed representation of
        the secret value. Applies entropy filtering and false positive
        detection to reduce noise.

        Args:
            content: Decoded text content of the file.
            file_path: Relative path of the file within the archive (used
                for reporting).

        Returns:
            List of secret dicts for each pattern match found.
        """
        secrets: list[dict[str, Any]] = []

        for pattern_def in SECRET_PATTERNS:
            pattern = re.compile(pattern_def["pattern"])

            for match in pattern.finditer(content):
                # Use the innermost capture group (the actual secret value)
                secret_value = match.group(match.lastindex) if match.lastindex else match.group(0)

                # Determine if this is a high-confidence provider-prefixed match
                is_high_confidence = any(
                    secret_value.startswith(prefix) for prefix in _HIGH_CONFIDENCE_PREFIXES
                )

                # False positive check — only apply to non-provider-prefixed matches
                if not is_high_confidence:
                    value_lower = secret_value.lower()
                    if any(fp in value_lower for fp in _FALSE_POSITIVE_INDICATORS):
                        continue

                    # Entropy check for generic patterns
                    entropy = self._calculate_entropy(secret_value)
                    if entropy < 3.0:
                        continue

                # Get line number
                line_start = content[:match.start()].count("\n") + 1

                # Get context (surrounding lines)
                lines = content.split("\n")
                context_start = max(0, line_start - 2)
                context_end = min(len(lines), line_start + 2)
                context = "\n".join(lines[context_start:context_end])

                # Redact the full match for display
                redacted = self._redact_secret(match.group(0))

                # Confidence and severity: high-confidence keeps original,
                # medium-confidence downgrades by one level
                confidence = "high" if is_high_confidence else "medium"
                severity = pattern_def["severity"]
                if not is_high_confidence:
                    _DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "info"}
                    severity = _DOWNGRADE.get(severity, severity)

                secrets.append({
                    "name": pattern_def["name"],
                    "type": pattern_def["type"],
                    "provider": pattern_def["provider"],
                    "severity": severity,
                    "confidence": confidence,
                    "file_path": file_path,
                    "line_number": line_start,
                    "context": context,
                    "value_redacted": redacted,
                    "value_hash": self._hash_secret(secret_value),
                })

        return secrets

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            data: Input string to measure.

        Returns:
            Entropy in bits. Low-entropy (< 3.0) values are likely
            placeholders or repetitive strings.
        """
        from collections import Counter
        import math

        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def _redact_secret(self, secret: str) -> str:
        """Redact a secret value for safe display in findings.

        Preserves the first 4 and last 4 characters, replacing the middle
        with asterisks. Secrets 8 characters or shorter are fully masked.

        Args:
            secret: Raw secret string to redact.

        Returns:
            Redacted string safe for storage and display.
        """
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _hash_secret(self, secret: str) -> str:
        """Hash a secret value for deduplication across scans.

        Args:
            secret: Raw secret string to hash.

        Returns:
            First 16 characters of the SHA-256 hex digest.
        """
        import hashlib
        return hashlib.sha256(secret.encode()).hexdigest()[:16]

    def _create_secret_finding(
        self,
        app: MobileApp,
        secret: dict[str, Any],
    ) -> Finding:
        """Create a Finding from a detected secret with provider-specific guidance.

        Generates PoC commands for secret validation, provider-specific
        remediation resources (e.g., AWS Secrets Manager, Android Keystore),
        and code examples for secure alternatives.

        Args:
            app: MobileApp ORM model for the scanned application.
            secret: Secret dict from ``_scan_content()`` with keys: ``name``,
                ``type``, ``provider``, ``severity``, ``file_path``,
                ``line_number``, ``context``, ``value_redacted``, ``value_hash``.

        Returns:
            Finding ORM model ready for database insertion.
        """
        provider_info = f" ({secret['provider']})" if secret["provider"] else ""
        provider = secret.get("provider", "unknown")

        # Build verification commands based on provider
        poc_cmds = [
            {
                "type": "bash",
                "command": f"jadx -d decompiled {app.file_path}" if app.platform == "android" else f"otool -l {app.file_path}",
                "description": "Decompile the application binary",
            },
            {
                "type": "bash",
                "command": f"grep -rn '{secret['value_redacted'][:8]}' decompiled/",
                "description": "Search for the secret in decompiled source",
            },
        ]

        # Add provider-specific validation commands
        if provider == "aws":
            poc_cmds.append({
                "type": "bash",
                "command": "aws sts get-caller-identity",
                "description": "Test if AWS credentials are valid (requires credentials export)",
            })
        elif provider == "google":
            poc_cmds.append({
                "type": "bash",
                "command": f"curl 'https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key=<EXTRACTED_KEY>'",
                "description": "Test if Google API key is valid",
            })
        elif provider == "stripe":
            poc_cmds.append({
                "type": "bash",
                "command": "curl https://api.stripe.com/v1/customers -u '<EXTRACTED_KEY>:'",
                "description": "Test if Stripe key is valid",
            })
        elif provider == "firebase":
            poc_cmds.append({
                "type": "bash",
                "command": "curl '<EXTRACTED_URL>/.json'",
                "description": "Test if Firebase database is accessible",
            })

        # Build remediation resources based on provider
        remediation_resources = [
            {
                "title": "OWASP MASTG - Testing for Sensitive Data in Local Storage",
                "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/",
                "type": "documentation",
            },
        ]

        if provider == "aws":
            remediation_resources.extend([
                {
                    "title": "AWS Secrets Manager",
                    "url": "https://aws.amazon.com/secrets-manager/",
                    "type": "documentation",
                },
                {
                    "title": "AWS Mobile SDK - Cognito for Authentication",
                    "url": "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                    "type": "documentation",
                },
            ])
        elif provider == "google":
            remediation_resources.append({
                "title": "Google Cloud - API Key Best Practices",
                "url": "https://cloud.google.com/docs/authentication/api-keys",
                "type": "documentation",
            })
        elif provider == "firebase":
            remediation_resources.append({
                "title": "Firebase Security Rules",
                "url": "https://firebase.google.com/docs/rules",
                "type": "documentation",
            })

        # Add platform-specific storage resources
        if app.platform == "android":
            remediation_resources.append({
                "title": "Android Keystore System",
                "url": "https://developer.android.com/training/articles/keystore",
                "type": "documentation",
            })
        else:
            remediation_resources.append({
                "title": "iOS Keychain Services",
                "url": "https://developer.apple.com/documentation/security/keychain_services",
                "type": "documentation",
            })

        # Build remediation commands
        remediation_cmds = []
        if app.platform == "android":
            remediation_cmds = [
                {
                    "type": "android",
                    "command": "KeyStore keyStore = KeyStore.getInstance(\"AndroidKeyStore\");",
                    "description": "Use Android KeyStore for secure key storage",
                },
                {
                    "type": "bash",
                    "command": "# Add to local.properties (gitignored)\nAPI_KEY=your_key_here",
                    "description": "Store keys in local.properties for build-time injection",
                },
            ]
        else:
            remediation_cmds = [
                {
                    "type": "ios",
                    "command": "let query: [String: Any] = [kSecClass: kSecClassGenericPassword, ...]",
                    "description": "Use iOS Keychain for secure storage",
                },
            ]

        return self.create_finding(
            app=app,
            title=f"Hardcoded {secret['name']}{provider_info}",
            severity=secret["severity"],
            category="Secrets",
            description=(
                f"A {secret['name']} was found hardcoded in the application. "
                f"The secret appears to be: {secret['value_redacted']}\n\n"
                f"**File:** `{secret['file_path']}`\n"
                f"**Line:** {secret['line_number']}\n"
                f"**Type:** {secret['type']}"
            ),
            impact=(
                f"Hardcoded secrets can be extracted by anyone with access to the APK/IPA. "
                f"This {secret['type']} could be used to access backend services, "
                f"impersonate the application, or compromise user data. "
                f"If the secret grants access to cloud services, attackers could incur "
                f"significant costs or access sensitive data."
            ),
            remediation=(
                "Remove the hardcoded secret immediately. Use one of these approaches:\n\n"
                "1. **Server-side storage**: Fetch secrets from your backend at runtime\n"
                "2. **Secure storage**: Use Android Keystore / iOS Keychain\n"
                "3. **Build-time injection**: Use environment variables or CI/CD secrets\n"
                "4. **Secrets management**: Use AWS Secrets Manager, HashiCorp Vault, etc.\n\n"
                "**Important**: Rotate compromised credentials immediately!"
            ),
            file_path=secret["file_path"],
            line_number=secret["line_number"],
            code_snippet=secret["context"],
            poc_evidence=f"Found {secret['name']}: {secret['value_redacted']}\nHash: {secret['value_hash']}",
            poc_verification=f"grep -rn '{secret['value_redacted'][:8]}' <decompiled_path>/",
            poc_commands=poc_cmds,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            cvss_score=9.1 if secret["severity"] == "critical" else 7.5 if secret["severity"] == "high" else 5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if secret["severity"] == "critical" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            owasp_masvs_category="MASVS-STORAGE",
            owasp_masvs_control="MASVS-STORAGE-1",
            owasp_mastg_test="MASTG-TEST-0001",
            remediation_commands=remediation_cmds,
            remediation_code={
                "kotlin": '''// Use EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val sharedPreferences = EncryptedSharedPreferences.create(
    context,
    "secret_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)''',
                "swift": '''// Use iOS Keychain
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "apiKey",
    kSecValueData as String: keyData,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)''',
            },
            remediation_resources=remediation_resources,
        )

    async def _live_validate_secrets(
        self, app: MobileApp, secrets: list[dict[str, Any]],
    ) -> list[Finding]:
        """Perform safe, read-only live validation of extracted secrets.

        Tests discovered cloud identifiers against public APIs to determine
        if they grant unauthenticated access. Only performs GET requests —
        never writes or modifies data.

        Current checks:
            - S3 bucket public listing (extracted from URL patterns)
            - Google API key scope validation (Maps API probe)

        Args:
            app: MobileApp ORM model for the scanned application.
            secrets: List of secret dicts from ``_scan_content()``.

        Returns:
            List of Finding objects for confirmed misconfigurations.
        """
        findings: list[Finding] = []

        # Collect testable identifiers from secrets
        s3_buckets: set[str] = set()
        google_api_keys: set[str] = set()

        for secret in secrets:
            context = secret.get("context", "")

            # Extract S3 bucket names from context
            for bucket_match in re.finditer(
                r'(?:https?://)?([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.\-](?:amazonaws\.com|[a-z0-9-]+\.amazonaws\.com)',
                context,
            ):
                s3_buckets.add(bucket_match.group(1))

            # Also match path-style S3 URLs
            for bucket_match in re.finditer(
                r's3\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])',
                context,
            ):
                s3_buckets.add(bucket_match.group(1))

            # Extract Google API keys from context (AIza pattern)
            if secret.get("provider") == "google" and secret.get("name") == "Google API Key":
                for key_match in re.finditer(r'AIza[0-9A-Za-z_-]{35}', context):
                    google_api_keys.add(key_match.group(0))

        if not s3_buckets and not google_api_keys:
            return findings

        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            # 1. S3 bucket public listing test
            for bucket in s3_buckets:
                try:
                    url = f"https://{bucket}.s3.amazonaws.com/"
                    resp = await client.get(url)
                    if resp.status_code == 200 and "ListBucketResult" in resp.text:
                        findings.append(self.create_finding(
                            app=app,
                            title=f"S3 bucket publicly listable: {bucket}",
                            severity="critical",
                            category="Cloud Misconfiguration",
                            description=(
                                f"S3 bucket '{bucket}' allows unauthenticated listing. "
                                f"Response returned ListBucketResult with {resp.text.count('<Key>')} keys."
                            ),
                            impact=(
                                "Anyone can list and potentially download all objects in this S3 bucket. "
                                "This may expose sensitive data, backups, or application assets."
                            ),
                            remediation=(
                                "1. Enable S3 Block Public Access on the bucket\n"
                                "2. Review and restrict bucket policy and ACLs\n"
                                "3. Audit what data was publicly exposed\n"
                                "4. Enable S3 access logging"
                            ),
                            poc_evidence=f"curl '{url}' returned ListBucketResult",
                            poc_commands=[
                                {"type": "bash", "command": f"curl '{url}'", "description": "List S3 bucket contents"},
                                {"type": "bash", "command": f"aws s3 ls s3://{bucket}/ --no-sign-request", "description": "List with AWS CLI"},
                            ],
                            cwe_id="CWE-284",
                            cwe_name="Improper Access Control",
                            owasp_masvs_category="MASVS-STORAGE",
                            remediation_resources=[
                                {"title": "AWS S3 Block Public Access", "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", "type": "documentation"},
                            ],
                        ))
                except Exception as e:
                    logger.debug(f"S3 bucket check failed for {bucket}: {e}")

            # 2. Google API key scope test
            for api_key in google_api_keys:
                try:
                    url = f"https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key={api_key}"
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        redacted_key = api_key[:8] + "*" * (len(api_key) - 12) + api_key[-4:]
                        findings.append(self.create_finding(
                            app=app,
                            title=f"Google API key unrestricted: {redacted_key}",
                            severity="high",
                            category="Cloud Misconfiguration",
                            description=(
                                f"Google API key ({redacted_key}) works without referrer or IP restrictions. "
                                f"The key was tested against the Maps Static API and returned a valid response."
                            ),
                            impact=(
                                "An unrestricted Google API key can be used by anyone to make API calls "
                                "billed to the key owner. Attackers could abuse Maps, Places, Geocoding, "
                                "or other enabled APIs to generate significant charges."
                            ),
                            remediation=(
                                "1. Restrict the API key by application (Android/iOS package) or HTTP referrer\n"
                                "2. Limit the key to only the APIs your app needs\n"
                                "3. Set a quota/budget alert on the Google Cloud project\n"
                                "4. Consider rotating the key"
                            ),
                            poc_evidence=f"GET Maps Static API with key returned HTTP 200",
                            poc_commands=[
                                {"type": "bash", "command": f"curl -o /dev/null -w '%{{http_code}}' 'https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key={redacted_key}'", "description": "Test Google Maps API key (use actual key)"},
                            ],
                            cwe_id="CWE-284",
                            cwe_name="Improper Access Control",
                            owasp_masvs_category="MASVS-STORAGE",
                            remediation_resources=[
                                {"title": "Google API Key Restrictions", "url": "https://cloud.google.com/docs/authentication/api-keys#securing_an_api_key", "type": "documentation"},
                            ],
                        ))
                except Exception as e:
                    logger.debug(f"Google API key check failed: {e}")

        return findings
