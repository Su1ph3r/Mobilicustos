"""Secret scanner for detecting hardcoded credentials."""

import logging
import re
import zipfile
from pathlib import Path
from typing import Any

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


class SecretScanner(BaseAnalyzer):
    """Scans for hardcoded secrets and credentials."""

    name = "secret_scanner"
    platform = "cross-platform"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Scan app for secrets."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            secrets = await self._scan_archive(Path(app.file_path), app.platform)

            for secret in secrets:
                finding = self._create_secret_finding(app, secret)
                findings.append(finding)

        except Exception as e:
            logger.error(f"Secret scanning failed: {e}")

        return findings

    async def _scan_archive(
        self,
        archive_path: Path,
        platform: str,
    ) -> list[dict[str, Any]]:
        """Scan archive for secrets."""
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
        """Scan content for secrets using patterns."""
        secrets: list[dict[str, Any]] = []

        for pattern_def in SECRET_PATTERNS:
            pattern = re.compile(pattern_def["pattern"])

            for match in pattern.finditer(content):
                # Get line number
                line_start = content[:match.start()].count("\n") + 1

                # Get context (surrounding lines)
                lines = content.split("\n")
                context_start = max(0, line_start - 2)
                context_end = min(len(lines), line_start + 2)
                context = "\n".join(lines[context_start:context_end])

                # Redact the secret
                secret_value = match.group(0)
                redacted = self._redact_secret(secret_value)

                secrets.append({
                    "name": pattern_def["name"],
                    "type": pattern_def["type"],
                    "provider": pattern_def["provider"],
                    "severity": pattern_def["severity"],
                    "file_path": file_path,
                    "line_number": line_start,
                    "context": context,
                    "value_redacted": redacted,
                    "value_hash": self._hash_secret(secret_value),
                })

        return secrets

    def _redact_secret(self, secret: str) -> str:
        """Redact a secret for safe display."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _hash_secret(self, secret: str) -> str:
        """Hash a secret for deduplication."""
        import hashlib
        return hashlib.sha256(secret.encode()).hexdigest()[:16]

    def _create_secret_finding(
        self,
        app: MobileApp,
        secret: dict[str, Any],
    ) -> Finding:
        """Create a finding from a detected secret."""
        provider_info = f" ({secret['provider']})" if secret["provider"] else ""

        return self.create_finding(
            app=app,
            title=f"Hardcoded {secret['name']}{provider_info}",
            severity=secret["severity"],
            category="Secrets",
            description=(
                f"A {secret['name']} was found hardcoded in the application. "
                f"The secret appears to be: {secret['value_redacted']}\n\n"
                f"File: {secret['file_path']}\n"
                f"Line: {secret['line_number']}"
            ),
            impact=(
                f"Hardcoded secrets can be extracted by anyone with access to the APK/IPA. "
                f"This {secret['type']} could be used to access backend services, "
                f"impersonate the application, or compromise user data."
            ),
            remediation=(
                "Remove the hardcoded secret immediately. Use one of these approaches:\n"
                "1. Store secrets server-side and fetch at runtime\n"
                "2. Use Android Keystore / iOS Keychain for local secrets\n"
                "3. Use environment-based configuration for build-time secrets\n"
                "4. Consider using a secrets management service"
            ),
            file_path=secret["file_path"],
            line_number=secret["line_number"],
            code_snippet=secret["context"],
            poc_evidence=f"Found {secret['name']}: {secret['value_redacted']}",
            poc_verification=(
                "1. Decompile the APK/IPA\n"
                f"2. Search for the pattern in {secret['file_path']}\n"
                "3. Extract and test the credential"
            ),
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            owasp_masvs_category="MASVS-STORAGE",
            owasp_masvs_control="MASVS-STORAGE-1",
            owasp_mastg_test="MASTG-TEST-0001",
        )
