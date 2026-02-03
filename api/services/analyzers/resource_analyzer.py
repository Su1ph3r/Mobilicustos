"""Resource analyzer for Android APK res/ and assets/ directories."""

import json
import logging
import re
import zipfile
from pathlib import Path

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


# Sensitive file patterns
SENSITIVE_PATTERNS = {
    "private_key": {
        "patterns": [
            r"\.pem$", r"\.key$", r"\.p12$", r"\.pfx$", r"\.jks$", r"\.keystore$",
            r"\.pk8$", r"\.der$",
        ],
        "severity": "critical",
        "description": "Private key file found in assets",
    },
    "certificate": {
        "patterns": [r"\.cer$", r"\.crt$", r"\.cert$"],
        "severity": "medium",
        "description": "Certificate file found in assets",
    },
    "database": {
        "patterns": [r"\.db$", r"\.sqlite$", r"\.sqlite3$", r"\.realm$"],
        "severity": "medium",
        "description": "Database file found in assets",
    },
    "backup": {
        "patterns": [r"\.bak$", r"\.backup$", r"\.old$", r"\.save$"],
        "severity": "low",
        "description": "Backup file found in assets",
    },
    "config": {
        "patterns": [
            r"\.ini$", r"\.conf$", r"\.cfg$", r"\.properties$",
            r"google-services\.json$", r"firebase.*\.json$",
        ],
        "severity": "medium",
        "description": "Configuration file found in assets",
    },
}

# Content patterns for sensitive data
CONTENT_PATTERNS = {
    "api_key": {
        "patterns": [
            r"(?i)api[_\-]?key[\"\'\s:=]+[\"\']?([a-zA-Z0-9\-_]{20,})[\"\']?",
            r"(?i)apikey[\"\'\s:=]+[\"\']?([a-zA-Z0-9\-_]{20,})[\"\']?",
        ],
        "severity": "high",
        "category": "Hardcoded Secret",
    },
    "aws_key": {
        "patterns": [
            r"AKIA[0-9A-Z]{16}",
            r"(?i)aws[_\-]?access[_\-]?key[_\-]?id[\"\'\s:=]+[\"\']?([A-Z0-9]{20})[\"\']?",
        ],
        "severity": "critical",
        "category": "Cloud Credentials",
    },
    "google_api": {
        "patterns": [
            r"AIza[0-9A-Za-z\-_]{35}",
            r"(?i)google[_\-]?api[_\-]?key[\"\'\s:=]+[\"\']?([A-Za-z0-9\-_]{39})[\"\']?",
        ],
        "severity": "high",
        "category": "Cloud Credentials",
    },
    "firebase": {
        "patterns": [
            r"(?i)firebase[_\-]?api[_\-]?key[\"\'\s:=]+[\"\']?([A-Za-z0-9\-_]{20,})[\"\']?",
        ],
        "severity": "high",
        "category": "Cloud Credentials",
    },
    "private_key_content": {
        "patterns": [
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ],
        "severity": "critical",
        "category": "Cryptographic Key",
    },
    "password": {
        "patterns": [
            r"(?i)password[\"\'\s:=]+[\"\']([^\"\'\s]{4,})[\"\']",
            r"(?i)passwd[\"\'\s:=]+[\"\']([^\"\'\s]{4,})[\"\']",
        ],
        "severity": "high",
        "category": "Hardcoded Secret",
    },
    "jwt_secret": {
        "patterns": [
            r"(?i)jwt[_\-]?secret[\"\'\s:=]+[\"\']?([A-Za-z0-9\-_+/=]{16,})[\"\']?",
        ],
        "severity": "high",
        "category": "Hardcoded Secret",
    },
    "connection_string": {
        "patterns": [
            r"(?i)(?:jdbc|mongodb|mysql|postgres|redis|amqp)://[^\s\"\'\n]+",
        ],
        "severity": "high",
        "category": "Connection String",
    },
    "internal_url": {
        "patterns": [
            r"https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^\s\"\'\n]*)?",
        ],
        "severity": "medium",
        "category": "Internal URL",
    },
}


class ResourceAnalyzer(BaseAnalyzer):
    """Analyzes APK resources and assets for security issues."""

    name = "resource_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze resources and assets in the APK."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            apk_path = Path(app.file_path)

            # Scan for sensitive files
            findings.extend(await self._scan_sensitive_files(app, apk_path))

            # Scan file contents
            findings.extend(await self._scan_file_contents(app, apk_path))

            # Check for hardcoded resources
            findings.extend(await self._check_strings_xml(app, apk_path))

            # Check raw resources
            findings.extend(await self._check_raw_resources(app, apk_path))

        except Exception as e:
            logger.error(f"Resource analysis failed: {e}")

        return findings

    async def _scan_sensitive_files(
        self, app: MobileApp, apk_path: Path
    ) -> list[Finding]:
        """Scan for sensitive file types in assets/res."""
        findings = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                for name in apk.namelist():
                    # Only scan assets/ and res/ directories
                    if not (name.startswith("assets/") or name.startswith("res/")):
                        continue

                    for file_type, config in SENSITIVE_PATTERNS.items():
                        for pattern in config["patterns"]:
                            if re.search(pattern, name, re.IGNORECASE):
                                findings.append(self.create_finding(
                                    app=app,
                                    title=f"Sensitive {file_type.replace('_', ' ').title()} in APK",
                                    severity=config["severity"],
                                    category="Sensitive Data Exposure",
                                    description=(
                                        f"{config['description']}: {name}. "
                                        "Sensitive files should not be bundled with the application "
                                        "as they can be easily extracted from the APK."
                                    ),
                                    impact=(
                                        "An attacker can extract the APK and access these files. "
                                        "Private keys can be used to impersonate the application, "
                                        "decrypt data, or access backend services. Databases may "
                                        "contain sensitive user data or credentials."
                                    ),
                                    remediation=(
                                        "Remove sensitive files from the APK. Store secrets securely:\n"
                                        "1. Use Android Keystore for cryptographic keys\n"
                                        "2. Use encrypted SharedPreferences for sensitive data\n"
                                        "3. Fetch secrets from a secure backend at runtime\n"
                                        "4. Use environment-specific configuration"
                                    ),
                                    file_path=name,
                                    code_snippet=f"# Found in APK:\n{name}",
                                    poc_evidence=(
                                        f"Sensitive file '{name}' found in APK. "
                                        f"File type: {file_type}"
                                    ),
                                    poc_verification=(
                                        f"1. Extract APK: unzip app.apk -d extracted/\n"
                                        f"2. Check file: ls -la extracted/{name}\n"
                                        f"3. Examine contents: cat extracted/{name}"
                                    ),
                                    poc_commands=[
                                        f"unzip -o {app.file_path} -d /tmp/extracted",
                                        f"ls -la /tmp/extracted/{name}",
                                        f"file /tmp/extracted/{name}",
                                    ],
                                    cwe_id="CWE-312",
                                    cwe_name="Cleartext Storage of Sensitive Information",
                                    owasp_masvs_category="MASVS-STORAGE",
                                    owasp_masvs_control="MSTG-STORAGE-1",
                                    cvss_score=7.5 if config["severity"] == "critical" else 5.3,
                                ))
                                break

        except Exception as e:
            logger.error(f"Failed to scan sensitive files: {e}")

        return findings

    async def _scan_file_contents(
        self, app: MobileApp, apk_path: Path
    ) -> list[Finding]:
        """Scan file contents for hardcoded secrets."""
        findings = []
        seen_secrets = set()  # Deduplicate findings

        # File extensions to scan
        scannable_extensions = {
            ".json", ".xml", ".properties", ".txt", ".html", ".js", ".css",
            ".yml", ".yaml", ".conf", ".cfg", ".ini",
        }

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                for name in apk.namelist():
                    # Only scan assets/ and res/raw/
                    if not (name.startswith("assets/") or name.startswith("res/raw/")):
                        continue

                    # Check file extension
                    ext = Path(name).suffix.lower()
                    if ext not in scannable_extensions:
                        continue

                    try:
                        content = apk.read(name).decode("utf-8", errors="ignore")
                    except Exception:
                        continue

                    # Skip very large files
                    if len(content) > 1_000_000:
                        continue

                    for secret_type, config in CONTENT_PATTERNS.items():
                        for pattern in config["patterns"]:
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                # Create dedup key
                                secret_key = f"{name}:{secret_type}:{match.group(0)[:50]}"
                                if secret_key in seen_secrets:
                                    continue
                                seen_secrets.add(secret_key)

                                # Get context around match
                                start = max(0, match.start() - 50)
                                end = min(len(content), match.end() + 50)
                                context = content[start:end]

                                # Get line number
                                line_num = content[:match.start()].count("\n") + 1

                                findings.append(self.create_finding(
                                    app=app,
                                    title=f"Hardcoded {config['category']} in Resource",
                                    severity=config["severity"],
                                    category=config["category"],
                                    description=(
                                        f"A potential {secret_type.replace('_', ' ')} was found "
                                        f"hardcoded in {name}. Hardcoded secrets in application "
                                        "resources can be extracted by anyone with access to the APK."
                                    ),
                                    impact=(
                                        "Hardcoded secrets allow attackers to:\n"
                                        "- Access backend services without authorization\n"
                                        "- Impersonate the application\n"
                                        "- Access cloud resources (AWS, GCP, Firebase)\n"
                                        "- Decrypt sensitive data"
                                    ),
                                    remediation=(
                                        "Remove hardcoded secrets and implement secure storage:\n"
                                        "1. Use Android Keystore for cryptographic keys\n"
                                        "2. Fetch API keys from a secure backend\n"
                                        "3. Use build-time environment variables\n"
                                        "4. Implement proper OAuth flows for third-party services"
                                    ),
                                    file_path=name,
                                    line_number=line_num,
                                    code_snippet=f"// Context from {name}:{line_num}\n{context}",
                                    poc_evidence=(
                                        f"Found {secret_type.replace('_', ' ')} in {name} at line {line_num}: "
                                        f"'{match.group(0)[:100]}...'"
                                    ),
                                    poc_verification=(
                                        f"1. Extract APK: unzip app.apk -d extracted/\n"
                                        f"2. Search file: grep -n '{pattern[:30]}' extracted/{name}\n"
                                        f"3. Verify at line {line_num}"
                                    ),
                                    poc_commands=[
                                        f"unzip -o {app.file_path} -d /tmp/extracted",
                                        f"cat /tmp/extracted/{name}",
                                        f"grep -n -E '{pattern[:50]}' /tmp/extracted/{name}",
                                    ],
                                    cwe_id="CWE-798",
                                    cwe_name="Use of Hard-coded Credentials",
                                    owasp_masvs_category="MASVS-STORAGE",
                                    owasp_masvs_control="MSTG-STORAGE-14",
                                    cvss_score=7.5 if config["severity"] == "critical" else 6.5,
                                ))

        except Exception as e:
            logger.error(f"Failed to scan file contents: {e}")

        return findings

    async def _check_strings_xml(
        self, app: MobileApp, apk_path: Path
    ) -> list[Finding]:
        """Check strings.xml for potential secrets."""
        findings = []

        sensitive_string_patterns = [
            (r"(?i)api[_\-]?key", "API Key"),
            (r"(?i)secret[_\-]?key", "Secret Key"),
            (r"(?i)password", "Password"),
            (r"(?i)auth[_\-]?token", "Auth Token"),
            (r"(?i)access[_\-]?token", "Access Token"),
            (r"(?i)private[_\-]?key", "Private Key"),
            (r"(?i)aws[_\-]?key", "AWS Key"),
            (r"(?i)firebase[_\-]?key", "Firebase Key"),
        ]

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                for name in apk.namelist():
                    if not name.startswith("res/values") or not name.endswith("strings.xml"):
                        continue

                    try:
                        # androguard for proper AXML parsing
                        from androguard.core.axml import AXMLPrinter
                        content = AXMLPrinter(apk.read(name)).get_xml()
                    except ImportError:
                        content = apk.read(name).decode("utf-8", errors="ignore")

                    # Parse strings
                    string_pattern = r'<string\s+name="([^"]+)"[^>]*>([^<]*)</string>'
                    for match in re.finditer(string_pattern, content, re.DOTALL):
                        string_name = match.group(1)
                        string_value = match.group(2).strip()

                        # Skip empty or short values
                        if len(string_value) < 10:
                            continue

                        for pattern, secret_type in sensitive_string_patterns:
                            if re.search(pattern, string_name):
                                # Check if value looks like a real secret
                                if self._looks_like_secret(string_value):
                                    findings.append(self.create_finding(
                                        app=app,
                                        title=f"Potential {secret_type} in strings.xml",
                                        severity="high",
                                        category="Hardcoded Secret",
                                        description=(
                                            f"String resource '{string_name}' appears to contain "
                                            f"a hardcoded {secret_type.lower()}. This value can be easily "
                                            "extracted from the APK."
                                        ),
                                        impact=(
                                            "Secrets in strings.xml are easily extractable and can be "
                                            "used to access backend services or impersonate the app."
                                        ),
                                        remediation=(
                                            "Remove secrets from strings.xml:\n"
                                            "1. Use BuildConfig fields for build-time secrets\n"
                                            "2. Fetch secrets from a secure backend\n"
                                            "3. Use the Android Keystore system"
                                        ),
                                        file_path=name,
                                        code_snippet=(
                                            f'<string name="{string_name}">\n'
                                            f'    {string_value[:50]}...\n'
                                            f'</string>'
                                        ),
                                        poc_evidence=(
                                            f"String resource '{string_name}' contains a potential "
                                            f"{secret_type.lower()}: '{string_value[:30]}...'"
                                        ),
                                        poc_verification=(
                                            f"1. Decode APK: apktool d app.apk\n"
                                            f"2. Check strings: grep -r '{string_name}' res/values/\n"
                                            f"3. Or use: aapt dump resources app.apk | grep {string_name}"
                                        ),
                                        poc_commands=[
                                            f"apktool d {app.file_path} -o /tmp/decoded",
                                            f"grep -r '{string_name}' /tmp/decoded/res/values/",
                                        ],
                                        cwe_id="CWE-798",
                                        cwe_name="Use of Hard-coded Credentials",
                                        owasp_masvs_category="MASVS-STORAGE",
                                        owasp_masvs_control="MSTG-STORAGE-14",
                                        cvss_score=6.5,
                                    ))
                                break

        except Exception as e:
            logger.error(f"Failed to check strings.xml: {e}")

        return findings

    async def _check_raw_resources(
        self, app: MobileApp, apk_path: Path
    ) -> list[Finding]:
        """Check res/raw/ for certificates and config files."""
        findings = []

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                for name in apk.namelist():
                    if not name.startswith("res/raw/"):
                        continue

                    # Check for certificate files that might be used for pinning
                    if name.endswith((".cer", ".crt", ".pem")):
                        try:
                            content = apk.read(name)
                            # Check if it's a valid certificate
                            if b"-----BEGIN CERTIFICATE-----" in content:
                                # This is likely for SSL pinning - informational
                                findings.append(self.create_finding(
                                    app=app,
                                    title="Certificate Found in Raw Resources",
                                    severity="info",
                                    category="Certificate Pinning",
                                    description=(
                                        f"A certificate file was found in {name}. This may be used "
                                        "for SSL certificate pinning, which is a security best practice."
                                    ),
                                    impact=(
                                        "If this is a pinning certificate, it helps protect against "
                                        "man-in-the-middle attacks. However, attackers can extract "
                                        "and analyze the certificate."
                                    ),
                                    remediation=(
                                        "Ensure certificate pinning is properly implemented:\n"
                                        "1. Pin to multiple certificates for backup\n"
                                        "2. Have a plan for certificate rotation\n"
                                        "3. Consider using public key pinning instead"
                                    ),
                                    file_path=name,
                                    code_snippet="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                                    poc_evidence=f"Certificate file found at {name}",
                                    poc_verification=(
                                        f"1. Extract: unzip app.apk -d extracted/\n"
                                        f"2. View cert: openssl x509 -in extracted/{name} -text"
                                    ),
                                    poc_commands=[
                                        f"unzip -o {app.file_path} -d /tmp/extracted",
                                        f"openssl x509 -in /tmp/extracted/{name} -text -noout",
                                    ],
                                    owasp_masvs_category="MASVS-NETWORK",
                                    owasp_masvs_control="MSTG-NETWORK-4",
                                ))
                        except Exception:
                            pass

                    # Check for JSON config files
                    if name.endswith(".json"):
                        try:
                            content = apk.read(name).decode("utf-8", errors="ignore")
                            data = json.loads(content)

                            # Check for google-services.json
                            if "project_info" in data or "project_id" in data:
                                findings.append(self.create_finding(
                                    app=app,
                                    title="Firebase/Google Services Configuration Found",
                                    severity="info",
                                    category="Configuration",
                                    description=(
                                        f"Firebase/Google Services configuration found in {name}. "
                                        "This file contains project identifiers that may help attackers "
                                        "identify your Firebase project."
                                    ),
                                    impact=(
                                        "While this file is typically safe to include, attackers can use "
                                        "the project ID to attempt unauthorized access if Firebase security "
                                        "rules are misconfigured."
                                    ),
                                    remediation=(
                                        "Ensure Firebase security rules are properly configured:\n"
                                        "1. Use authentication for all sensitive operations\n"
                                        "2. Implement proper security rules in Firebase console\n"
                                        "3. Avoid storing sensitive data in public collections"
                                    ),
                                    file_path=name,
                                    code_snippet=json.dumps(data, indent=2)[:500],
                                    poc_evidence=f"Firebase config found in {name}",
                                    poc_commands=[
                                        f"unzip -o {app.file_path} -d /tmp/extracted",
                                        f"cat /tmp/extracted/{name} | python -m json.tool",
                                    ],
                                    owasp_masvs_category="MASVS-STORAGE",
                                    owasp_masvs_control="MSTG-STORAGE-12",
                                ))
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            pass

        except Exception as e:
            logger.error(f"Failed to check raw resources: {e}")

        return findings

    def _looks_like_secret(self, value: str) -> bool:
        """Check if a string value looks like a real secret."""
        # Skip placeholder values
        placeholders = ["your_key_here", "TODO", "FIXME", "example", "placeholder"]
        lower_value = value.lower()
        if any(p in lower_value for p in placeholders):
            return False

        # Check for high entropy (secrets tend to have varied characters)
        if len(value) < 16:
            return False

        unique_chars = len(set(value))
        if unique_chars / len(value) < 0.3:  # Too repetitive
            return False

        # Check for common secret patterns
        if re.match(r"^[A-Za-z0-9\-_+/=]{20,}$", value):
            return True

        return True
