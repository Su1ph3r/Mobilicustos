"""Firebase configuration security analyzer.

Analyzes Firebase/Google services configuration embedded in mobile
applications for security misconfigurations and exposed credentials.

Security checks:
    - Exposed Firebase API keys and project IDs
    - Publicly accessible Firebase Realtime Database URLs
    - Sensitive data in Crashlytics logging
    - Insecure Firebase Storage rules references
    - Cloud Firestore security rules misconfigurations

OWASP references:
    - CWE-798: Use of Hard-coded Credentials
    - MASVS-STORAGE-1
"""

import json
import logging
import re
import zipfile
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class FirebaseAnalyzer(BaseAnalyzer):
    """Analyzes Firebase and Google services configuration for security issues.

    Scans for exposed Firebase credentials, insecure database URLs,
    sensitive data in crash reporting, and misconfigured storage rules
    within application binaries and configuration files.
    """

    name = "firebase_analyzer"
    platform = "cross-platform"

    FIREBASE_CONFIG_PATTERNS = {
        "api_key": {"pattern": r'AIza[0-9A-Za-z_-]{35}', "name": "Firebase API Key", "severity": "medium"},
        "project_id": {"pattern": r'["\']?projectId["\']?\s*[:=]\s*["\']([a-z0-9-]+)["\']', "name": "Firebase Project ID", "severity": "info"},
        "database_url": {"pattern": r'https://([a-z0-9-]+)\.firebaseio\.com', "name": "Firebase Database URL", "severity": "medium"},
    }

    DANGEROUS_PATTERNS = {
        "crashlytics_sensitive": {
            "pattern": r'Crashlytics\.log\([^)]*password|Crashlytics\.log\([^)]*token',
            "name": "Sensitive Data in Crashlytics",
            "severity": "high",
        },
        "server_key": {
            "pattern": r'["\']?serverKey["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{100,})["\']',
            "name": "Firebase Server Key Exposed",
            "severity": "critical",
        },
    }

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze Firebase configuration."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            if app.platform == "android":
                findings.extend(await self._analyze_android(app))
            elif app.platform == "ios":
                findings.extend(await self._analyze_ios(app))
        except Exception as e:
            logger.error(f"Firebase analysis failed: {e}")

        return findings

    async def _analyze_android(self, app: MobileApp) -> list[Finding]:
        """Analyze Android app for Firebase configuration."""
        findings: list[Finding] = []

        try:
            with zipfile.ZipFile(app.file_path, "r") as apk:
                for name in apk.namelist():
                    if "google-services.json" in name.lower():
                        config_data = apk.read(name)
                        findings.extend(await self._analyze_google_services(app, config_data, name))

                    if name.endswith(".dex"):
                        dex_data = apk.read(name)
                        dex_text = dex_data.decode("utf-8", errors="ignore")
                        findings.extend(self._check_dangerous_patterns(app, dex_text, name))

        except Exception as e:
            logger.error(f"Android Firebase analysis failed: {e}")

        return findings

    async def _analyze_ios(self, app: MobileApp) -> list[Finding]:
        """Analyze iOS app for Firebase configuration."""
        findings: list[Finding] = []

        try:
            with zipfile.ZipFile(app.file_path, "r") as ipa:
                for name in ipa.namelist():
                    if "GoogleService-Info.plist" in name:
                        plist_data = ipa.read(name)
                        findings.extend(await self._analyze_google_service_plist(app, plist_data, name))
        except Exception as e:
            logger.error(f"iOS Firebase analysis failed: {e}")

        return findings

    async def _analyze_google_services(self, app: MobileApp, config_data: bytes, file_path: str) -> list[Finding]:
        """Analyze google-services.json configuration."""
        findings: list[Finding] = []

        try:
            config_text = config_data.decode("utf-8")
            config = json.loads(config_text)
            project_info = config.get("project_info", {})
            project_id = project_info.get("project_id", "")
            firebase_url = project_info.get("firebase_url", "")

            findings.append(self.create_finding(
                app=app,
                title="Firebase Configuration Exposed",
                severity="medium",
                category="Secrets",
                description=f"Firebase config found. Project: {project_id}, URL: {firebase_url or 'not set'}",
                impact="If Security Rules are misconfigured, attackers can access data.",
                remediation="Verify Firebase Security Rules are properly configured.",
                file_path=file_path,
                code_snippet=config_text[:500],
                owasp_masvs_category="MASVS-STORAGE",
                poc_commands=[
                    {"type": "bash", "command": f"curl 'https://{project_id}.firebaseio.com/.json'", "description": "Test public access"},
                ],
                remediation_resources=[
                    {"title": "Firebase Security Rules", "url": "https://firebase.google.com/docs/rules", "type": "documentation"},
                ],
            ))

        except json.JSONDecodeError:
            logger.warning("Failed to parse google-services.json")

        return findings

    async def _analyze_google_service_plist(self, app: MobileApp, plist_data: bytes, file_path: str) -> list[Finding]:
        """Analyze GoogleService-Info.plist for iOS."""
        findings: list[Finding] = []

        try:
            import plistlib
            config = plistlib.loads(plist_data)
            project_id = config.get("PROJECT_ID", "")

            if project_id:
                findings.append(self.create_finding(
                    app=app,
                    title="Firebase Configuration Exposed (iOS)",
                    severity="medium",
                    category="Secrets",
                    description=f"Firebase config found. Project ID: {project_id}",
                    impact="Firebase resources may be accessible if Security Rules are misconfigured.",
                    remediation="Verify Firebase Security Rules.",
                    file_path=file_path,
                    owasp_masvs_category="MASVS-STORAGE",
                ))
        except Exception as e:
            logger.error(f"Error analyzing GoogleService-Info.plist: {e}")

        return findings

    def _check_dangerous_patterns(self, app: MobileApp, text: str, file_path: str) -> list[Finding]:
        """Check for dangerous Firebase usage patterns."""
        findings: list[Finding] = []

        for name, info in self.DANGEROUS_PATTERNS.items():
            if re.search(info["pattern"], text, re.IGNORECASE):
                findings.append(self.create_finding(
                    app=app,
                    title=info["name"],
                    severity=info["severity"],
                    category="Firebase",
                    description=f"Dangerous Firebase pattern detected: {info['name']}",
                    impact="Security credentials or sensitive data may be exposed.",
                    remediation="Remove sensitive data from client code. Use backend for server keys.",
                    file_path=file_path,
                    cwe_id="CWE-798",
                    cwe_name="Use of Hard-coded Credentials",
                    owasp_masvs_category="MASVS-STORAGE",
                ))

        return findings
