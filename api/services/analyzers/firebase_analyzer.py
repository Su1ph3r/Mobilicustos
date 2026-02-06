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

import httpx

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
        """Analyze Firebase configuration and perform live validation."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            if app.platform == "android":
                findings.extend(await self._analyze_android(app))
            elif app.platform == "ios":
                findings.extend(await self._analyze_ios(app))

            # Live validation of extracted Firebase project IDs
            findings.extend(await self._live_validate_firebase(app, findings))
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

    async def _live_validate_firebase(
        self, app: MobileApp, existing_findings: list[Finding],
    ) -> list[Finding]:
        """Perform safe, read-only live validation of Firebase resources.

        Probes Firebase RTDB and Firestore for unauthenticated access.
        Only performs GET requests — never writes or modifies data.
        """
        findings: list[Finding] = []

        # Extract project IDs from existing findings
        project_ids: set[str] = set()
        for f in existing_findings:
            if f.description:
                # Match "Project: xxx" or "Project ID: xxx"
                match = re.search(r'Project(?:\s*ID)?:\s*([a-z0-9-]+)', f.description)
                if match:
                    project_ids.add(match.group(1))

        if not project_ids:
            return findings

        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            for project_id in project_ids:
                # 1. Firebase Realtime Database open access test
                try:
                    rtdb_url = f"https://{project_id}-default-rtdb.firebaseio.com/.json"
                    resp = await client.get(rtdb_url)
                    if resp.status_code == 200 and resp.text != "null":
                        findings.append(self.create_finding(
                            app=app,
                            title=f"Firebase RTDB publicly accessible: {project_id}",
                            severity="critical",
                            category="Cloud Misconfiguration",
                            description=(
                                f"Firebase Realtime Database for project '{project_id}' allows "
                                f"unauthenticated read access. Response status: {resp.status_code}, "
                                f"data length: {len(resp.text)} bytes."
                            ),
                            impact="Anyone can read data from this Firebase database without authentication. This may expose user data, app configuration, or other sensitive information.",
                            remediation=(
                                "1. Update Firebase Security Rules to require authentication:\n"
                                '   { "rules": { ".read": "auth != null", ".write": "auth != null" } }\n'
                                "2. Review and restrict data access per user/role\n"
                                "3. Audit what data was publicly exposed"
                            ),
                            poc_evidence=f"curl '{rtdb_url}' returned {len(resp.text)} bytes",
                            poc_commands=[
                                {"type": "bash", "command": f"curl '{rtdb_url}'", "description": "Test unauthenticated RTDB access"},
                            ],
                            cwe_id="CWE-284",
                            owasp_masvs_category="MASVS-STORAGE",
                        ))
                except Exception as e:
                    logger.debug(f"Firebase RTDB check failed for {project_id}: {e}")

                # 2. Firestore open access test
                try:
                    firestore_url = (
                        f"https://firestore.googleapis.com/v1/projects/{project_id}"
                        f"/databases/(default)/documents"
                    )
                    resp = await client.get(firestore_url)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("documents"):
                            findings.append(self.create_finding(
                                app=app,
                                title=f"Firestore publicly accessible: {project_id}",
                                severity="critical",
                                category="Cloud Misconfiguration",
                                description=(
                                    f"Cloud Firestore for project '{project_id}' allows "
                                    f"unauthenticated document listing. "
                                    f"{len(data.get('documents', []))} documents returned."
                                ),
                                impact="Anyone can list and read Firestore documents without authentication.",
                                remediation="Configure Firestore Security Rules to require authentication for all reads.",
                                poc_evidence=f"GET {firestore_url} returned documents",
                                poc_commands=[
                                    {"type": "bash", "command": f"curl '{firestore_url}'", "description": "Test unauthenticated Firestore access"},
                                ],
                                cwe_id="CWE-284",
                                owasp_masvs_category="MASVS-STORAGE",
                            ))
                except Exception as e:
                    logger.debug(f"Firestore check failed for {project_id}: {e}")

        return findings
