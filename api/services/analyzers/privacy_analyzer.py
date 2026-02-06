"""Privacy compliance analyzer for mobile application tracking and data collection.

Performs comprehensive privacy analysis to detect tracking SDKs, personally
identifiable information (PII) handling patterns, sensitive data collection
APIs, and compliance gaps with GDPR, CCPA, and app store privacy policies.

Analysis categories:
    - **Tracking SDK Detection**: Identifies 16+ analytics, advertising,
      crash reporting, and social login SDKs including Firebase Analytics,
      Google Analytics, Mixpanel, Amplitude, Facebook Ads, AppsFlyer,
      Adjust, Branch, Crashlytics, Sentry, Bugsnag, and more.
    - **PII Handling Detection**: Searches for variable names and patterns
      indicating handling of email, phone, SSN, credit card, password,
      address, and date-of-birth data.
    - **Data Collection API Detection**: Identifies platform-specific APIs
      for accessing location, contacts, camera, microphone, calendar, SMS,
      call logs, device IDs, and installed applications.
    - **Permission Analysis**: Maps dangerous Android permissions and iOS
      privacy usage description keys to privacy implications.
    - **Privacy Policy Detection**: Checks application resources for
      references to a privacy policy URL.

OWASP references:
    - MASVS-PRIVACY: Privacy Requirements
    - MSTG-PRIVACY-1: Testing for PII Disclosure
    - MSTG-PRIVACY-3: Testing for Tracking
    - CWE-359: Exposure of Private Personal Information

Supported tracking SDK vendors:
    Google, Meta, Mixpanel, Amplitude, Segment, Yahoo, AppsFlyer,
    Adjust, Branch, Sentry, Bugsnag
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger(__name__)


@dataclass
class TrackerInfo:
    """Information about a detected tracker."""
    name: str
    vendor: str
    category: str
    data_collected: list[str]
    detection_method: str
    evidence: str


# Known tracking SDKs and their signatures
TRACKING_SDKS = {
    # Analytics
    "firebase_analytics": {
        "vendor": "Google",
        "category": "analytics",
        "patterns": [
            r"com\.google\.firebase\.analytics",
            r"FirebaseAnalytics",
            r"logEvent\s*\(",
            r"setUserProperty\s*\(",
        ],
        "data_collected": ["device_id", "app_events", "user_properties", "session_data"],
    },
    "google_analytics": {
        "vendor": "Google",
        "category": "analytics",
        "patterns": [
            r"com\.google\.android\.gms\.analytics",
            r"GoogleAnalytics",
            r"ga-tracking-id",
            r"UA-\d+-\d+",
        ],
        "data_collected": ["device_id", "app_events", "screen_views", "user_id"],
    },
    "mixpanel": {
        "vendor": "Mixpanel",
        "category": "analytics",
        "patterns": [
            r"com\.mixpanel",
            r"MixpanelAPI",
            r"mixpanel\.track",
        ],
        "data_collected": ["device_id", "events", "user_profiles", "location"],
    },
    "amplitude": {
        "vendor": "Amplitude",
        "category": "analytics",
        "patterns": [
            r"com\.amplitude",
            r"AmplitudeClient",
            r"amplitude\.logEvent",
        ],
        "data_collected": ["device_id", "events", "user_properties", "revenue"],
    },
    "segment": {
        "vendor": "Segment",
        "category": "analytics",
        "patterns": [
            r"com\.segment\.analytics",
            r"Analytics\.with\(",
            r"segment\.track",
        ],
        "data_collected": ["device_id", "events", "user_traits", "context"],
    },
    "flurry": {
        "vendor": "Yahoo",
        "category": "analytics",
        "patterns": [
            r"com\.flurry",
            r"FlurryAgent",
            r"flurry\.logEvent",
        ],
        "data_collected": ["device_id", "events", "demographics", "location"],
    },

    # Advertising
    "facebook_ads": {
        "vendor": "Meta",
        "category": "advertising",
        "patterns": [
            r"com\.facebook\.ads",
            r"FacebookSdk\.sdkInitialize",
            r"AppEventsLogger",
            r"fb-app-id",
        ],
        "data_collected": ["device_id", "ad_interactions", "app_events", "demographics"],
    },
    "google_ads": {
        "vendor": "Google",
        "category": "advertising",
        "patterns": [
            r"com\.google\.android\.gms\.ads",
            r"AdMob",
            r"InterstitialAd",
            r"RewardedAd",
        ],
        "data_collected": ["advertising_id", "ad_interactions", "device_info"],
    },
    "appsflyer": {
        "vendor": "AppsFlyer",
        "category": "advertising",
        "patterns": [
            r"com\.appsflyer",
            r"AppsFlyerLib",
            r"trackEvent",
        ],
        "data_collected": ["device_id", "install_attribution", "events", "revenue"],
    },
    "adjust": {
        "vendor": "Adjust",
        "category": "advertising",
        "patterns": [
            r"com\.adjust\.sdk",
            r"Adjust\.trackEvent",
            r"AdjustConfig",
        ],
        "data_collected": ["device_id", "install_attribution", "events", "revenue"],
    },
    "branch": {
        "vendor": "Branch",
        "category": "advertising",
        "patterns": [
            r"io\.branch",
            r"Branch\.getInstance",
            r"BranchEvent",
        ],
        "data_collected": ["device_id", "deep_link_data", "attribution", "events"],
    },

    # Crash Reporting
    "crashlytics": {
        "vendor": "Google",
        "category": "crash_reporting",
        "patterns": [
            r"com\.google\.firebase\.crashlytics",
            r"com\.crashlytics",
            r"Crashlytics\.logException",
        ],
        "data_collected": ["device_info", "crash_logs", "stack_traces", "user_id"],
    },
    "sentry": {
        "vendor": "Sentry",
        "category": "crash_reporting",
        "patterns": [
            r"io\.sentry",
            r"Sentry\.captureException",
            r"SentryClient",
        ],
        "data_collected": ["device_info", "crash_logs", "breadcrumbs", "user_context"],
    },
    "bugsnag": {
        "vendor": "Bugsnag",
        "category": "crash_reporting",
        "patterns": [
            r"com\.bugsnag",
            r"Bugsnag\.notify",
            r"BugsnagClient",
        ],
        "data_collected": ["device_info", "crash_logs", "app_state", "user_info"],
    },

    # Social Login
    "facebook_login": {
        "vendor": "Meta",
        "category": "social",
        "patterns": [
            r"com\.facebook\.login",
            r"LoginManager",
            r"AccessToken\.getCurrentAccessToken",
        ],
        "data_collected": ["user_id", "email", "profile", "friends_list"],
    },
    "google_signin": {
        "vendor": "Google",
        "category": "social",
        "patterns": [
            r"com\.google\.android\.gms\.auth",
            r"GoogleSignInClient",
            r"GoogleSignInAccount",
        ],
        "data_collected": ["user_id", "email", "profile", "id_token"],
    },
}

# PII patterns
PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

# API patterns that collect user data
DATA_COLLECTION_APIS = {
    "android": {
        "location": [
            r"getLastKnownLocation",
            r"requestLocationUpdates",
            r"FusedLocationProviderClient",
            r"LocationManager",
        ],
        "contacts": [
            r"ContactsContract",
            r"getContentResolver\(\)\.query.*contacts",
        ],
        "camera": [
            r"Camera\.open",
            r"CameraManager",
            r"takePicture",
        ],
        "microphone": [
            r"MediaRecorder",
            r"AudioRecord",
            r"startRecording",
        ],
        "calendar": [
            r"CalendarContract",
        ],
        "sms": [
            r"Telephony\.Sms",
            r"SmsManager",
        ],
        "call_log": [
            r"CallLog",
        ],
        "device_id": [
            r"getDeviceId",
            r"getAndroidId",
            r"getImei",
            r"getMacAddress",
            r"getSerialNumber",
        ],
        "installed_apps": [
            r"getInstalledPackages",
            r"getInstalledApplications",
        ],
    },
    "ios": {
        "location": [
            r"CLLocationManager",
            r"requestLocation",
            r"startUpdatingLocation",
        ],
        "contacts": [
            r"CNContactStore",
            r"ABAddressBook",
        ],
        "camera": [
            r"AVCaptureDevice",
            r"UIImagePickerController",
        ],
        "microphone": [
            r"AVAudioRecorder",
            r"AVAudioSession",
        ],
        "calendar": [
            r"EKEventStore",
        ],
        "health": [
            r"HKHealthStore",
            r"HealthKit",
        ],
        "device_id": [
            r"identifierForVendor",
            r"advertisingIdentifier",
        ],
    },
}


class PrivacyAnalyzer(BaseAnalyzer):
    """Analyzes mobile apps for privacy compliance and tracking SDKs.

    Extracts the application archive, scans source code for tracking SDK
    signatures, PII variable patterns, and platform-specific data collection
    APIs. Also checks manifest/Info.plist for dangerous permissions and
    searches application resources for privacy policy references.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        description: Human-readable description of analyzer purpose.
    """

    name = "privacy_analyzer"
    description = "Detects tracking SDKs, PII collection, and privacy compliance issues"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze the application for privacy issues and tracking.

        Args:
            app: The mobile application to analyze.

        Returns:
            A list of Finding objects covering detected trackers, PII
            handling, data collection APIs, permission analysis, and
            privacy policy presence.
        """
        if not app.file_path:
            return []

        import shutil
        import tempfile
        import zipfile

        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="privacy_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            results = []
            detected_trackers = []
            pii_findings = []
            data_collection_findings = []

            # Scan all source files
            source_extensions = [".java", ".kt", ".swift", ".m", ".h", ".js", ".ts", ".dart"]
            for ext in source_extensions:
                for source_file in extracted_path.rglob(f"*{ext}"):
                    try:
                        content = source_file.read_text(errors='ignore')
                        rel_path = str(source_file.relative_to(extracted_path))

                        # Check for tracking SDKs
                        trackers = self._detect_trackers(content, rel_path)
                        detected_trackers.extend(trackers)

                        # Check for PII handling
                        pii = self._detect_pii_handling(content, rel_path)
                        pii_findings.extend(pii)

                        # Check for data collection APIs
                        collection = self._detect_data_collection(content, rel_path, app.platform)
                        data_collection_findings.extend(collection)

                    except Exception as e:
                        logger.debug(f"Error analyzing {source_file}: {e}")

            # Check manifest/Info.plist for permissions
            permission_findings = await self._analyze_permissions(extracted_path, app.platform)

            # Create findings
            if detected_trackers:
                results.extend(self._create_tracker_findings(detected_trackers, app))

            if pii_findings:
                results.append(self._create_pii_finding(pii_findings, app))

            if data_collection_findings:
                results.extend(self._create_data_collection_findings(data_collection_findings, app))

            if permission_findings:
                results.extend(permission_findings)

            # Check for privacy policy
            privacy_policy_result = await self._check_privacy_policy(extracted_path, app)
            if privacy_policy_result:
                results.append(privacy_policy_result)

            # Convert AnalyzerResults to Findings
            findings = []
            for result in results:
                findings.append(self.result_to_finding(app, result))

            return findings

        except Exception as e:
            logger.error(f"Privacy analysis failed: {e}")
            return []
        finally:
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    def _detect_trackers(self, content: str, file_path: str) -> list[TrackerInfo]:
        """Detect tracking SDKs in source code via pattern matching.

        Args:
            content: Source file content to scan.
            file_path: Relative path of the source file for evidence.

        Returns:
            A list of TrackerInfo instances for each detected SDK.
        """
        detected = []

        for sdk_name, sdk_info in TRACKING_SDKS.items():
            for pattern in sdk_info["patterns"]:
                if re.search(pattern, content, re.IGNORECASE):
                    detected.append(TrackerInfo(
                        name=sdk_name,
                        vendor=sdk_info["vendor"],
                        category=sdk_info["category"],
                        data_collected=sdk_info["data_collected"],
                        detection_method="code_pattern",
                        evidence=f"Pattern '{pattern}' found in {file_path}"
                    ))
                    break  # Only detect once per SDK

        return detected

    def _detect_pii_handling(self, content: str, file_path: str) -> list[dict]:
        """Detect potential PII handling in code via variable name patterns.

        Args:
            content: Source file content to scan.
            file_path: Relative path of the source file for evidence.

        Returns:
            A list of dicts with 'type', 'pattern', 'matches', and
            'file_path' keys for each detected PII variable pattern.
        """
        findings = []

        # Check for PII variable names
        pii_variable_patterns = [
            r'\b(?:email|userEmail|user_email)\b',
            r'\b(?:phone|phoneNumber|phone_number|mobile)\b',
            r'\b(?:ssn|socialSecurity|social_security)\b',
            r'\b(?:creditCard|credit_card|cardNumber|card_number)\b',
            r'\b(?:password|passwd|pwd)\b',
            r'\b(?:address|homeAddress|home_address|street)\b',
            r'\b(?:dateOfBirth|dob|birth_date|birthDate)\b',
        ]

        for pattern in pii_variable_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "pii_variable",
                    "pattern": pattern,
                    "matches": matches[:5],
                    "file_path": file_path
                })

        return findings

    def _detect_data_collection(self, content: str, file_path: str, platform: str) -> list[dict]:
        """Detect sensitive data collection APIs for the given platform.

        Args:
            content: Source file content to scan.
            file_path: Relative path of the source file for evidence.
            platform: Either "android" or "ios".

        Returns:
            A list of dicts with 'data_type', 'pattern', and 'file_path'
            for each detected data collection API usage.
        """
        findings = []

        if platform not in DATA_COLLECTION_APIS:
            return findings

        for data_type, patterns in DATA_COLLECTION_APIS[platform].items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        "data_type": data_type,
                        "pattern": pattern,
                        "file_path": file_path
                    })
                    break

        return findings

    async def _analyze_permissions(self, extracted_path: Path, platform: str) -> list[AnalyzerResult]:
        """Analyze requested permissions for privacy implications."""
        results = []
        dangerous_permissions = []

        if platform == "android":
            manifest = extracted_path / "AndroidManifest.xml"
            if manifest.exists():
                content = manifest.read_text(errors='ignore')
                dangerous_android_perms = [
                    "READ_CONTACTS", "WRITE_CONTACTS",
                    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
                    "READ_CALL_LOG", "WRITE_CALL_LOG",
                    "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
                    "CAMERA", "RECORD_AUDIO",
                    "READ_CALENDAR", "WRITE_CALENDAR",
                    "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
                    "BODY_SENSORS",
                ]
                for perm in dangerous_android_perms:
                    if perm in content:
                        dangerous_permissions.append(perm)

        elif platform == "ios":
            info_plist = extracted_path / "Info.plist"
            if info_plist.exists():
                content = info_plist.read_text(errors='ignore')
                ios_privacy_keys = [
                    ("NSLocationWhenInUseUsageDescription", "Location"),
                    ("NSLocationAlwaysUsageDescription", "Background Location"),
                    ("NSCameraUsageDescription", "Camera"),
                    ("NSMicrophoneUsageDescription", "Microphone"),
                    ("NSContactsUsageDescription", "Contacts"),
                    ("NSCalendarsUsageDescription", "Calendar"),
                    ("NSPhotoLibraryUsageDescription", "Photos"),
                    ("NSHealthShareUsageDescription", "Health Data"),
                    ("NSMotionUsageDescription", "Motion Data"),
                ]
                for key, name in ios_privacy_keys:
                    if key in content:
                        dangerous_permissions.append(name)

        if dangerous_permissions:
            results.append(AnalyzerResult(
                title=f"Sensitive Permissions Requested ({len(dangerous_permissions)})",
                description=f"The app requests access to sensitive user data:\n\n" +
                           "\n".join([f"- {p}" for p in dangerous_permissions]),
                severity="medium",
                category="Privacy",
                impact="The app can access sensitive user data. Ensure proper consent is obtained and data is handled according to privacy regulations.",
                remediation="1. Justify each permission in privacy policy\n2. Implement runtime permission requests with clear explanations\n3. Apply data minimization principles\n4. Ensure proper consent mechanisms",
                cwe_id="CWE-359",
                cwe_name="Exposure of Private Personal Information",
                owasp_masvs_category="MASVS-PRIVACY",
                owasp_masvs_control="MSTG-PRIVACY-1",
                metadata={"permissions": dangerous_permissions}
            ))

        return results

    async def _check_privacy_policy(self, extracted_path: Path, app: MobileApp) -> AnalyzerResult | None:
        """Check for privacy policy URL in app."""
        privacy_url_patterns = [
            r'privacy[-_]?policy',
            r'privacypolicy',
            r'/privacy',
            r'privacy\.html',
        ]

        found_privacy_url = False

        # Check strings/resources
        for ext in [".xml", ".json", ".strings", ".plist"]:
            for f in extracted_path.rglob(f"*{ext}"):
                try:
                    content = f.read_text(errors='ignore').lower()
                    for pattern in privacy_url_patterns:
                        if re.search(pattern, content):
                            found_privacy_url = True
                            break
                except:
                    pass
                if found_privacy_url:
                    break

        if not found_privacy_url:
            return AnalyzerResult(
                title="Privacy Policy URL Not Found",
                description="No privacy policy URL was detected in the application resources. Apps that collect user data should provide a clear and accessible privacy policy.",
                severity="medium",
                category="Privacy Compliance",
                impact="Users cannot easily access information about how their data is collected and used, which may violate app store policies and privacy regulations.",
                remediation="1. Create a comprehensive privacy policy\n2. Add privacy policy URL to app store listing\n3. Include in-app link to privacy policy\n4. Ensure policy covers all data collection practices",
                cwe_id="CWE-359",
                cwe_name="Exposure of Private Personal Information",
                owasp_masvs_category="MASVS-PRIVACY",
                owasp_masvs_control="MSTG-PRIVACY-1",
            )

        return None

    def _create_tracker_findings(self, trackers: list[TrackerInfo], app: MobileApp) -> list[AnalyzerResult]:
        """Create findings for detected trackers."""
        results = []

        # Group by category
        by_category = {}
        for tracker in trackers:
            if tracker.category not in by_category:
                by_category[tracker.category] = []
            # Avoid duplicates
            if not any(t.name == tracker.name for t in by_category[tracker.category]):
                by_category[tracker.category].append(tracker)

        for category, category_trackers in by_category.items():
            tracker_list = "\n".join([
                f"- {t.name} ({t.vendor}): Collects {', '.join(t.data_collected[:3])}"
                for t in category_trackers
            ])

            all_data = set()
            for t in category_trackers:
                all_data.update(t.data_collected)

            severity = "high" if category == "advertising" else "medium"

            results.append(AnalyzerResult(
                title=f"{category.replace('_', ' ').title()} SDKs Detected ({len(category_trackers)})",
                description=f"The following {category} SDKs were detected:\n\n{tracker_list}",
                severity=severity,
                category="Privacy - Tracking",
                impact=f"These SDKs collect user data including: {', '.join(sorted(all_data))}. This may require user consent under GDPR/CCPA.",
                remediation="1. Document all tracking in privacy policy\n2. Implement consent management platform\n3. Provide opt-out mechanism\n4. Review data sharing agreements with vendors",
                cwe_id="CWE-359",
                cwe_name="Exposure of Private Personal Information",
                owasp_masvs_category="MASVS-PRIVACY",
                owasp_masvs_control="MSTG-PRIVACY-3",
                metadata={
                    "category": category,
                    "trackers": [t.name for t in category_trackers],
                    "vendors": list(set(t.vendor for t in category_trackers)),
                    "data_collected": list(all_data),
                }
            ))

        return results

    def _create_pii_finding(self, pii_findings: list[dict], app: MobileApp) -> AnalyzerResult:
        """Create finding for PII handling."""
        files_with_pii = list(set(f["file_path"] for f in pii_findings))

        # Group PII by type for better clarity
        pii_types = {}
        for f in pii_findings:
            pii_type = f.get("pii_type", "unknown")
            if pii_type not in pii_types:
                pii_types[pii_type] = []
            pii_types[pii_type].append(f["file_path"])

        pii_summary = "\n".join([
            f"• {pii_type}: {len(set(files))} file(s)"
            for pii_type, files in sorted(pii_types.items())
        ])

        return AnalyzerResult(
            title=f"PII Handling Detected in {len(files_with_pii)} Files",
            description=f"PII (Personally Identifiable Information) handling patterns detected:\n\n{pii_summary}\n\nAffected files:\n" +
                       "\n".join([f"- {f}" for f in files_with_pii]),
            severity="medium",
            category="Privacy - PII",
            impact="PII requires special handling under privacy regulations. Improper storage or transmission of PII can lead to data breaches and regulatory fines.",
            remediation="1. Encrypt PII at rest and in transit\n2. Minimize PII collection\n3. Implement data retention policies\n4. Ensure proper access controls\n5. Document PII processing in privacy policy",
            cwe_id="CWE-359",
            cwe_name="Exposure of Private Personal Information",
            owasp_masvs_category="MASVS-PRIVACY",
            owasp_masvs_control="MSTG-PRIVACY-1",
            metadata={
                "files_count": len(files_with_pii),
                "files": files_with_pii[:20],
            }
        )

    def _create_data_collection_findings(self, findings: list[dict], app: MobileApp) -> list[AnalyzerResult]:
        """Create findings for data collection APIs."""
        results = []

        # Group by data type
        by_type = {}
        for f in findings:
            if f["data_type"] not in by_type:
                by_type[f["data_type"]] = []
            by_type[f["data_type"]].append(f["file_path"])

        for data_type, files in by_type.items():
            unique_files = list(set(files))
            severity = "high" if data_type in ["location", "contacts", "microphone", "camera"] else "medium"

            results.append(AnalyzerResult(
                title=f"{data_type.replace('_', ' ').title()} Data Collection",
                description=f"The app accesses {data_type.replace('_', ' ')} data via system APIs.\n\nFound in:\n" +
                           "\n".join([f"- {f}" for f in unique_files[:5]]),
                severity=severity,
                category="Privacy - Data Collection",
                impact=f"Collection of {data_type} data requires user consent and proper handling under privacy regulations.",
                remediation=f"1. Ensure runtime permission request for {data_type}\n2. Provide clear justification to user\n3. Document in privacy policy\n4. Minimize data collection",
                cwe_id="CWE-359",
                cwe_name="Exposure of Private Personal Information",
                owasp_masvs_category="MASVS-PRIVACY",
                owasp_masvs_control="MSTG-PRIVACY-1",
                metadata={
                    "data_type": data_type,
                    "files": unique_files,
                }
            ))

        return results
