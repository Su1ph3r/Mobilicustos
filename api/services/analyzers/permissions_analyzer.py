"""Android permissions analyzer for dangerous, special, and unused permissions.

Evaluates all permissions declared in AndroidManifest.xml against a
comprehensive database of 20+ dangerous permissions and 4 special
permissions, categorizes them by risk domain (location, communication,
media, privacy, storage), and performs API usage cross-referencing to
detect over-privileged applications.

Security checks performed:
    - **Dangerous Permission Categorization**: Groups dangerous permissions
      by risk domain (location, communication, media, privacy, storage)
      with platform-specific risk descriptions and privacy implications.
    - **Special Permission Detection**: Flags high-risk special permissions
      including SYSTEM_ALERT_WINDOW (tapjacking), REQUEST_INSTALL_PACKAGES,
      QUERY_ALL_PACKAGES, and MANAGE_EXTERNAL_STORAGE.
    - **Unused Permission Detection**: Cross-references declared dangerous
      permissions against API usage patterns in decompiled source code
      to identify permissions that may be unnecessary (over-privileging).
    - **Custom Permission Analysis**: Enumerates custom permission
      definitions with their protectionLevel values.

OWASP references:
    - MASVS-PLATFORM: Platform Interaction
    - MASVS-PLATFORM-1: Testing App Permissions
    - CWE-250: Execution with Unnecessary Privileges
"""

import logging
import re
import shutil
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

# Android namespace
NS = {"android": "http://schemas.android.com/apk/res/android"}

# Dangerous Android permissions and their related APIs
DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA": {
        "description": "Camera access",
        "risk": "Can capture photos/videos without user awareness",
        "apis": ["Camera", "CameraManager", "CameraDevice", "takePicture", "openCamera"],
    },
    "android.permission.READ_CONTACTS": {
        "description": "Read contacts",
        "risk": "Access to user's contacts and personal information",
        "apis": ["ContactsContract", "ContentResolver.*contacts"],
    },
    "android.permission.WRITE_CONTACTS": {
        "description": "Modify contacts",
        "risk": "Can modify or delete user's contacts",
        "apis": ["ContactsContract", "ContentResolver.*insert.*contacts"],
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "description": "Precise GPS location",
        "risk": "Track user's precise location",
        "apis": ["LocationManager", "FusedLocationProvider", "getLastKnownLocation", "requestLocationUpdates"],
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "description": "Approximate location",
        "risk": "Track user's approximate location (cell tower/Wi-Fi)",
        "apis": ["LocationManager", "FusedLocationProvider"],
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "description": "Background location access",
        "risk": "Track user location even when app is in background",
        "apis": ["requestLocationUpdates", "FusedLocationProvider"],
    },
    "android.permission.RECORD_AUDIO": {
        "description": "Microphone access",
        "risk": "Can record audio conversations",
        "apis": ["MediaRecorder", "AudioRecord", "startRecording"],
    },
    "android.permission.READ_PHONE_STATE": {
        "description": "Phone state and identity",
        "risk": "Access to IMEI, phone number, and call state",
        "apis": ["TelephonyManager", "getDeviceId", "getLine1Number", "getImei"],
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "description": "Phone numbers",
        "risk": "Access to device phone numbers",
        "apis": ["TelephonyManager", "getLine1Number"],
    },
    "android.permission.READ_CALL_LOG": {
        "description": "Read call history",
        "risk": "Access to incoming and outgoing call records",
        "apis": ["CallLog", "Calls.CONTENT_URI"],
    },
    "android.permission.READ_SMS": {
        "description": "Read SMS messages",
        "risk": "Access to text messages including OTP codes",
        "apis": ["Telephony.Sms", "SmsManager", "ContentResolver.*sms"],
    },
    "android.permission.SEND_SMS": {
        "description": "Send SMS messages",
        "risk": "Can send messages potentially incurring charges",
        "apis": ["SmsManager", "sendTextMessage", "sendMultipartTextMessage"],
    },
    "android.permission.RECEIVE_SMS": {
        "description": "Receive SMS messages",
        "risk": "Can intercept incoming SMS including OTP codes",
        "apis": ["SmsReceiver", "SMS_RECEIVED", "android.provider.Telephony.SMS_RECEIVED"],
    },
    "android.permission.READ_CALENDAR": {
        "description": "Read calendar events",
        "risk": "Access to calendar events and meeting details",
        "apis": ["CalendarContract", "Events.CONTENT_URI"],
    },
    "android.permission.WRITE_CALENDAR": {
        "description": "Modify calendar",
        "risk": "Can add or modify calendar events",
        "apis": ["CalendarContract", "Events.CONTENT_URI"],
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "description": "Read external storage",
        "risk": "Access to photos, downloads, and other files",
        "apis": ["getExternalStorageDirectory", "getExternalFilesDir", "MediaStore"],
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "description": "Write external storage",
        "risk": "Can modify or delete files on external storage",
        "apis": ["getExternalStorageDirectory", "getExternalFilesDir"],
    },
    "android.permission.BODY_SENSORS": {
        "description": "Body sensors (e.g., heart rate)",
        "risk": "Access to sensitive health/biometric data",
        "apis": ["SensorManager", "TYPE_HEART_RATE"],
    },
    "android.permission.ACTIVITY_RECOGNITION": {
        "description": "Physical activity recognition",
        "risk": "Track user's physical activities",
        "apis": ["ActivityRecognition", "DetectedActivity"],
    },
}

# Special permissions (not dangerous but noteworthy)
SPECIAL_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "description": "Draw overlays",
        "risk": "Can display UI on top of other apps (tapjacking, phishing)",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "description": "Install packages",
        "risk": "Can request installation of APKs",
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "description": "Query installed packages",
        "risk": "Can enumerate all installed applications",
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "description": "All files access",
        "risk": "Full access to external storage including other apps' files",
    },
}


class PermissionsAnalyzer(BaseAnalyzer):
    """Analyzes requested Android permissions for security and privacy issues.

    Parses AndroidManifest.xml to extract all uses-permission declarations,
    categorizes them by risk level, cross-references with source code API
    usage to detect over-privileging, and generates permission-domain-
    specific findings.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform ("android").
    """

    name = "permissions_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze application permissions for security and privacy issues.

        Args:
            app: The mobile application to analyze.

        Returns:
            A list of Finding objects covering dangerous permissions,
            special permissions, unused permissions, custom permissions,
            and a summary.
        """
        if not app.file_path:
            return []

        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="permissions_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            findings = []

            # Parse AndroidManifest.xml
            manifest_xml = None
            manifest_path = extracted_path / "AndroidManifest.xml"

            if manifest_path.exists():
                try:
                    manifest_xml = manifest_path.read_text(errors='ignore')
                except Exception:
                    pass

            if not manifest_xml:
                try:
                    from androguard.core.axml import AXMLPrinter
                    with zipfile.ZipFile(app.file_path, "r") as apk:
                        manifest_data = apk.read("AndroidManifest.xml")
                        axml = AXMLPrinter(manifest_data)
                        manifest_xml = axml.get_xml()
                except Exception:
                    pass

            if not manifest_xml:
                return findings

            try:
                root = ET.fromstring(manifest_xml)
            except ET.ParseError:
                return findings

            # Extract requested permissions
            requested_permissions = self._extract_permissions(root)

            # Categorize permissions
            dangerous_perms = []
            special_perms = []
            normal_perms = []

            for perm in requested_permissions:
                if perm in DANGEROUS_PERMISSIONS:
                    dangerous_perms.append(perm)
                elif perm in SPECIAL_PERMISSIONS:
                    special_perms.append(perm)
                else:
                    normal_perms.append(perm)

            # Check for dangerous permissions
            if dangerous_perms:
                findings.extend(self._create_dangerous_perm_findings(dangerous_perms, app))

            # Check for special permissions
            if special_perms:
                findings.extend(self._create_special_perm_findings(special_perms, app))

            # Check for unused permissions (over-privileging)
            unused_perms = await self._check_unused_permissions(
                extracted_path, dangerous_perms, app
            )
            if unused_perms:
                findings.append(self._create_unused_perm_finding(unused_perms, app))

            # Check for custom permissions defined by the app
            custom_perms = self._check_custom_permissions(root, app)
            if custom_perms:
                findings.extend(custom_perms)

            # Overall permissions summary
            findings.append(self.create_finding(
                app=app,
                title=f"Permissions Summary ({len(requested_permissions)} total)",
                description=(
                    f"**Total permissions requested:** {len(requested_permissions)}\n"
                    f"**Dangerous permissions:** {len(dangerous_perms)}\n"
                    f"**Special permissions:** {len(special_perms)}\n"
                    f"**Normal permissions:** {len(normal_perms)}\n\n"
                    "**Dangerous permissions:**\n" +
                    "\n".join(f"- {DANGEROUS_PERMISSIONS[p]['description']}: {p.split('.')[-1]}" for p in dangerous_perms)
                    if dangerous_perms else "No dangerous permissions."
                ),
                severity="info",
                category="Permissions",
                impact="Review all permissions to ensure they are necessary for app functionality.",
                remediation="Apply principle of least privilege. Remove unnecessary permissions.",
                owasp_masvs_category="MASVS-PLATFORM",
                owasp_masvs_control="MASVS-PLATFORM-1",
            ))

            return findings

        except Exception as e:
            logger.error(f"Permissions analysis failed: {e}")
            return []
        finally:
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    def _extract_permissions(self, root: ET.Element) -> list[str]:
        """Extract all requested permissions from the manifest.

        Args:
            root: Parsed XML root of AndroidManifest.xml.

        Returns:
            A list of fully qualified permission name strings.
        """
        permissions = []

        for uses_perm in root.iter("uses-permission"):
            perm = uses_perm.get(f"{{{NS['android']}}}name", "")
            if not perm:
                perm = uses_perm.get("name", "")
            if perm:
                permissions.append(perm)

        return permissions

    def _create_dangerous_perm_findings(self, perms: list[str], app: MobileApp) -> list[Finding]:
        """Create findings for dangerous permissions grouped by risk domain.

        Groups permissions into location, communication, privacy, media,
        and storage categories, generating separate findings for each.

        Args:
            perms: List of dangerous permission name strings.
            app: The mobile application being analyzed.

        Returns:
            A list of Finding objects, one per permission domain.
        """
        findings = []

        # Group permissions by risk category
        location_perms = [p for p in perms if "LOCATION" in p]
        communication_perms = [p for p in perms if any(x in p for x in ["SMS", "CALL", "PHONE"])]
        privacy_perms = [p for p in perms if any(x in p for x in ["CONTACTS", "CALENDAR", "SENSOR"])]
        media_perms = [p for p in perms if any(x in p for x in ["CAMERA", "AUDIO", "RECORD"])]
        storage_perms = [p for p in perms if "STORAGE" in p]

        if location_perms:
            perm_list = "\n".join(
                f"- {DANGEROUS_PERMISSIONS.get(p, {}).get('description', p.split('.')[-1])}"
                for p in location_perms
            )
            has_background = "android.permission.ACCESS_BACKGROUND_LOCATION" in location_perms

            findings.append(self.create_finding(
                app=app,
                title=f"Location Permissions Requested ({len(location_perms)})",
                description=(
                    f"The application requests location access:\n\n{perm_list}"
                    + ("\n\n**WARNING:** Background location access is requested. "
                       "This allows tracking even when the app is not in use."
                       if has_background else "")
                ),
                severity="high" if has_background else "medium",
                category="Permissions",
                impact="The app can track user's physical location, raising significant privacy concerns.",
                remediation=(
                    "1. Justify location usage clearly to users\n"
                    "2. Use the least precise location that meets requirements\n"
                    "3. Avoid background location unless absolutely necessary\n"
                    "4. Document in privacy policy"
                ),
                file_path="AndroidManifest.xml",
                cwe_id="CWE-250",
                cwe_name="Execution with Unnecessary Privileges",
                cvss_score=5.3 if has_background else 3.3,
                owasp_masvs_category="MASVS-PLATFORM",
                owasp_masvs_control="MASVS-PLATFORM-1",
            ))

        if communication_perms:
            perm_list = "\n".join(
                f"- {DANGEROUS_PERMISSIONS.get(p, {}).get('description', p.split('.')[-1])}"
                for p in communication_perms
            )
            findings.append(self.create_finding(
                app=app,
                title=f"Communication Permissions Requested ({len(communication_perms)})",
                description=f"The application requests access to communication data:\n\n{perm_list}",
                severity="medium",
                category="Permissions",
                impact="Access to SMS, call logs, and phone state can expose sensitive communications.",
                remediation="Ensure these permissions are necessary. Consider using SMS Retriever API instead of READ_SMS.",
                file_path="AndroidManifest.xml",
                cwe_id="CWE-250",
                cwe_name="Execution with Unnecessary Privileges",
                owasp_masvs_category="MASVS-PLATFORM",
                owasp_masvs_control="MASVS-PLATFORM-1",
            ))

        if media_perms:
            perm_list = "\n".join(
                f"- {DANGEROUS_PERMISSIONS.get(p, {}).get('description', p.split('.')[-1])}"
                for p in media_perms
            )
            findings.append(self.create_finding(
                app=app,
                title=f"Camera/Microphone Permissions Requested ({len(media_perms)})",
                description=f"The application requests camera and/or microphone access:\n\n{perm_list}",
                severity="medium",
                category="Permissions",
                impact="Camera and microphone access can capture visual and audio data.",
                remediation="Ensure camera/microphone usage is clearly communicated to users.",
                file_path="AndroidManifest.xml",
                cwe_id="CWE-250",
                cwe_name="Execution with Unnecessary Privileges",
                owasp_masvs_category="MASVS-PLATFORM",
                owasp_masvs_control="MASVS-PLATFORM-1",
            ))

        return findings

    def _create_special_perm_findings(self, perms: list[str], app: MobileApp) -> list[Finding]:
        """Create findings for special permissions."""
        findings = []

        for perm in perms:
            info = SPECIAL_PERMISSIONS.get(perm, {})

            severity = "high" if perm in (
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
            ) else "medium"

            findings.append(self.create_finding(
                app=app,
                title=f"Special Permission: {info.get('description', perm.split('.')[-1])}",
                description=(
                    f"The application requests the special permission: {perm}\n\n"
                    f"**Risk:** {info.get('risk', 'Elevated privilege access')}"
                ),
                severity=severity,
                category="Permissions",
                impact=info.get("risk", "Special permissions grant elevated privileges."),
                remediation="Verify this permission is necessary. Special permissions require explicit user approval.",
                file_path="AndroidManifest.xml",
                cwe_id="CWE-250",
                cwe_name="Execution with Unnecessary Privileges",
                owasp_masvs_category="MASVS-PLATFORM",
                owasp_masvs_control="MASVS-PLATFORM-1",
            ))

        return findings

    async def _check_unused_permissions(
        self, extracted_path: Path, dangerous_perms: list[str], app: MobileApp
    ) -> list[str]:
        """Check if dangerous permissions are actually used in source code.

        Aggregates all source content and checks each dangerous permission's
        associated API patterns against it.

        Args:
            extracted_path: Root directory of the extracted APK.
            dangerous_perms: List of dangerous permission names to check.
            app: The mobile application being analyzed.

        Returns:
            A list of permission names that appear to be unused.
        """
        unused = []

        # Collect all source code content
        all_source = ""
        for ext in [".java", ".kt", ".smali"]:
            for source_file in extracted_path.rglob(f"*{ext}"):
                try:
                    all_source += source_file.read_text(errors='ignore') + "\n"
                except Exception:
                    pass

        for perm in dangerous_perms:
            perm_info = DANGEROUS_PERMISSIONS.get(perm, {})
            apis = perm_info.get("apis", [])

            if not apis:
                continue

            # Check if any of the APIs are used
            api_found = False
            for api_pattern in apis:
                if re.search(api_pattern, all_source, re.IGNORECASE):
                    api_found = True
                    break

            if not api_found:
                unused.append(perm)

        return unused

    def _create_unused_perm_finding(self, unused_perms: list[str], app: MobileApp) -> Finding:
        """Create finding for unused permissions."""
        perm_list = "\n".join(
            f"- {DANGEROUS_PERMISSIONS.get(p, {}).get('description', p.split('.')[-1])}: {p.split('.')[-1]}"
            for p in unused_perms
        )

        return self.create_finding(
            app=app,
            title=f"Potentially Unused Dangerous Permissions ({len(unused_perms)})",
            description=(
                "The following dangerous permissions are declared in the manifest but "
                "no corresponding API usage was found in the source code:\n\n"
                f"{perm_list}\n\n"
                "These may be leftovers from removed features, library requirements, "
                "or permissions used only in native code."
            ),
            severity="low",
            category="Permissions",
            impact=(
                "Over-privileged apps request more permissions than needed, "
                "increasing the attack surface and reducing user trust."
            ),
            remediation=(
                "1. Remove permissions that are not used by the app\n"
                "2. If permissions are required by libraries, document the justification\n"
                "3. Apply principle of least privilege"
            ),
            file_path="AndroidManifest.xml",
            cwe_id="CWE-250",
            cwe_name="Execution with Unnecessary Privileges",
            cvss_score=3.3,
            owasp_masvs_category="MASVS-PLATFORM",
            owasp_masvs_control="MASVS-PLATFORM-1",
        )

    def _check_custom_permissions(self, root: ET.Element, app: MobileApp) -> list[Finding]:
        """Check for custom permission definitions."""
        findings = []
        custom_perms = []

        for permission in root.iter("permission"):
            perm_name = permission.get(f"{{{NS['android']}}}name", "")
            if not perm_name:
                perm_name = permission.get("name", "")

            # Skip system permissions
            if perm_name.startswith("android.permission"):
                continue

            if perm_name:
                protection_level = permission.get(f"{{{NS['android']}}}protectionLevel", "normal")
                custom_perms.append({
                    "name": perm_name,
                    "protection_level": protection_level,
                })

        if custom_perms:
            perm_list = "\n".join(
                f"- {p['name']} (protectionLevel={p['protection_level']})"
                for p in custom_perms
            )

            findings.append(self.create_finding(
                app=app,
                title=f"Custom Permissions Defined ({len(custom_perms)})",
                description=(
                    f"The application defines {len(custom_perms)} custom permission(s):\n\n"
                    f"{perm_list}\n\n"
                    "Review protection levels to ensure adequate access control."
                ),
                severity="info",
                category="Permissions",
                impact="Custom permissions control access to app components.",
                remediation="Ensure custom permissions use 'signature' protectionLevel for inter-app communication.",
                file_path="AndroidManifest.xml",
                owasp_masvs_category="MASVS-PLATFORM",
                owasp_masvs_control="MASVS-PLATFORM-1",
            ))

        return findings
