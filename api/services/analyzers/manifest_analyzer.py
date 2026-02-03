"""Android manifest analyzer."""

import logging
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

# Android namespace
NS = {"android": "http://schemas.android.com/apk/res/android"}


class ManifestAnalyzer(BaseAnalyzer):
    """Analyzes AndroidManifest.xml for security issues."""

    name = "manifest_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze the Android manifest."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            manifest_xml = await self._extract_manifest(Path(app.file_path))
            if not manifest_xml:
                return findings

            root = ET.fromstring(manifest_xml)

            # Run all checks
            findings.extend(await self._check_debug_enabled(app, root))
            findings.extend(await self._check_backup_enabled(app, root))
            findings.extend(await self._check_exported_components(app, root))
            findings.extend(await self._check_deep_links(app, root))
            findings.extend(await self._check_clear_text_traffic(app, root))
            findings.extend(await self._check_dangerous_permissions(app, root))
            findings.extend(await self._check_task_hijacking(app, root))

        except Exception as e:
            logger.error(f"Manifest analysis failed: {e}")

        return findings

    async def _extract_manifest(self, apk_path: Path) -> str | None:
        """Extract and decode AndroidManifest.xml."""
        try:
            # androguard 4.x uses different import paths
            from androguard.core.axml import AXMLPrinter

            with zipfile.ZipFile(apk_path, "r") as apk:
                manifest_data = apk.read("AndroidManifest.xml")
                axml = AXMLPrinter(manifest_data)
                return axml.get_xml()
        except ImportError:
            logger.warning("androguard not installed")
            return None
        except Exception as e:
            logger.error(f"Failed to extract manifest: {e}")
            return None

    async def _check_debug_enabled(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check if android:debuggable is true."""
        findings = []
        application = root.find("application")

        if application is not None:
            debuggable = application.get(f"{{{NS['android']}}}debuggable")
            if debuggable == "true":
                findings.append(self.create_finding(
                    app=app,
                    title="Application is Debuggable",
                    severity="high",
                    category="Configuration",
                    description=(
                        "The application has android:debuggable set to true. "
                        "This allows attackers to attach a debugger and inspect "
                        "runtime data, modify application behavior, and extract sensitive information."
                    ),
                    impact=(
                        "An attacker can connect a debugger to the running application to: "
                        "inspect variables containing credentials, modify control flow, "
                        "bypass security checks, and extract encryption keys from memory."
                    ),
                    remediation=(
                        "Remove android:debuggable=\"true\" from the application tag or "
                        "ensure release builds have debuggable=false. Use build variants "
                        "to manage debug vs release configurations."
                    ),
                    file_path="AndroidManifest.xml",
                    code_snippet='android:debuggable="true"',
                    poc_evidence="Found debuggable=true in manifest",
                    poc_verification="adb shell run-as <package> ls",
                    poc_commands=[
                        "adb jdwp",
                        f"adb shell run-as {app.package_name} ls",
                    ],
                    cwe_id="CWE-489",
                    cwe_name="Active Debug Code",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-4",
                    owasp_mastg_test="MASTG-TEST-0039",
                    remediation_code={
                        "android": 'android:debuggable="false"',
                    },
                ))

        return findings

    async def _check_backup_enabled(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check if backups are enabled."""
        findings = []
        application = root.find("application")

        if application is not None:
            backup = application.get(f"{{{NS['android']}}}allowBackup")
            # Default is true if not specified (for API < 31)
            if backup != "false":
                findings.append(self.create_finding(
                    app=app,
                    title="Application Data Backup Enabled",
                    severity="medium",
                    category="Data Protection",
                    description=(
                        "The application allows backup of its data via ADB. "
                        "This can expose sensitive data stored in SharedPreferences, "
                        "databases, and internal storage to anyone with USB access."
                    ),
                    impact=(
                        "An attacker with physical or ADB access can extract all "
                        "application data including credentials, tokens, and personal information."
                    ),
                    remediation=(
                        "Set android:allowBackup=\"false\" or implement a BackupAgent "
                        "that excludes sensitive data. For API 31+, use android:dataExtractionRules."
                    ),
                    file_path="AndroidManifest.xml",
                    code_snippet=f'android:allowBackup="{backup or "true (default)}"',
                    poc_evidence=f"allowBackup is {'not set (defaults to true)' if backup is None else 'explicitly set to true'}",
                    poc_verification="1. Connect device via USB\n2. Run adb backup command\n3. Extract and examine backup contents",
                    poc_commands=[
                        f"adb backup -apk {app.package_name}",
                        "dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar",
                        "tar -xf backup.tar && ls -la",
                    ],
                    cwe_id="CWE-530",
                    cwe_name="Exposure of Backup File to an Unauthorized Control Sphere",
                    owasp_masvs_category="MASVS-STORAGE",
                    owasp_masvs_control="MASVS-STORAGE-2",
                    remediation_code={
                        "android": 'android:allowBackup="false"',
                    },
                ))

        return findings

    async def _check_exported_components(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check for exported components without permissions."""
        findings = []
        component_types = ["activity", "service", "receiver", "provider"]

        for comp_type in component_types:
            for component in root.iter(comp_type):
                name = component.get(f"{{{NS['android']}}}name", "")
                exported = component.get(f"{{{NS['android']}}}exported")
                permission = component.get(f"{{{NS['android']}}}permission")

                # Check if has intent-filters (implicitly exported in older SDKs)
                has_intent_filter = component.find("intent-filter") is not None

                if exported == "true" and not permission:
                    severity = "high" if comp_type in ("service", "provider") else "medium"

                    # Build PoC command based on component type
                    if comp_type == "activity":
                        poc_cmd = f"adb shell am start -n {app.package_name}/{name}"
                    elif comp_type == "service":
                        poc_cmd = f"adb shell am startservice -n {app.package_name}/{name}"
                    elif comp_type == "receiver":
                        poc_cmd = f"adb shell am broadcast -n {app.package_name}/{name}"
                    else:  # provider
                        poc_cmd = f"adb shell content query --uri content://{app.package_name}.provider/"

                    findings.append(self.create_finding(
                        app=app,
                        title=f"Exported {comp_type.title()} Without Permission: {name}",
                        severity=severity,
                        category="Component Security",
                        description=(
                            f"The {comp_type} '{name}' is exported without requiring "
                            f"any permission. Any app on the device can interact with it."
                        ),
                        impact=(
                            f"Other apps can invoke this {comp_type} to potentially: "
                            "access sensitive data, trigger privileged actions, "
                            "or exploit vulnerabilities in the component's code."
                        ),
                        remediation=(
                            f"Either set android:exported=\"false\" if external access "
                            f"is not needed, or protect the {comp_type} with a custom "
                            f"permission using android:permission."
                        ),
                        file_path="AndroidManifest.xml",
                        code_snippet=f'<{comp_type} android:name="{name}" android:exported="true">',
                        poc_evidence=f"Exported {comp_type} '{name}' has no permission protection",
                        poc_verification=f"1. Use adb to invoke the {comp_type}\n2. Check if it responds without permission\n3. Analyze data returned or actions triggered",
                        poc_commands=[
                            poc_cmd,
                            f"# Use Drozer for deeper analysis:",
                            f"dz> run app.{comp_type}.info -a {app.package_name}",
                        ],
                        cwe_id="CWE-926",
                        cwe_name="Improper Export of Android Application Components",
                        owasp_masvs_category="MASVS-PLATFORM",
                        owasp_masvs_control="MASVS-PLATFORM-1",
                    ))

        return findings

    async def _check_deep_links(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check for insecure deep link configurations."""
        findings = []

        for activity in root.iter("activity"):
            name = activity.get(f"{{{NS['android']}}}name", "")

            for intent_filter in activity.findall("intent-filter"):
                for data in intent_filter.findall("data"):
                    scheme = data.get(f"{{{NS['android']}}}scheme", "")
                    host = data.get(f"{{{NS['android']}}}host", "")

                    # Check for custom schemes (not http/https)
                    if scheme and scheme not in ("http", "https"):
                        findings.append(self.create_finding(
                            app=app,
                            title=f"Custom URL Scheme: {scheme}://",
                            severity="info",
                            category="Deep Links",
                            description=(
                                f"Activity '{name}' handles custom URL scheme '{scheme}://'. "
                                f"Custom schemes can be hijacked by malicious apps."
                            ),
                            impact=(
                                "A malicious app can register the same scheme to intercept "
                                "links intended for this app, potentially stealing data or credentials."
                            ),
                            remediation=(
                                "Consider using App Links (verified https:// links) instead of "
                                "custom schemes. If custom schemes are needed, validate all "
                                "input parameters carefully."
                            ),
                            file_path="AndroidManifest.xml",
                            code_snippet=f'<data android:scheme="{scheme}" android:host="{host or "*"}" />',
                            poc_evidence=f"Custom URL scheme '{scheme}://' registered for activity {name}",
                            poc_verification=f"1. Create test HTML: <a href=\"{scheme}://test\">Test</a>\n2. Open on device\n3. Verify app opens",
                            poc_commands=[
                                f"adb shell am start -W -a android.intent.action.VIEW -d '{scheme}://test'",
                                f"aapt dump badging {app.file_path} | grep -i scheme",
                            ],
                            owasp_masvs_category="MASVS-PLATFORM",
                            owasp_masvs_control="MASVS-PLATFORM-2",
                        ))

        return findings

    async def _check_clear_text_traffic(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check if clear text traffic is allowed."""
        findings = []
        application = root.find("application")

        if application is not None:
            cleartext = application.get(f"{{{NS['android']}}}usesCleartextTraffic")
            if cleartext == "true":
                findings.append(self.create_finding(
                    app=app,
                    title="Clear Text Traffic Allowed",
                    severity="high",
                    category="Network Security",
                    description=(
                        "The application explicitly allows clear text (HTTP) traffic. "
                        "This exposes all network communications to interception."
                    ),
                    impact=(
                        "An attacker on the same network can intercept and modify "
                        "all HTTP traffic, capturing credentials, tokens, and sensitive data."
                    ),
                    remediation=(
                        "Set android:usesCleartextTraffic=\"false\" and use HTTPS for "
                        "all network communications. Configure a Network Security Config "
                        "if specific domains need HTTP."
                    ),
                    file_path="AndroidManifest.xml",
                    code_snippet='android:usesCleartextTraffic="true"',
                    cwe_id="CWE-319",
                    cwe_name="Cleartext Transmission of Sensitive Information",
                    owasp_masvs_category="MASVS-NETWORK",
                    owasp_masvs_control="MASVS-NETWORK-1",
                ))

        return findings

    async def _check_dangerous_permissions(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check for dangerous permissions."""
        findings = []

        dangerous_permissions = {
            "android.permission.READ_CONTACTS": "Access to contacts",
            "android.permission.READ_CALL_LOG": "Access to call history",
            "android.permission.READ_SMS": "Access to SMS messages",
            "android.permission.ACCESS_FINE_LOCATION": "Precise location tracking",
            "android.permission.CAMERA": "Camera access",
            "android.permission.RECORD_AUDIO": "Microphone access",
            "android.permission.READ_EXTERNAL_STORAGE": "External storage read",
            "android.permission.WRITE_EXTERNAL_STORAGE": "External storage write",
        }

        requested_perms = []
        for uses_perm in root.findall("uses-permission"):
            perm = uses_perm.get(f"{{{NS['android']}}}name", "")
            if perm in dangerous_permissions:
                requested_perms.append((perm, dangerous_permissions[perm]))

        if requested_perms:
            perm_list = "\n".join(f"- {p[0]} ({p[1]})" for p in requested_perms)
            perm_xml = "\n".join(f'<uses-permission android:name="{p[0]}" />' for p in requested_perms[:5])
            findings.append(self.create_finding(
                app=app,
                title=f"Dangerous Permissions Requested ({len(requested_perms)})",
                severity="info",
                category="Permissions",
                description=(
                    f"The application requests {len(requested_perms)} dangerous permissions "
                    f"that provide access to sensitive user data:\n{perm_list}"
                ),
                impact=(
                    "These permissions grant access to sensitive user data. "
                    "Verify each permission is necessary and data is handled securely."
                ),
                remediation=(
                    "Review each permission to ensure it's necessary. Request permissions "
                    "at runtime when needed. Minimize data collection and storage."
                ),
                file_path="AndroidManifest.xml",
                code_snippet=perm_xml,
                poc_evidence=f"Dangerous permissions found: {', '.join(p[0].split('.')[-1] for p in requested_perms)}",
                poc_verification="1. Extract AndroidManifest.xml from APK\n2. Search for <uses-permission> tags\n3. Identify dangerous permissions",
                poc_commands=[
                    f"aapt dump permissions {app.file_path}",
                    "aapt dump badging app.apk | grep -i permission",
                ],
                owasp_masvs_category="MASVS-PRIVACY",
                owasp_masvs_control="MASVS-PRIVACY-1",
            ))

        return findings

    async def _check_task_hijacking(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check for task hijacking vulnerabilities."""
        findings = []

        for activity in root.iter("activity"):
            name = activity.get(f"{{{NS['android']}}}name", "")
            launch_mode = activity.get(f"{{{NS['android']}}}launchMode", "")
            task_affinity = activity.get(f"{{{NS['android']}}}taskAffinity")

            if launch_mode in ("singleTask", "singleInstance"):
                if task_affinity is None or task_affinity != "":
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Potential Task Hijacking: {name}",
                        severity="medium",
                        category="Activity Security",
                        description=(
                            f"Activity '{name}' uses launchMode='{launch_mode}' without "
                            f"setting a specific taskAffinity. This may be vulnerable to "
                            f"StrandHogg/task hijacking attacks."
                        ),
                        impact=(
                            "A malicious app can hijack the task and display phishing "
                            "UI that appears to belong to this app, stealing credentials."
                        ),
                        remediation=(
                            "Set android:taskAffinity=\"\" to use a unique task, or "
                            "reconsider the launch mode if not strictly necessary."
                        ),
                        file_path="AndroidManifest.xml",
                        code_snippet=f'<activity android:name="{name}"\n    android:launchMode="{launch_mode}"\n    android:taskAffinity="{task_affinity or "(not set)"}" />',
                        poc_evidence=f"Activity {name} with launchMode={launch_mode} and {'no' if task_affinity is None else 'default'} taskAffinity",
                        poc_verification="1. Create PoC app with same taskAffinity\n2. Launch target app\n3. Launch PoC app\n4. Verify PoC appears in target's task stack",
                        poc_commands=[
                            f"adb shell dumpsys activity activities | grep -A5 {app.package_name}",
                            "# Check task affinity and stack behavior",
                        ],
                        cwe_id="CWE-1021",
                        cwe_name="Improper Restriction of Rendered UI Layers",
                        owasp_masvs_category="MASVS-PLATFORM",
                    ))

        return findings
