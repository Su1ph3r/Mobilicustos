"""Android manifest security analyzer.

Parses and analyzes the ``AndroidManifest.xml`` from APK files to detect
security misconfigurations and vulnerabilities. Uses androguard for binary
XML decoding.

Security checks performed:
    - **Debuggable flag** (CWE-489, MASVS-RESILIENCE-4): Application allows
      debugger attachment in release builds.
    - **Backup enabled** (CWE-530, MASVS-STORAGE-2): Application data can be
      extracted via ``adb backup``.
    - **Exported components** (CWE-926, MASVS-PLATFORM-1): Activities, services,
      receivers, or providers exported without permission protection.
    - **Deep links** (MASVS-PLATFORM-2): Custom URL schemes susceptible to
      hijacking by malicious apps.
    - **Clear text traffic** (CWE-319, MASVS-NETWORK-1): HTTP traffic allowed
      instead of enforcing HTTPS.
    - **Dangerous permissions** (MASVS-PRIVACY-1): Requests for runtime
      permissions that access sensitive user data.
    - **Task hijacking** (CWE-1021, MASVS-PLATFORM): Activities using
      singleTask/singleInstance launch modes without taskAffinity.

OWASP references:
    - OWASP MASVS: MASVS-RESILIENCE, MASVS-STORAGE, MASVS-PLATFORM,
      MASVS-NETWORK, MASVS-PRIVACY
    - OWASP MASTG: MASTG-TEST-0008, MASTG-TEST-0024, MASTG-TEST-0039
"""

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
    """Analyzes AndroidManifest.xml for security misconfigurations.

    Extracts the binary XML manifest from APK files using androguard,
    parses it into an ElementTree, and runs a suite of security checks.
    Each check produces one or more ``Finding`` objects with detailed
    descriptions, PoC commands, remediation guidance, and OWASP/CWE mappings.

    Attributes:
        name: Analyzer identifier used in scan configuration and logging.
        platform: Target platform (``"android"`` only).
    """

    name = "manifest_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Run all manifest security checks against the target application.

        Extracts ``AndroidManifest.xml`` from the APK, decodes the binary XML,
        and executes each check method sequentially.

        Args:
            app: MobileApp ORM model with ``file_path`` pointing to the APK.

        Returns:
            List of Finding objects for all detected issues. Returns an empty
            list if the file path is missing or manifest extraction fails.
        """
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
        """Extract and decode the binary AndroidManifest.xml from an APK.

        Uses androguard's ``AXMLPrinter`` to decode Android's binary XML
        format into a standard XML string suitable for ElementTree parsing.

        Args:
            apk_path: Filesystem path to the APK file.

        Returns:
            Decoded XML string, or None if androguard is not installed or
            extraction fails.
        """
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
        """Check if ``android:debuggable`` is set to true.

        A debuggable application allows JDWP debugger attachment, enabling
        runtime inspection and modification of application state.

        Maps to: CWE-489, MASVS-RESILIENCE-4, MASTG-TEST-0039.
        """
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
                    poc_evidence="Found debuggable=true in manifest. Application allows debugging access.",
                    poc_verification=f"adb shell run-as {app.package_name} ls /data/data/{app.package_name}",
                    poc_commands=[
                        {
                            "type": "adb",
                            "command": "adb jdwp",
                            "description": "List debuggable processes via JDWP",
                        },
                        {
                            "type": "adb",
                            "command": f"adb shell run-as {app.package_name} ls /data/data/{app.package_name}",
                            "description": "Access app's private data directory (only works on debuggable apps)",
                        },
                        {
                            "type": "adb",
                            "command": f"adb shell am set-debug-app -w {app.package_name}",
                            "description": "Set app to wait for debugger on launch",
                        },
                    ],
                    poc_frida_script=f'''// Verify debuggable flag at runtime
Java.perform(function() {{
    var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var appInfo = context.getApplicationInfo();
    var debuggable = (appInfo.flags.value & 2) != 0;  // FLAG_DEBUGGABLE = 2
    console.log("[*] Package: {app.package_name}");
    console.log("[*] Debuggable: " + debuggable);
}});
''',
                    cwe_id="CWE-489",
                    cwe_name="Active Debug Code",
                    cvss_score=7.2,
                    cvss_vector="CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-4",
                    owasp_mastg_test="MASTG-TEST-0039",
                    remediation_commands=[
                        {
                            "type": "android",
                            "command": "buildTypes { release { debuggable false } }",
                            "description": "Set debuggable to false in build.gradle for release builds",
                        },
                    ],
                    remediation_code={
                        "xml": 'android:debuggable="false"',
                        "gradle": "android {\n    buildTypes {\n        release {\n            debuggable false\n        }\n    }\n}",
                    },
                    remediation_resources=[
                        {
                            "title": "OWASP MASTG - Testing for Debugging Symbols",
                            "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039/",
                            "type": "documentation",
                        },
                        {
                            "title": "Android Developer - Configure Build Variants",
                            "url": "https://developer.android.com/build/build-variants",
                            "type": "documentation",
                        },
                    ],
                ))

        return findings

    async def _check_backup_enabled(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check if ``android:allowBackup`` permits ADB data extraction.

        If not explicitly set to ``false``, Android defaults to allowing
        backup (API < 31), enabling extraction of SharedPreferences,
        databases, and internal files via ``adb backup``.

        Maps to: CWE-530, MASVS-STORAGE-2, MASTG-TEST-0008.
        """
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
                    code_snippet=f'android:allowBackup="{backup if backup else "true (default)"}"',
                    poc_evidence=f"allowBackup is {'not set (defaults to true)' if backup is None else 'explicitly set to true'}. Data can be extracted via ADB backup.",
                    poc_verification=f"adb backup -f backup.ab -apk {app.package_name}",
                    poc_commands=[
                        {
                            "type": "adb",
                            "command": f"adb backup -f backup.ab -apk {app.package_name}",
                            "description": "Create backup of app data",
                        },
                        {
                            "type": "bash",
                            "command": "dd if=backup.ab bs=24 skip=1 | python3 -c \"import zlib,sys;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))\" > backup.tar",
                            "description": "Extract backup archive (Android backup format)",
                        },
                        {
                            "type": "bash",
                            "command": "tar -xf backup.tar && find apps -type f -name '*.db' -o -name '*.xml'",
                            "description": "Unpack and search for sensitive data files",
                        },
                    ],
                    cwe_id="CWE-530",
                    cwe_name="Exposure of Backup File to an Unauthorized Control Sphere",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    owasp_masvs_category="MASVS-STORAGE",
                    owasp_masvs_control="MASVS-STORAGE-2",
                    owasp_mastg_test="MASTG-TEST-0008",
                    remediation_commands=[
                        {
                            "type": "android",
                            "command": 'android:allowBackup="false"',
                            "description": "Add to <application> tag in AndroidManifest.xml",
                        },
                    ],
                    remediation_code={
                        "xml": '<application\n    android:allowBackup="false"\n    android:fullBackupContent="false">',
                        "xml-api31": '<application\n    android:allowBackup="false"\n    android:dataExtractionRules="@xml/data_extraction_rules">',
                    },
                    remediation_resources=[
                        {
                            "title": "OWASP MASTG - Testing Backups for Sensitive Data",
                            "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0008/",
                            "type": "documentation",
                        },
                        {
                            "title": "Android Developer - Back up user data",
                            "url": "https://developer.android.com/guide/topics/data/backup",
                            "type": "documentation",
                        },
                    ],
                ))

        return findings

    async def _check_exported_components(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check for exported components (activities, services, receivers,
        providers) that lack permission protection.

        Exported components without ``android:permission`` can be invoked
        by any application on the device, potentially exposing sensitive
        functionality or data.

        Maps to: CWE-926, MASVS-PLATFORM-1, MASTG-TEST-0024.
        """
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

                    # Build PoC commands based on component type
                    poc_cmds = []
                    if comp_type == "activity":
                        poc_cmds = [
                            {
                                "type": "adb",
                                "command": f"adb shell am start -n {app.package_name}/{name}",
                                "description": f"Launch the exported activity",
                            },
                            {
                                "type": "adb",
                                "command": f"adb shell am start -n {app.package_name}/{name} -e secret_data 'test'",
                                "description": "Test passing extra data to the activity",
                            },
                        ]
                    elif comp_type == "service":
                        poc_cmds = [
                            {
                                "type": "adb",
                                "command": f"adb shell am startservice -n {app.package_name}/{name}",
                                "description": "Start the exported service",
                            },
                            {
                                "type": "drozer",
                                "command": f"run app.service.send {app.package_name} {name}",
                                "description": "Send message to service via Drozer",
                            },
                        ]
                    elif comp_type == "receiver":
                        poc_cmds = [
                            {
                                "type": "adb",
                                "command": f"adb shell am broadcast -n {app.package_name}/{name}",
                                "description": "Send broadcast to the receiver",
                            },
                        ]
                    else:  # provider
                        poc_cmds = [
                            {
                                "type": "adb",
                                "command": f"adb shell content query --uri content://{app.package_name}.provider/",
                                "description": "Query the content provider",
                            },
                            {
                                "type": "drozer",
                                "command": f"run app.provider.query content://{app.package_name}.provider/",
                                "description": "Query provider via Drozer for deeper analysis",
                            },
                        ]

                    # Add Drozer analysis command
                    poc_cmds.append({
                        "type": "drozer",
                        "command": f"run app.{comp_type}.info -a {app.package_name}",
                        "description": f"Enumerate {comp_type} details with Drozer",
                    })

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
                        poc_evidence=f"Exported {comp_type} '{name}' has no permission protection. Component can be invoked by any application on the device.",
                        poc_verification=poc_cmds[0]["command"] if poc_cmds else None,
                        poc_commands=poc_cmds,
                        cwe_id="CWE-926",
                        cwe_name="Improper Export of Android Application Components",
                        cvss_score=6.5 if comp_type in ("service", "provider") else 5.3,
                        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if comp_type == "provider" else "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        owasp_masvs_category="MASVS-PLATFORM",
                        owasp_masvs_control="MASVS-PLATFORM-1",
                        owasp_mastg_test="MASTG-TEST-0024",
                        remediation_commands=[
                            {
                                "type": "android",
                                "command": f'android:exported="false"',
                                "description": f"Add to {comp_type} declaration if external access not needed",
                            },
                            {
                                "type": "android",
                                "command": f'android:permission="{app.package_name}.permission.ACCESS_{comp_type.upper()}"',
                                "description": f"Protect with custom permission if external access is required",
                            },
                        ],
                        remediation_code={
                            "xml": f'<{comp_type}\n    android:name="{name}"\n    android:exported="false" />',
                            "xml-protected": f'<{comp_type}\n    android:name="{name}"\n    android:exported="true"\n    android:permission="{app.package_name}.permission.ACCESS" />',
                        },
                        remediation_resources=[
                            {
                                "title": "OWASP MASTG - Testing for Vulnerable IPC",
                                "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0024/",
                                "type": "documentation",
                            },
                            {
                                "title": "Android Developer - App Manifest Overview",
                                "url": "https://developer.android.com/guide/topics/manifest/manifest-intro",
                                "type": "documentation",
                            },
                        ],
                    ))

        return findings

    async def _check_deep_links(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check for custom URL scheme deep links that can be hijacked.

        Custom URL schemes (non-http/https) can be registered by any app,
        allowing malicious apps to intercept links intended for this
        application.

        Maps to: MASVS-PLATFORM-2.
        """
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
                                {"type": "adb", "command": f"adb shell am start -W -a android.intent.action.VIEW -d '{scheme}://test'", "description": "Test deep link handler"},
                                {"type": "bash", "command": f"aapt dump badging {app.file_path} | grep -i scheme", "description": "List registered URL schemes"},
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
        """Check if ``android:usesCleartextTraffic`` allows HTTP connections.

        When set to true, the application can make unencrypted HTTP requests,
        exposing network traffic to interception and tampering.

        Maps to: CWE-319, MASVS-NETWORK-1.
        """
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
                        "The application explicitly allows clear text (HTTP) traffic via "
                        "android:usesCleartextTraffic=\"true\" in AndroidManifest.xml. "
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
                    poc_evidence="android:usesCleartextTraffic=\"true\" found in AndroidManifest.xml",
                    poc_verification=(
                        "1. Set up mitmproxy on port 8080\n"
                        "2. Configure device proxy to point to mitmproxy\n"
                        "3. Use the app and observe unencrypted HTTP requests in mitmproxy"
                    ),
                    poc_commands=[
                        {"type": "bash", "command": "mitmproxy -p 8080", "description": "Start mitmproxy to intercept HTTP traffic"},
                        {"type": "adb", "command": "adb shell settings put global http_proxy 127.0.0.1:8080", "description": "Set device proxy"},
                        {"type": "bash", "command": f"aapt dump xmltree {app.file_path or 'app.apk'} AndroidManifest.xml | grep -i cleartext", "description": "Verify cleartext traffic setting"},
                    ],
                ))

        return findings

    async def _check_dangerous_permissions(
        self,
        app: MobileApp,
        root: ET.Element,
    ) -> list[Finding]:
        """Check for dangerous runtime permissions that access sensitive data.

        Identifies requests for permissions such as READ_CONTACTS, CAMERA,
        RECORD_AUDIO, ACCESS_FINE_LOCATION, etc. that require user consent
        and grant access to personal information.

        Maps to: MASVS-PRIVACY-1.
        """
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
            perm_xml = "\n".join(f'<uses-permission android:name="{p[0]}" />' for p in requested_perms)
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
                    {"type": "bash", "command": f"aapt dump permissions {app.file_path}", "description": "List all requested permissions"},
                    {"type": "bash", "command": f"aapt dump badging {app.file_path} | grep -i permission", "description": "Show permission details from APK"},
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
        """Check for StrandHogg-style task hijacking vulnerabilities.

        Activities using ``singleTask`` or ``singleInstance`` launch mode
        without an explicit empty ``taskAffinity`` may be vulnerable to task
        hijacking, where a malicious app inserts phishing UI into the
        target's task stack.

        Maps to: CWE-1021, MASVS-PLATFORM.
        """
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
                            {"type": "adb", "command": f"adb shell dumpsys activity activities | grep -A5 {app.package_name}", "description": "Check task affinity and stack behavior"},
                        ],
                        cwe_id="CWE-1021",
                        cwe_name="Improper Restriction of Rendered UI Layers",
                        owasp_masvs_category="MASVS-PLATFORM",
                    ))

        return findings
