"""Android component security analyzer for manifest and intent vulnerabilities.

Performs in-depth analysis of Android application component declarations
in AndroidManifest.xml and source code to detect access control failures,
permission misconfigurations, and intent-based attack vectors.

Security checks performed:
    - **Custom Permission Protection Level**: Identifies custom permissions
      declared with "normal" or "dangerous" protectionLevel instead of
      "signature", allowing any app to obtain the permission.
    - **Exported Components Without Permissions**: Detects services,
      content providers, activities, and broadcast receivers that are
      exported (explicitly or via intent-filters) without requiring
      a permission for access.
    - **PendingIntent Vulnerabilities**: Scans source code for PendingIntents
      wrapping implicit intents (no target component), missing
      FLAG_IMMUTABLE, or use of FLAG_MUTABLE that enables hijacking.
    - **Implicit Intent for Sensitive Operations**: Detects use of implicit
      intents for login, auth, payment, and admin operations that can be
      intercepted by malicious intent filter registrations.

OWASP references:
    - MASVS-PLATFORM: Platform Interaction
    - MASVS-PLATFORM-1: Testing App Permissions
    - MASTG-TEST-0024: Testing for Improper Platform Usage
    - CWE-926: Improper Export of Android Application Components
    - CWE-927: Use of Implicit Intent for Sensitive Communication
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

# Protection level values
WEAK_PROTECTION_LEVELS = {"normal", "dangerous"}
STRONG_PROTECTION_LEVELS = {"signature", "signatureOrSystem"}


class ComponentSecurityAnalyzer(BaseAnalyzer):
    """Analyzes Android component security configuration.

    Parses AndroidManifest.xml to check custom permission definitions,
    exported component access controls, and scans source code for
    PendingIntent and implicit intent vulnerabilities.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform ("android").
    """

    name = "component_security_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze Android component security configuration.

        Args:
            app: The mobile application to analyze.

        Returns:
            A list of Finding objects covering custom permissions,
            exported components, PendingIntents, and implicit intents.
        """
        if not app.file_path:
            return []

        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="comp_sec_"))
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

            # Check custom permissions with wrong protectionLevel
            findings.extend(self._check_custom_permissions(root, app))

            # Check exported components without permissions
            findings.extend(self._check_exported_components(root, app))

            # Check for PendingIntent vulnerabilities
            findings.extend(await self._check_pending_intents(extracted_path, app))

            # Check for implicit intent vulnerabilities
            findings.extend(await self._check_implicit_intents(extracted_path, app))

            return findings

        except Exception as e:
            logger.error(f"Component security analysis failed: {e}")
            return []
        finally:
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    def _check_custom_permissions(self, root: ET.Element, app: MobileApp) -> list[Finding]:
        """Check custom permission definitions for weak protectionLevel.

        Identifies non-system permissions declared with "normal" or
        "dangerous" protectionLevel and recommends "signature" level.

        Args:
            root: Parsed XML root of AndroidManifest.xml.
            app: The mobile application being analyzed.

        Returns:
            A list of Finding objects for weak custom permissions.
        """
        findings = []

        for permission in root.iter("permission"):
            perm_name = permission.get(f"{{{NS['android']}}}name", "")
            if not perm_name:
                perm_name = permission.get("name", "")

            protection_level = permission.get(f"{{{NS['android']}}}protectionLevel", "normal")
            if not protection_level:
                protection_level = permission.get("protectionLevel", "normal")

            # Skip system permissions
            if perm_name.startswith("android.permission"):
                continue

            if protection_level.lower() in WEAK_PROTECTION_LEVELS:
                findings.append(self.create_finding(
                    app=app,
                    title=f"Custom Permission with Weak Protection Level: {perm_name}",
                    description=(
                        f"The custom permission '{perm_name}' is declared with "
                        f"protectionLevel=\"{protection_level}\". "
                        f"{'Normal permissions are automatically granted without user consent. ' if protection_level == 'normal' else ''}"
                        f"{'Dangerous permissions only require user approval, which can be socially engineered. ' if protection_level == 'dangerous' else ''}"
                        "Any app can request and obtain this permission."
                    ),
                    severity="medium",
                    category="Component Security",
                    impact=(
                        "Any application can declare this permission in its manifest and gain "
                        "access to the protected components. This effectively provides no "
                        "meaningful access control against malicious apps."
                    ),
                    remediation=(
                        f"Change the protectionLevel to 'signature' to ensure only apps signed "
                        f"with the same certificate can use this permission:\n\n"
                        f'<permission\n'
                        f'    android:name="{perm_name}"\n'
                        f'    android:protectionLevel="signature" />'
                    ),
                    file_path="AndroidManifest.xml",
                    code_snippet=f'<permission android:name="{perm_name}" android:protectionLevel="{protection_level}" />',
                    cwe_id="CWE-926",
                    cwe_name="Improper Export of Android Application Components",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    owasp_masvs_category="MASVS-PLATFORM",
                    owasp_masvs_control="MASVS-PLATFORM-1",
                    owasp_mastg_test="MASTG-TEST-0024",
                    poc_commands=[
                        {
                            "type": "bash",
                            "command": f"aapt dump permissions {app.file_path}",
                            "description": "List all defined and requested permissions",
                        },
                        {
                            "type": "adb",
                            "command": f"adb shell dumpsys package {app.package_name} | grep -A5 permission",
                            "description": "Check runtime permission grants",
                        },
                    ],
                    remediation_code={
                        "xml": (
                            f'<permission\n'
                            f'    android:name="{perm_name}"\n'
                            f'    android:protectionLevel="signature"\n'
                            f'    android:label="@string/perm_label"\n'
                            f'    android:description="@string/perm_desc" />'
                        ),
                    },
                ))

        return findings

    def _check_exported_components(self, root: ET.Element, app: MobileApp) -> list[Finding]:
        """Check for exported components without proper permission protection.

        Enumerates activities, services, receivers, and content providers.
        Separates high-risk (services, providers) from medium-risk
        (activities, receivers) exported components.

        Args:
            root: Parsed XML root of AndroidManifest.xml.
            app: The mobile application being analyzed.

        Returns:
            A list of Finding objects grouped by risk level.
        """
        findings = []

        component_types = {
            "activity": "Activity",
            "service": "Service",
            "receiver": "Broadcast Receiver",
            "provider": "Content Provider",
        }

        exported_without_perm = []

        for comp_tag, comp_name in component_types.items():
            for component in root.iter(comp_tag):
                name = component.get(f"{{{NS['android']}}}name", "")
                if not name:
                    name = component.get("name", "")

                exported_attr = component.get(f"{{{NS['android']}}}exported")
                permission = component.get(f"{{{NS['android']}}}permission")

                # Check if has intent-filter (implicitly exported pre-Android 12)
                has_intent_filter = component.find("intent-filter") is not None

                is_exported = False
                if exported_attr is not None:
                    is_exported = exported_attr.lower() == "true"
                elif has_intent_filter:
                    is_exported = True  # Implicitly exported

                if is_exported and not permission:
                    # For providers, also check readPermission/writePermission
                    if comp_tag == "provider":
                        read_perm = component.get(f"{{{NS['android']}}}readPermission")
                        write_perm = component.get(f"{{{NS['android']}}}writePermission")
                        if read_perm or write_perm:
                            continue

                    exported_without_perm.append({
                        "type": comp_tag,
                        "type_name": comp_name,
                        "name": name,
                        "has_intent_filter": has_intent_filter,
                        "explicitly_exported": exported_attr is not None,
                    })

        if exported_without_perm:
            # Group by severity
            high_risk = [c for c in exported_without_perm if c["type"] in ("service", "provider")]
            medium_risk = [c for c in exported_without_perm if c["type"] in ("activity", "receiver")]

            if high_risk:
                component_list = "\n".join(
                    f"- [{c['type_name']}] {c['name']}"
                    for c in high_risk[:15]
                )
                findings.append(self.create_finding(
                    app=app,
                    title=f"High-Risk Exported Components Without Permission ({len(high_risk)})",
                    description=(
                        "The following services and content providers are exported without "
                        "permission protection:\n\n"
                        f"{component_list}\n\n"
                        "Any app can interact with these components, potentially accessing "
                        "sensitive data or triggering privileged operations."
                    ),
                    severity="high",
                    category="Component Security",
                    impact=(
                        "Exported services can be started/bound by malicious apps to abuse functionality. "
                        "Exported content providers can leak or allow modification of application data."
                    ),
                    remediation=(
                        '1. Set android:exported="false" if external access is not needed\n'
                        '2. Add android:permission with signature-level protection\n'
                        '3. Validate caller identity in component code'
                    ),
                    file_path="AndroidManifest.xml",
                    cwe_id="CWE-926",
                    cwe_name="Improper Export of Android Application Components",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    owasp_masvs_category="MASVS-PLATFORM",
                    owasp_masvs_control="MASVS-PLATFORM-1",
                    owasp_mastg_test="MASTG-TEST-0024",
                    poc_commands=[
                        {
                            "type": "adb",
                            "command": f"adb shell dumpsys package {app.package_name} | grep -A2 'exported=true'",
                            "description": "List exported components",
                        },
                    ],
                ))

            if medium_risk:
                component_list = "\n".join(
                    f"- [{c['type_name']}] {c['name']}"
                    for c in medium_risk[:15]
                )
                findings.append(self.create_finding(
                    app=app,
                    title=f"Exported Activities/Receivers Without Permission ({len(medium_risk)})",
                    description=(
                        "The following activities and broadcast receivers are exported without "
                        "permission protection:\n\n"
                        f"{component_list}"
                    ),
                    severity="medium",
                    category="Component Security",
                    impact=(
                        "Exported activities can be launched by other apps, potentially bypassing "
                        "authentication or displaying unintended screens. Broadcast receivers "
                        "can be triggered with crafted intents."
                    ),
                    remediation=(
                        '1. Set android:exported="false" if not needed\n'
                        "2. Add permission protection for sensitive activities\n"
                        "3. Validate intent data in activity's onCreate"
                    ),
                    file_path="AndroidManifest.xml",
                    cwe_id="CWE-926",
                    cwe_name="Improper Export of Android Application Components",
                    cvss_score=5.3,
                    owasp_masvs_category="MASVS-PLATFORM",
                    owasp_masvs_control="MASVS-PLATFORM-1",
                ))

        return findings

    async def _check_pending_intents(self, extracted_path: Path, app: MobileApp) -> list[Finding]:
        """Check for PendingIntent vulnerabilities in source code.

        Detects PendingIntents wrapping implicit intents (no explicit
        target component), missing FLAG_IMMUTABLE, and use of
        FLAG_MUTABLE that allows intent modification by recipients.

        Args:
            extracted_path: Root directory of the extracted APK.
            app: The mobile application being analyzed.

        Returns:
            A list of Finding objects for PendingIntent issues.
        """
        findings = []

        # Patterns for unsafe PendingIntent usage
        unsafe_patterns = [
            # PendingIntent with implicit intent (no component specified)
            (r'PendingIntent\.get(?:Activity|Service|Broadcast)\s*\([^)]*new\s+Intent\s*\(\s*["\'][^"\']*["\']\s*\)',
             "PendingIntent with implicit Intent action"),
            # PendingIntent without FLAG_IMMUTABLE (Android 12+ requirement)
            (r'PendingIntent\.get(?:Activity|Service|Broadcast)\s*\([^)]*(?!FLAG_IMMUTABLE)',
             "PendingIntent potentially missing FLAG_IMMUTABLE"),
            # Mutable PendingIntent
            (r'PendingIntent\.FLAG_MUTABLE',
             "Mutable PendingIntent (writable by recipients)"),
        ]

        vulnerable_locations = []

        for ext in [".java", ".kt"]:
            for source_file in extracted_path.rglob(f"*{ext}"):
                try:
                    content = source_file.read_text(errors='ignore')
                    if "PendingIntent" not in content:
                        continue

                    rel_path = str(source_file.relative_to(extracted_path))

                    for pattern, desc in unsafe_patterns:
                        for match in re.finditer(pattern, content, re.DOTALL):
                            line_num = content[:match.start()].count('\n') + 1
                            vulnerable_locations.append({
                                "file": rel_path,
                                "line": line_num,
                                "type": desc,
                                "snippet": content.split('\n')[max(0, line_num - 2):line_num + 2],
                            })

                except Exception:
                    pass

        if vulnerable_locations:
            location_summary = "\n".join(
                f"- {loc['file']}:{loc['line']} ({loc['type']})"
                for loc in vulnerable_locations[:10]
            )

            findings.append(self.create_finding(
                app=app,
                title=f"PendingIntent Vulnerabilities ({len(vulnerable_locations)} instances)",
                description=(
                    "Potentially unsafe PendingIntent usage detected:\n\n"
                    f"{location_summary}\n\n"
                    "PendingIntents wrapping implicit intents or missing FLAG_IMMUTABLE "
                    "can be hijacked by malicious apps."
                ),
                severity="high",
                category="Component Security",
                impact=(
                    "A malicious app can intercept or modify the PendingIntent, redirecting "
                    "it to a different component. This can lead to privilege escalation, "
                    "data theft, or unauthorized actions performed with the sender's identity."
                ),
                remediation=(
                    "1. Use explicit intents (specify target component) in PendingIntents\n"
                    "2. Add PendingIntent.FLAG_IMMUTABLE for all PendingIntents (Android 12+)\n"
                    "3. Never embed sensitive data in PendingIntent extras"
                ),
                file_path=vulnerable_locations[0]["file"],
                line_number=vulnerable_locations[0]["line"],
                cwe_id="CWE-926",
                cwe_name="Improper Export of Android Application Components",
                cvss_score=7.8,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                owasp_masvs_category="MASVS-PLATFORM",
                owasp_masvs_control="MASVS-PLATFORM-1",
                remediation_code={
                    "kotlin": (
                        "// Safe PendingIntent usage\n"
                        "val intent = Intent(context, TargetActivity::class.java)\n"
                        "val pendingIntent = PendingIntent.getActivity(\n"
                        "    context, 0, intent,\n"
                        "    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT\n"
                        ")"
                    ),
                },
            ))

        return findings

    async def _check_implicit_intents(self, extracted_path: Path, app: MobileApp) -> list[Finding]:
        """Check for implicit intents used for sensitive operations.

        Detects implicit intent construction for login, auth, payment,
        transfer, admin, and settings actions, as well as sendBroadcast
        and startService with implicit intents.

        Args:
            extracted_path: Root directory of the extracted APK.
            app: The mobile application being analyzed.

        Returns:
            A list of Finding objects for implicit intent misuse.
        """
        findings = []

        sensitive_intent_patterns = [
            (r'new\s+Intent\s*\(\s*["\'](?:.*(?:login|auth|pay|transfer|admin|settings))["\']\s*\)',
             "Sensitive operation via implicit intent"),
            (r'sendBroadcast\s*\(\s*(?:new\s+)?Intent\s*\(\s*["\']',
             "Broadcast with implicit intent"),
            (r'startService\s*\(\s*(?:new\s+)?Intent\s*\(\s*["\']',
             "Service started with implicit intent"),
        ]

        implicit_issues = []

        for ext in [".java", ".kt"]:
            for source_file in extracted_path.rglob(f"*{ext}"):
                try:
                    content = source_file.read_text(errors='ignore')
                    rel_path = str(source_file.relative_to(extracted_path))

                    for pattern, desc in sensitive_intent_patterns:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            line_num = content[:match.start()].count('\n') + 1
                            implicit_issues.append({
                                "file": rel_path,
                                "line": line_num,
                                "type": desc,
                            })

                except Exception:
                    pass

        if implicit_issues:
            issue_list = "\n".join(
                f"- {i['file']}:{i['line']} ({i['type']})"
                for i in implicit_issues[:10]
            )

            findings.append(self.create_finding(
                app=app,
                title=f"Implicit Intents for Sensitive Operations ({len(implicit_issues)} instances)",
                description=(
                    "Implicit intents are used for potentially sensitive operations:\n\n"
                    f"{issue_list}\n\n"
                    "Implicit intents can be intercepted by any app that registers a matching "
                    "intent filter."
                ),
                severity="medium",
                category="Component Security",
                impact=(
                    "Sensitive data or operations may be intercepted by malicious apps "
                    "that register matching intent filters."
                ),
                remediation=(
                    "1. Use explicit intents by specifying the target component\n"
                    "2. For broadcasts, use LocalBroadcastManager or specify the package\n"
                    "3. Add permissions to restrict intent receivers"
                ),
                cwe_id="CWE-927",
                cwe_name="Use of Implicit Intent for Sensitive Communication",
                cvss_score=5.3,
                owasp_masvs_category="MASVS-PLATFORM",
                owasp_masvs_control="MASVS-PLATFORM-1",
            ))

        return findings
