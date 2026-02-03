"""iOS plist analyzer for Info.plist and entitlements."""

import logging
import plistlib
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class PlistAnalyzer(BaseAnalyzer):
    """Analyzes iOS Info.plist and entitlements for security issues."""

    name = "plist_analyzer"
    platform = "ios"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze iOS plists."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            info_plist, entitlements = await self._extract_plists(Path(app.file_path))

            if info_plist:
                findings.extend(await self._check_ats_config(app, info_plist))
                findings.extend(await self._check_url_schemes(app, info_plist))
                findings.extend(await self._check_permissions(app, info_plist))

            if entitlements:
                findings.extend(await self._check_entitlements(app, entitlements))

        except Exception as e:
            logger.error(f"Plist analysis failed: {e}")

        return findings

    async def _extract_plists(
        self,
        ipa_path: Path,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Extract Info.plist and entitlements from IPA."""
        info_plist = None
        entitlements = None

        try:
            with zipfile.ZipFile(ipa_path, "r") as ipa:
                for name in ipa.namelist():
                    if name.endswith("Info.plist") and "Payload/" in name:
                        data = ipa.read(name)
                        info_plist = plistlib.loads(data)
                        # Store raw XML for code snippets
                        try:
                            info_plist["_raw_xml"] = data.decode("utf-8", errors="ignore")
                        except Exception:
                            info_plist["_raw_xml"] = ""

                    if "embedded.mobileprovision" in name:
                        data = ipa.read(name)
                        entitlements = await self._extract_entitlements(data)

        except Exception as e:
            logger.error(f"Failed to extract plists: {e}")

        return info_plist, entitlements

    async def _extract_entitlements(
        self,
        provision_data: bytes,
    ) -> dict[str, Any] | None:
        """Extract entitlements from provisioning profile."""
        try:
            start = provision_data.find(b"<?xml")
            end = provision_data.find(b"</plist>") + len(b"</plist>")

            if start > 0 and end > start:
                plist_data = provision_data[start:end]
                plist = plistlib.loads(plist_data)
                return plist.get("Entitlements", {})

        except Exception as e:
            logger.error(f"Failed to extract entitlements: {e}")

        return None

    async def _check_ats_config(
        self,
        app: MobileApp,
        info_plist: dict[str, Any],
    ) -> list[Finding]:
        """Check App Transport Security configuration."""
        findings: list[Finding] = []

        ats = info_plist.get("NSAppTransportSecurity", {})

        if ats.get("NSAllowsArbitraryLoads", False):
            findings.append(self.create_finding(
                app=app,
                title="App Transport Security Disabled",
                severity="high",
                category="Network Security",
                description="NSAllowsArbitraryLoads is set to YES, completely disabling App Transport Security. This allows the app to make insecure HTTP connections.",
                impact="All network traffic can be sent over unencrypted HTTP, exposing sensitive data to man-in-the-middle attacks.",
                remediation="Remove NSAllowsArbitraryLoads or set it to NO. Use NSExceptionDomains for specific legacy servers that require HTTP.",
                file_path="Info.plist",
                code_snippet='''<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>''',
                poc_evidence="NSAllowsArbitraryLoads is set to true in Info.plist",
                poc_verification="1. Unzip IPA: unzip app.ipa -d extracted\n2. Open Info.plist: plutil -p extracted/Payload/*.app/Info.plist\n3. Find NSAppTransportSecurity section\n4. Verify NSAllowsArbitraryLoads is true",
                poc_commands=[
                    f"unzip -o {app.file_path} -d /tmp/extracted",
                    "plutil -p /tmp/extracted/Payload/*.app/Info.plist | grep -A5 NSAppTransportSecurity",
                    "plutil -extract NSAppTransportSecurity xml1 -o - /tmp/extracted/Payload/*.app/Info.plist",
                ],
                cwe_id="CWE-319",
                owasp_masvs_category="MASVS-NETWORK",
            ))

        exceptions = ats.get("NSExceptionDomains", {})
        insecure_domains = [
            d for d, c in exceptions.items()
            if c.get("NSExceptionAllowsInsecureHTTPLoads", False)
        ]

        if insecure_domains:
            domain_xml = "\n".join(f'''    <key>{d}</key>
    <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
    </dict>''' for d in insecure_domains[:5])
            findings.append(self.create_finding(
                app=app,
                title=f"ATS Exceptions for {len(insecure_domains)} Domain(s)",
                severity="medium",
                category="Network Security",
                description=f"Domains with HTTP allowed:\n" + "\n".join(f"- {d}" for d in insecure_domains),
                impact="Traffic to these domains is not protected by ATS and can be intercepted by attackers.",
                remediation="Ensure exceptions are necessary and use HTTPS where possible. Request server admins to enable HTTPS.",
                file_path="Info.plist",
                code_snippet=f'''<key>NSExceptionDomains</key>
<dict>
{domain_xml}
</dict>''',
                poc_evidence=f"ATS exceptions found for: {', '.join(insecure_domains)}",
                poc_verification="1. Extract IPA\n2. Check Info.plist NSExceptionDomains\n3. Verify each domain truly requires HTTP",
                poc_commands=[
                    f"unzip -o {app.file_path} -d /tmp/extracted",
                    "plutil -p /tmp/extracted/Payload/*.app/Info.plist | grep -A20 NSExceptionDomains",
                ],
                owasp_masvs_category="MASVS-NETWORK",
            ))

        return findings

    async def _check_url_schemes(
        self,
        app: MobileApp,
        info_plist: dict[str, Any],
    ) -> list[Finding]:
        """Check for custom URL schemes."""
        findings: list[Finding] = []

        url_types = info_plist.get("CFBundleURLTypes", [])
        schemes = []

        for url_type in url_types:
            for scheme in url_type.get("CFBundleURLSchemes", []):
                schemes.append(scheme)

        if schemes:
            scheme_xml = "\n".join(f"        <string>{s}</string>" for s in schemes)
            findings.append(self.create_finding(
                app=app,
                title=f"Custom URL Schemes Registered ({len(schemes)})",
                severity="info",
                category="Deep Links",
                description="URL schemes:\n" + "\n".join(f"- {s}://" for s in schemes),
                impact="Custom URL schemes can be hijacked by malicious apps that register the same scheme. Sensitive parameters in URLs may be exposed.",
                remediation="Consider using Universal Links instead for secure deep linking. Validate all URL parameters before processing.",
                file_path="Info.plist",
                code_snippet=f'''<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
{scheme_xml}
        </array>
    </dict>
</array>''',
                poc_evidence=f"URL schemes registered: {', '.join(schemes)}",
                poc_verification="1. Extract IPA and check Info.plist\n2. Test each scheme with: safari open <scheme>://test\n3. Check if app handles malformed URLs safely",
                poc_commands=[
                    f"unzip -o {app.file_path} -d /tmp/extracted",
                    "plutil -p /tmp/extracted/Payload/*.app/Info.plist | grep -A10 CFBundleURLTypes",
                    f"# Test with: xcrun simctl openurl booted '{schemes[0]}://test'",
                ],
                owasp_masvs_category="MASVS-PLATFORM",
            ))

        return findings

    async def _check_permissions(
        self,
        app: MobileApp,
        info_plist: dict[str, Any],
    ) -> list[Finding]:
        """Check for sensitive permission usage descriptions."""
        findings: list[Finding] = []

        sensitive_permissions = {
            "NSCameraUsageDescription": "Camera access",
            "NSMicrophoneUsageDescription": "Microphone access",
            "NSLocationWhenInUseUsageDescription": "Location (when in use)",
            "NSLocationAlwaysUsageDescription": "Location (always)",
            "NSContactsUsageDescription": "Contacts access",
        }

        requested_perms = [
            (desc, info_plist[key])
            for key, desc in sensitive_permissions.items()
            if key in info_plist
        ]

        if requested_perms:
            perm_list = "\n".join(f"- {p[0]}: \"{p[1]}\"" for p in requested_perms)
            perm_xml = "\n".join(f"<key>{key}</key>\n<string>{info_plist[key]}</string>"
                                  for key, _ in sensitive_permissions.items() if key in info_plist)
            findings.append(self.create_finding(
                app=app,
                title=f"Sensitive Permissions Requested ({len(requested_perms)})",
                severity="info",
                category="Permissions",
                description=f"The app requests access to sensitive device capabilities:\n\n{perm_list}",
                impact="Each permission grants access to sensitive user data. Review if all permissions are necessary for app functionality.",
                remediation="Only request permissions that are essential. Use purpose strings that clearly explain why the permission is needed.",
                file_path="Info.plist",
                code_snippet=perm_xml,
                poc_evidence=f"App requests {len(requested_perms)} sensitive permission(s)",
                poc_verification="1. Install app on device\n2. Navigate to Settings > Privacy\n3. Verify app appears under each requested permission category\n4. Test app behavior when permissions are denied",
                poc_commands=[
                    f"unzip -o {app.file_path} -d /tmp/extracted",
                    "plutil -p /tmp/extracted/Payload/*.app/Info.plist | grep -i usage",
                ],
                owasp_masvs_category="MASVS-PRIVACY",
            ))

        return findings

    async def _check_entitlements(
        self,
        app: MobileApp,
        entitlements: dict[str, Any],
    ) -> list[Finding]:
        """Check entitlements for security issues."""
        findings: list[Finding] = []

        if entitlements.get("get-task-allow", False):
            findings.append(self.create_finding(
                app=app,
                title="Debug Entitlement Enabled (get-task-allow)",
                severity="high",
                category="Entitlements",
                description="The get-task-allow entitlement is set to true, indicating this is a development build. This entitlement allows debugger attachment.",
                impact="Attackers can attach a debugger (lldb/gdb) to inspect memory, modify runtime behavior, and bypass security controls.",
                remediation="Ensure release builds don't include get-task-allow. Use Xcode Archive for App Store builds which strips this entitlement.",
                file_path="embedded.mobileprovision",
                code_snippet='''<key>get-task-allow</key>
<true/>''',
                poc_evidence="get-task-allow entitlement is enabled",
                poc_verification="1. Extract IPA\n2. Check embedded.mobileprovision\n3. Verify get-task-allow value",
                poc_commands=[
                    f"unzip -o {app.file_path} -d /tmp/extracted",
                    "security cms -D -i /tmp/extracted/Payload/*.app/embedded.mobileprovision | grep -A2 get-task-allow",
                    "# Attach debugger: lldb -n <process_name>",
                ],
                owasp_masvs_category="MASVS-RESILIENCE",
            ))

        keychain_groups = entitlements.get("keychain-access-groups", [])
        if keychain_groups:
            groups_xml = "\n".join(f"    <string>{g}</string>" for g in keychain_groups)
            findings.append(self.create_finding(
                app=app,
                title=f"Keychain Access Groups ({len(keychain_groups)})",
                severity="info",
                category="Entitlements",
                description="Keychain groups:\n" + "\n".join(f"- {g}" for g in keychain_groups),
                impact="Keychain groups allow data sharing between apps from the same developer. Ensure shared data is properly protected.",
                remediation="Review if keychain sharing is necessary. Use unique access groups for sensitive data that shouldn't be shared.",
                file_path="embedded.mobileprovision",
                code_snippet=f'''<key>keychain-access-groups</key>
<array>
{groups_xml}
</array>''',
                poc_evidence=f"Keychain access groups: {', '.join(keychain_groups)}",
                poc_verification="1. Install app\n2. Use Keychain-Dumper on jailbroken device\n3. Check for shared keychain items",
                poc_commands=[
                    "security cms -D -i /tmp/extracted/Payload/*.app/embedded.mobileprovision | grep -A10 keychain-access-groups",
                    "# On jailbroken device: keychain-dumper",
                ],
                owasp_masvs_category="MASVS-STORAGE",
            ))

        return findings
