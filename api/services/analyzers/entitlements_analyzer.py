"""iOS Entitlements analyzer for comprehensive entitlements security checks."""

import logging
import plistlib
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


# Entitlement security configurations
ENTITLEMENT_CHECKS = {
    # Critical Security Entitlements
    "get-task-allow": {
        "severity": "critical",
        "category": "Debug Configuration",
        "title": "Debugging Enabled (get-task-allow)",
        "description": (
            "The get-task-allow entitlement is enabled, which allows other processes "
            "to attach a debugger to the application. This should only be enabled in "
            "development builds."
        ),
        "impact": (
            "Attackers can attach debuggers to the running application to inspect "
            "memory, modify variables, and bypass security controls at runtime."
        ),
        "remediation": (
            "Ensure get-task-allow is set to false in production builds:\n"
            "1. Use separate provisioning profiles for development and production\n"
            "2. Verify entitlements in Archive builds\n"
            "3. Add CI/CD checks to verify production entitlements"
        ),
        "trigger_value": True,
        "cwe_id": "CWE-489",
        "cwe_name": "Active Debug Code",
        "masvs": "MASVS-RESILIENCE",
        "mastg": "MSTG-CODE-2",
    },
    "com.apple.security.cs.disable-library-validation": {
        "severity": "high",
        "category": "Code Signing",
        "title": "Library Validation Disabled",
        "description": (
            "The application has disabled library validation, allowing it to load "
            "unsigned or incorrectly signed libraries."
        ),
        "impact": (
            "Attackers can inject malicious code by placing unsigned dylibs in "
            "locations the app will load from, bypassing code signing protections."
        ),
        "remediation": (
            "Remove this entitlement unless absolutely necessary. If required:\n"
            "1. Document why it's needed\n"
            "2. Implement additional runtime integrity checks\n"
            "3. Verify library sources before loading"
        ),
        "trigger_value": True,
        "cwe_id": "CWE-829",
        "cwe_name": "Inclusion of Functionality from Untrusted Control Sphere",
        "masvs": "MASVS-RESILIENCE",
        "mastg": "MSTG-CODE-2",
    },
    "com.apple.security.cs.allow-unsigned-executable-memory": {
        "severity": "high",
        "category": "Memory Security",
        "title": "Unsigned Executable Memory Allowed",
        "description": (
            "The application can execute code from unsigned memory regions, "
            "weakening the hardened runtime protection."
        ),
        "impact": (
            "Attackers can exploit memory corruption vulnerabilities more easily "
            "as they can execute shellcode from writable memory regions."
        ),
        "remediation": (
            "Remove this entitlement and refactor code to not require JIT compilation "
            "or dynamic code execution. If needed for specific features, isolate "
            "that functionality."
        ),
        "trigger_value": True,
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within Memory Buffer",
        "masvs": "MASVS-RESILIENCE",
        "mastg": "MSTG-CODE-9",
    },
    "com.apple.security.cs.allow-jit": {
        "severity": "medium",
        "category": "Memory Security",
        "title": "JIT Compilation Allowed",
        "description": (
            "The application has permission to use Just-In-Time (JIT) compilation, "
            "which allows creating executable memory at runtime."
        ),
        "impact": (
            "While necessary for some applications (like JavaScript engines), JIT "
            "can be exploited by attackers to execute arbitrary code if they can "
            "control JIT inputs."
        ),
        "remediation": (
            "Only enable if absolutely necessary (e.g., for JS engines). Ensure:\n"
            "1. JIT inputs are thoroughly validated\n"
            "2. The JIT engine is kept up-to-date\n"
            "3. Additional sandboxing is in place"
        ),
        "trigger_value": True,
        "cwe_id": "CWE-94",
        "cwe_name": "Improper Control of Generation of Code",
        "masvs": "MASVS-RESILIENCE",
        "mastg": "MSTG-CODE-9",
    },
    "com.apple.security.cs.disable-executable-page-protection": {
        "severity": "critical",
        "category": "Memory Security",
        "title": "Executable Page Protection Disabled",
        "description": (
            "The application has disabled executable page protection, allowing "
            "memory pages to be both writable and executable simultaneously."
        ),
        "impact": (
            "This completely disables W^X (Write XOR Execute) protection, making "
            "exploitation of memory corruption bugs trivial."
        ),
        "remediation": (
            "Remove this entitlement. Refactor code to not require writable and "
            "executable memory. This is a severe security weakening."
        ),
        "trigger_value": True,
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within Memory Buffer",
        "masvs": "MASVS-RESILIENCE",
        "mastg": "MSTG-CODE-9",
    },
    # Data Protection
    "com.apple.developer.default-data-protection": {
        "severity": "medium",
        "category": "Data Protection",
        "title": "Data Protection Level Configuration",
        "description": "The application specifies a default data protection level.",
        "impact": (
            "Lower protection levels may leave sensitive data accessible when the "
            "device is locked or after first unlock."
        ),
        "check_value": True,  # We check the value, not just presence
        "cwe_id": "CWE-311",
        "cwe_name": "Missing Encryption of Sensitive Data",
        "masvs": "MASVS-STORAGE",
        "mastg": "MSTG-STORAGE-1",
    },
    # Keychain Access Groups
    "keychain-access-groups": {
        "severity": "info",
        "category": "Keychain",
        "title": "Keychain Access Groups Configured",
        "description": "The application has configured keychain access groups.",
        "info_only": True,
        "masvs": "MASVS-STORAGE",
        "mastg": "MSTG-STORAGE-1",
    },
    # App Groups (for shared data)
    "com.apple.security.application-groups": {
        "severity": "low",
        "category": "Data Sharing",
        "title": "App Groups Configured",
        "description": (
            "The application uses App Groups for sharing data between apps or extensions."
        ),
        "impact": (
            "Shared containers may expose data to other apps in the group. Ensure "
            "sensitive data is properly protected."
        ),
        "info_only": True,
        "masvs": "MASVS-STORAGE",
        "mastg": "MSTG-STORAGE-3",
    },
    # Associated Domains
    "com.apple.developer.associated-domains": {
        "severity": "info",
        "category": "Universal Links",
        "title": "Associated Domains Configured",
        "description": "The application has configured universal links or associated domains.",
        "info_only": True,
        "masvs": "MASVS-PLATFORM",
        "mastg": "MSTG-PLATFORM-3",
    },
    # Inter-App Audio
    "inter-app-audio": {
        "severity": "info",
        "category": "Audio",
        "title": "Inter-App Audio Enabled",
        "description": "The application can share audio with other applications.",
        "info_only": True,
    },
    # HealthKit
    "com.apple.developer.healthkit": {
        "severity": "medium",
        "category": "Sensitive Data",
        "title": "HealthKit Access",
        "description": "The application has access to HealthKit health data.",
        "impact": (
            "Health data is highly sensitive. Ensure proper data protection and "
            "user consent flows are implemented."
        ),
        "check_presence": True,
        "masvs": "MASVS-PRIVACY",
        "mastg": "MSTG-STORAGE-6",
    },
    # HomeKit
    "com.apple.developer.homekit": {
        "severity": "low",
        "category": "IoT Access",
        "title": "HomeKit Access",
        "description": "The application can control HomeKit-enabled devices.",
        "info_only": True,
    },
    # iCloud
    "com.apple.developer.icloud-services": {
        "severity": "medium",
        "category": "Cloud Storage",
        "title": "iCloud Services Enabled",
        "description": "The application uses iCloud services for data storage.",
        "impact": (
            "Data stored in iCloud may be accessible from other devices. Ensure "
            "sensitive data is encrypted before upload."
        ),
        "check_presence": True,
        "masvs": "MASVS-STORAGE",
        "mastg": "MSTG-STORAGE-8",
    },
    # Network Extensions
    "com.apple.developer.networking.networkextension": {
        "severity": "medium",
        "category": "Network",
        "title": "Network Extension Capabilities",
        "description": "The application has network extension capabilities.",
        "impact": (
            "Network extensions can intercept and modify network traffic. Ensure "
            "proper user consent and data handling."
        ),
        "check_presence": True,
        "masvs": "MASVS-NETWORK",
        "mastg": "MSTG-NETWORK-1",
    },
    # VPN
    "com.apple.developer.networking.vpn.api": {
        "severity": "medium",
        "category": "Network",
        "title": "VPN API Access",
        "description": "The application can create VPN configurations.",
        "impact": (
            "VPN capabilities allow routing all device traffic. Ensure proper "
            "user consent and secure tunnel implementation."
        ),
        "check_presence": True,
        "masvs": "MASVS-NETWORK",
        "mastg": "MSTG-NETWORK-1",
    },
    # Siri
    "com.apple.developer.siri": {
        "severity": "info",
        "category": "Siri Integration",
        "title": "Siri Integration Enabled",
        "description": "The application integrates with Siri.",
        "info_only": True,
    },
    # Apple Pay
    "com.apple.developer.in-app-payments": {
        "severity": "info",
        "category": "Payments",
        "title": "Apple Pay Enabled",
        "description": "The application can process Apple Pay transactions.",
        "info_only": True,
        "masvs": "MASVS-STORAGE",
    },
    # Push Notifications
    "aps-environment": {
        "severity": "info",
        "category": "Push Notifications",
        "title": "Push Notifications Configured",
        "description": "The application uses push notifications.",
        "check_value": True,  # development vs production
        "masvs": "MASVS-PLATFORM",
    },
}

# Data protection levels (from most to least secure)
DATA_PROTECTION_LEVELS = {
    "NSFileProtectionComplete": {
        "level": 4,
        "description": "File is accessible only when device is unlocked",
        "severity": "info",
    },
    "NSFileProtectionCompleteUnlessOpen": {
        "level": 3,
        "description": "File is accessible only after first unlock, even if locked again while open",
        "severity": "low",
    },
    "NSFileProtectionCompleteUntilFirstUserAuthentication": {
        "level": 2,
        "description": "File is accessible after first unlock until device restart",
        "severity": "medium",
    },
    "NSFileProtectionNone": {
        "level": 1,
        "description": "No protection - file is always accessible",
        "severity": "high",
    },
}


class EntitlementsAnalyzer(BaseAnalyzer):
    """Analyzes iOS app entitlements for security issues."""

    name = "entitlements_analyzer"
    platform = "ios"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze iOS entitlements."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            ipa_path = Path(app.file_path)
            entitlements = await self._extract_entitlements(ipa_path)

            if not entitlements:
                # No entitlements found - this is suspicious for a production app
                findings.append(self.create_finding(
                    app=app,
                    title="No Entitlements Found",
                    severity="info",
                    category="Entitlements",
                    description=(
                        "No embedded entitlements were found in the IPA. This may indicate "
                        "an ad-hoc or enterprise build, or extraction may have failed."
                    ),
                    impact="Unable to verify entitlement security configuration.",
                    remediation="Ensure the IPA contains valid entitlements for analysis.",
                    poc_evidence="No embedded.mobileprovision or entitlements plist found in IPA",
                ))
                return findings

            # Store raw entitlements for display
            self._raw_entitlements = entitlements

            # Check each configured entitlement
            findings.extend(await self._check_configured_entitlements(app, entitlements))

            # Check data protection level
            findings.extend(await self._check_data_protection(app, entitlements))

            # Check for excessive capabilities
            findings.extend(await self._check_excessive_capabilities(app, entitlements))

            # Check associated domains
            findings.extend(await self._check_associated_domains(app, entitlements))

            # Check for custom entitlements
            findings.extend(await self._check_custom_entitlements(app, entitlements))

        except Exception as e:
            logger.error(f"Entitlements analysis failed: {e}")

        return findings

    async def _extract_entitlements(self, ipa_path: Path) -> dict[str, Any] | None:
        """Extract entitlements from IPA."""
        entitlements = {}

        try:
            with zipfile.ZipFile(ipa_path, "r") as ipa:
                # Try embedded.mobileprovision first
                for name in ipa.namelist():
                    if "embedded.mobileprovision" in name:
                        data = ipa.read(name)
                        provision_entitlements = await self._parse_provisioning_profile(data)
                        if provision_entitlements:
                            entitlements.update(provision_entitlements)

                # Also try to extract from the binary directly using codesign
                binary_path = None
                app_name = None
                for name in ipa.namelist():
                    if name.endswith(".app/") and "Payload/" in name:
                        parts = name.split("/")
                        app_name = parts[-2]  # Get .app name
                        break

                if app_name:
                    # Extract to temp and use codesign
                    with tempfile.TemporaryDirectory() as tmpdir:
                        ipa.extractall(tmpdir)
                        app_path = Path(tmpdir) / "Payload" / app_name
                        if app_path.exists():
                            binary_entitlements = await self._extract_from_binary(app_path)
                            if binary_entitlements:
                                entitlements.update(binary_entitlements)

        except Exception as e:
            logger.error(f"Failed to extract entitlements: {e}")

        return entitlements if entitlements else None

    async def _parse_provisioning_profile(self, data: bytes) -> dict[str, Any] | None:
        """Parse entitlements from provisioning profile."""
        try:
            # Find XML plist in the CMS signed data
            start = data.find(b"<?xml")
            if start == -1:
                start = data.find(b"<plist")
            if start == -1:
                return None

            end = data.find(b"</plist>", start)
            if end == -1:
                return None

            plist_data = data[start:end + len(b"</plist>")]
            profile = plistlib.loads(plist_data)

            return profile.get("Entitlements", {})

        except Exception as e:
            logger.error(f"Failed to parse provisioning profile: {e}")
            return None

    async def _extract_from_binary(self, app_path: Path) -> dict[str, Any] | None:
        """Extract entitlements directly from binary using codesign."""
        try:
            # Find the main binary
            info_plist = app_path / "Info.plist"
            if info_plist.exists():
                with open(info_plist, "rb") as f:
                    info = plistlib.load(f)
                    binary_name = info.get("CFBundleExecutable", app_path.stem.replace(".app", ""))
            else:
                binary_name = app_path.stem.replace(".app", "")

            binary_path = app_path / binary_name

            if not binary_path.exists():
                return None

            # Use codesign to extract entitlements
            result = subprocess.run(
                ["codesign", "-d", "--entitlements", "-", str(app_path)],
                capture_output=True,
                timeout=30,
            )

            if result.returncode == 0 and result.stdout:
                # Parse the XML output
                output = result.stdout
                start = output.find(b"<?xml")
                if start != -1:
                    plist_data = output[start:]
                    return plistlib.loads(plist_data)

        except FileNotFoundError:
            logger.warning("codesign not available (not on macOS)")
        except subprocess.TimeoutExpired:
            logger.warning("codesign timed out")
        except Exception as e:
            logger.error(f"Failed to extract from binary: {e}")

        return None

    async def _check_configured_entitlements(
        self, app: MobileApp, entitlements: dict[str, Any]
    ) -> list[Finding]:
        """Check entitlements against security configurations."""
        findings = []

        for entitlement_key, config in ENTITLEMENT_CHECKS.items():
            if entitlement_key not in entitlements:
                continue

            value = entitlements[entitlement_key]

            # Skip info-only if not enabled
            if config.get("info_only") and not value:
                continue

            # Check trigger value (e.g., get-task-allow = true)
            if "trigger_value" in config:
                if value != config["trigger_value"]:
                    continue

            # Check presence only
            if config.get("check_presence") and not value:
                continue

            # Create finding
            severity = config["severity"]
            title = config["title"]

            # Format value for display
            if isinstance(value, bool):
                value_str = str(value).lower()
            elif isinstance(value, list):
                value_str = ", ".join(str(v) for v in value[:5])
                if len(value) > 5:
                    value_str += f" ... (+{len(value) - 5} more)"
            else:
                value_str = str(value)

            findings.append(self.create_finding(
                app=app,
                title=title,
                severity=severity,
                category=config.get("category", "Entitlements"),
                description=config.get("description", f"Entitlement {entitlement_key} is set."),
                impact=config.get("impact", "See description for details."),
                remediation=config.get("remediation", "Review this entitlement setting."),
                file_path="embedded.mobileprovision",
                code_snippet=(
                    f"<key>{entitlement_key}</key>\n"
                    f"<{type(value).__name__.lower()}>{value_str}</{type(value).__name__.lower()}>"
                ),
                poc_evidence=f"Entitlement '{entitlement_key}' is set to: {value_str}",
                poc_verification=(
                    f"1. Extract IPA: unzip app.ipa -d extracted/\n"
                    f"2. Check provision: security cms -D -i extracted/Payload/*.app/embedded.mobileprovision\n"
                    f"3. Or: codesign -d --entitlements - extracted/Payload/*.app"
                ),
                poc_commands=[
                    f"unzip -o {app.file_path} -d /tmp/extracted",
                    "security cms -D -i /tmp/extracted/Payload/*.app/embedded.mobileprovision 2>/dev/null | grep -A2 '{}'".format(entitlement_key),
                ],
                cwe_id=config.get("cwe_id"),
                cwe_name=config.get("cwe_name"),
                owasp_masvs_category=config.get("masvs"),
                owasp_mastg_test=config.get("mastg"),
            ))

        return findings

    async def _check_data_protection(
        self, app: MobileApp, entitlements: dict[str, Any]
    ) -> list[Finding]:
        """Check data protection configuration."""
        findings = []

        protection_key = "com.apple.developer.default-data-protection"
        protection_level = entitlements.get(protection_key)

        if protection_level:
            level_config = DATA_PROTECTION_LEVELS.get(protection_level, {})
            severity = level_config.get("severity", "info")
            level_num = level_config.get("level", 0)

            if level_num < 3:  # Less than CompleteUnlessOpen
                findings.append(self.create_finding(
                    app=app,
                    title=f"Weak Data Protection Level: {protection_level}",
                    severity=severity,
                    category="Data Protection",
                    description=(
                        f"The application uses data protection level '{protection_level}'. "
                        f"{level_config.get('description', '')}. "
                        "This may leave sensitive data accessible when the device is locked."
                    ),
                    impact=(
                        "Files created by the app may be accessible to an attacker who has "
                        "physical access to the device, even when locked."
                    ),
                    remediation=(
                        "Use NSFileProtectionComplete for sensitive files:\n"
                        "1. Set default protection to Complete in entitlements\n"
                        "2. Or set per-file using NSFileProtectionKey attribute\n"
                        "3. Ensure files are closed when app backgrounds"
                    ),
                    file_path="embedded.mobileprovision",
                    code_snippet=(
                        f"<key>{protection_key}</key>\n"
                        f"<string>{protection_level}</string>"
                    ),
                    poc_evidence=f"Data protection level set to: {protection_level}",
                    poc_commands=[
                        f"unzip -o {app.file_path} -d /tmp/extracted",
                        f"security cms -D -i /tmp/extracted/Payload/*.app/embedded.mobileprovision 2>/dev/null | grep -A2 'default-data-protection'",
                    ],
                    cwe_id="CWE-311",
                    cwe_name="Missing Encryption of Sensitive Data",
                    owasp_masvs_category="MASVS-STORAGE",
                    owasp_masvs_control="MSTG-STORAGE-1",
                ))
        else:
            # No explicit data protection - defaults to UntilFirstUserAuthentication
            findings.append(self.create_finding(
                app=app,
                title="No Explicit Data Protection Level Set",
                severity="low",
                category="Data Protection",
                description=(
                    "The application does not specify a default data protection level. "
                    "iOS defaults to NSFileProtectionCompleteUntilFirstUserAuthentication."
                ),
                impact=(
                    "Files are accessible after the device is unlocked for the first time "
                    "since boot, even when subsequently locked."
                ),
                remediation=(
                    "Set explicit data protection to NSFileProtectionComplete:\n"
                    "1. Add com.apple.developer.default-data-protection entitlement\n"
                    "2. Set value to NSFileProtectionComplete\n"
                    "3. Handle file access errors when device is locked"
                ),
                poc_evidence="No com.apple.developer.default-data-protection entitlement found",
                owasp_masvs_category="MASVS-STORAGE",
                owasp_masvs_control="MSTG-STORAGE-1",
            ))

        return findings

    async def _check_excessive_capabilities(
        self, app: MobileApp, entitlements: dict[str, Any]
    ) -> list[Finding]:
        """Check for excessive or unusual capability combinations."""
        findings = []

        # Count sensitive capabilities
        sensitive_capabilities = [
            "com.apple.developer.healthkit",
            "com.apple.developer.networking.vpn.api",
            "com.apple.developer.networking.networkextension",
            "com.apple.developer.icloud-services",
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.allow-unsigned-executable-memory",
        ]

        enabled_sensitive = [cap for cap in sensitive_capabilities if entitlements.get(cap)]

        if len(enabled_sensitive) > 3:
            findings.append(self.create_finding(
                app=app,
                title="Multiple Sensitive Capabilities Enabled",
                severity="medium",
                category="Entitlements",
                description=(
                    f"The application has {len(enabled_sensitive)} sensitive capabilities enabled: "
                    f"{', '.join(enabled_sensitive[:5])}. This increases the attack surface."
                ),
                impact=(
                    "Each additional capability increases the potential attack vectors. "
                    "Verify all capabilities are necessary for the app's functionality."
                ),
                remediation=(
                    "Review enabled capabilities and remove any that are not essential:\n"
                    "1. Audit each capability's usage in code\n"
                    "2. Remove unused entitlements from provisioning profile\n"
                    "3. Follow principle of least privilege"
                ),
                file_path="embedded.mobileprovision",
                code_snippet="\n".join(f"<key>{cap}</key>" for cap in enabled_sensitive),
                poc_evidence=f"Found {len(enabled_sensitive)} sensitive capabilities enabled",
                owasp_masvs_category="MASVS-PLATFORM",
            ))

        return findings

    async def _check_associated_domains(
        self, app: MobileApp, entitlements: dict[str, Any]
    ) -> list[Finding]:
        """Check associated domains configuration."""
        findings = []

        domains = entitlements.get("com.apple.developer.associated-domains", [])

        if not domains:
            return findings

        # Check for webcredentials (password autofill)
        webcreds = [d for d in domains if d.startswith("webcredentials:")]
        if webcreds:
            findings.append(self.create_finding(
                app=app,
                title="Password AutoFill Domains Configured",
                severity="info",
                category="Associated Domains",
                description=(
                    f"The app supports Password AutoFill for: {', '.join(webcreds)}. "
                    "This enables credential sharing with Safari."
                ),
                impact="Users can autofill credentials saved from the website.",
                remediation="Ensure associated domains file (apple-app-site-association) is properly secured.",
                file_path="embedded.mobileprovision",
                code_snippet="\n".join(webcreds),
                poc_evidence=f"WebCredentials domains: {webcreds}",
                owasp_masvs_category="MASVS-AUTH",
            ))

        # Check for applinks (Universal Links)
        applinks = [d for d in domains if d.startswith("applinks:")]
        if applinks:
            # Check for wildcard domains
            wildcards = [d for d in applinks if "*." in d]
            if wildcards:
                findings.append(self.create_finding(
                    app=app,
                    title="Wildcard Universal Link Domains",
                    severity="medium",
                    category="Associated Domains",
                    description=(
                        f"The app uses wildcard domains for Universal Links: {', '.join(wildcards)}. "
                        "This may allow unintended subdomains to open the app."
                    ),
                    impact=(
                        "An attacker controlling any subdomain could potentially trigger "
                        "app deep links, which may be exploitable if input is not validated."
                    ),
                    remediation=(
                        "Use specific domains instead of wildcards:\n"
                        "1. List each subdomain explicitly\n"
                        "2. Validate deep link parameters thoroughly\n"
                        "3. Use path restrictions in apple-app-site-association"
                    ),
                    file_path="embedded.mobileprovision",
                    code_snippet="\n".join(wildcards),
                    poc_evidence=f"Wildcard applinks: {wildcards}",
                    cwe_id="CWE-601",
                    cwe_name="URL Redirection to Untrusted Site",
                    owasp_masvs_category="MASVS-PLATFORM",
                    owasp_masvs_control="MSTG-PLATFORM-3",
                ))

        return findings

    async def _check_custom_entitlements(
        self, app: MobileApp, entitlements: dict[str, Any]
    ) -> list[Finding]:
        """Check for custom or private entitlements."""
        findings = []

        # Known Apple prefixes
        apple_prefixes = [
            "com.apple.",
            "application-identifier",
            "keychain-access-groups",
            "get-task-allow",
            "aps-environment",
            "beta-reports-active",
            "team-identifier",
        ]

        custom_entitlements = []
        for key in entitlements.keys():
            if not any(key.startswith(prefix) or key == prefix for prefix in apple_prefixes):
                custom_entitlements.append(key)

        if custom_entitlements:
            findings.append(self.create_finding(
                app=app,
                title="Custom Entitlements Detected",
                severity="info",
                category="Entitlements",
                description=(
                    f"The app uses custom entitlements: {', '.join(custom_entitlements)}. "
                    "These may be private Apple APIs or custom configurations."
                ),
                impact=(
                    "Custom entitlements may indicate use of private APIs (App Store rejection risk) "
                    "or enterprise-specific configurations."
                ),
                remediation="Review custom entitlements for App Store compliance and security.",
                file_path="embedded.mobileprovision",
                code_snippet="\n".join(f"<key>{e}</key>" for e in custom_entitlements),
                poc_evidence=f"Custom entitlements found: {custom_entitlements}",
            ))

        return findings
