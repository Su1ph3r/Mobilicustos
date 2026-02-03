"""Network Security Config analyzer for Android."""

import logging
import re
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class NetworkSecurityConfigAnalyzer(BaseAnalyzer):
    """Analyzes Android network_security_config.xml for security issues."""

    name = "network_security_config_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze Android network security configuration."""
        findings: list[Finding] = []

        if not app.file_path or app.platform != "android":
            return findings

        try:
            # Extract network_security_config.xml
            config_xml, manifest_xml = await self._extract_configs(Path(app.file_path))

            if config_xml:
                findings.extend(await self._analyze_network_config(app, config_xml))
            else:
                # Check manifest for cleartextTrafficPermitted
                if manifest_xml:
                    findings.extend(await self._analyze_manifest_network(app, manifest_xml))
                else:
                    # No network security config - default behavior varies by API level
                    findings.extend(await self._check_default_config(app))

        except Exception as e:
            logger.error(f"Network security config analysis failed: {e}")

        return findings

    async def _extract_configs(
        self,
        apk_path: Path,
    ) -> tuple[str | None, str | None]:
        """Extract network_security_config.xml and AndroidManifest.xml."""
        config_xml = None
        manifest_xml = None

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                # Try to find network_security_config.xml
                for name in apk.namelist():
                    if name.endswith("network_security_config.xml"):
                        data = apk.read(name)
                        config_xml = data.decode("utf-8", errors="ignore")
                        break

                # Read AndroidManifest.xml (binary format, need to decode)
                if "AndroidManifest.xml" in apk.namelist():
                    # Note: AndroidManifest.xml in APK is binary XML
                    # For full parsing, we'd need a library like androguard
                    # For now, we'll try to extract relevant attributes
                    manifest_data = apk.read("AndroidManifest.xml")
                    # Simple string search for cleartextTrafficPermitted
                    manifest_xml = manifest_data.decode("utf-8", errors="ignore")

        except Exception as e:
            logger.error(f"Failed to extract configs: {e}")

        return config_xml, manifest_xml

    async def _analyze_network_config(
        self,
        app: MobileApp,
        config_xml: str,
    ) -> list[Finding]:
        """Analyze network_security_config.xml for issues."""
        findings: list[Finding] = []

        try:
            root = ElementTree.fromstring(config_xml)

            # Check base-config
            base_config = root.find("base-config")
            if base_config is not None:
                findings.extend(await self._check_config_element(app, base_config, "base-config", config_xml))

            # Check domain-config entries
            for domain_config in root.findall(".//domain-config"):
                domains = [d.text for d in domain_config.findall("domain") if d.text]
                findings.extend(await self._check_config_element(
                    app, domain_config, f"domain-config ({', '.join(domains[:3])})", config_xml
                ))

            # Check debug-overrides
            debug_overrides = root.find("debug-overrides")
            if debug_overrides is not None:
                findings.append(self.create_finding(
                    app=app,
                    title="Debug Overrides Present in Network Security Config",
                    severity="medium",
                    category="Network Security",
                    description=(
                        "The network_security_config.xml contains debug-overrides section. "
                        "While this only applies to debug builds, it may indicate relaxed "
                        "security settings during development."
                    ),
                    impact="Debug overrides could accidentally be enabled in production if build configuration is incorrect.",
                    remediation="Verify that release builds don't include debug certificates. Use separate debug/release configs.",
                    file_path="res/xml/network_security_config.xml",
                    code_snippet=self._extract_element_xml(debug_overrides),
                    poc_evidence="debug-overrides element found in network security config",
                    poc_verification="1. Extract APK\n2. Check res/xml/network_security_config.xml\n3. Verify debug-overrides usage",
                    poc_commands=[
                        f"apktool d {app.file_path} -o /tmp/apk_out",
                        "cat /tmp/apk_out/res/xml/network_security_config.xml",
                    ],
                    owasp_masvs_category="MASVS-NETWORK",
                    owasp_masvs_control="MASVS-NETWORK-1",
                ))

            # Check for certificate pinning
            pin_set = root.find(".//pin-set")
            if pin_set is None:
                findings.append(self.create_finding(
                    app=app,
                    title="No Certificate Pinning Configured",
                    severity="info",
                    category="Network Security",
                    description=(
                        "The network_security_config.xml does not define certificate pinning. "
                        "While not required, pinning adds defense-in-depth against MITM attacks."
                    ),
                    impact="Without certificate pinning, compromised CAs could be used to intercept traffic.",
                    remediation="Consider adding pin-set with SHA-256 pins for your backend certificates.",
                    file_path="res/xml/network_security_config.xml",
                    code_snippet='''<!-- Add certificate pinning -->
<domain-config>
    <domain includeSubdomains="true">example.com</domain>
    <pin-set expiration="2025-01-01">
        <pin digest="SHA-256">base64EncodedPin==</pin>
    </pin-set>
</domain-config>''',
                    poc_evidence="No pin-set element found in network security config",
                    poc_verification="1. Check network_security_config.xml for pin-set\n2. Test with proxy (Burp/mitmproxy)",
                    poc_commands=[
                        "grep -r 'pin-set' /tmp/apk_out/res/xml/",
                        "# Test MITM: mitmproxy -p 8080",
                    ],
                    owasp_masvs_category="MASVS-NETWORK",
                    owasp_masvs_control="MASVS-NETWORK-2",
                ))
            else:
                # Check pin expiration
                expiration = pin_set.get("expiration")
                if expiration:
                    findings.append(self.create_finding(
                        app=app,
                        title="Certificate Pinning Configured",
                        severity="info",
                        category="Network Security",
                        description=f"Certificate pinning is configured with expiration: {expiration}",
                        impact="Pinning provides additional protection against MITM attacks.",
                        remediation="Ensure pins are updated before expiration. Have a backup pin.",
                        file_path="res/xml/network_security_config.xml",
                        code_snippet=self._extract_element_xml(pin_set),
                        poc_evidence=f"Certificate pinning configured, expires: {expiration}",
                        owasp_masvs_category="MASVS-NETWORK",
                        owasp_masvs_control="MASVS-NETWORK-2",
                    ))

        except ElementTree.ParseError as e:
            logger.error(f"Failed to parse network_security_config.xml: {e}")

        return findings

    async def _check_config_element(
        self,
        app: MobileApp,
        element: ElementTree.Element,
        config_name: str,
        full_xml: str,
    ) -> list[Finding]:
        """Check a config element for security issues."""
        findings: list[Finding] = []

        # Check cleartextTrafficPermitted
        cleartext = element.get("cleartextTrafficPermitted")
        if cleartext == "true":
            findings.append(self.create_finding(
                app=app,
                title=f"Cleartext Traffic Permitted in {config_name}",
                severity="high",
                category="Network Security",
                description=(
                    f"The {config_name} section allows cleartext (HTTP) traffic. "
                    "This disables the Android Network Security Config protection against "
                    "unencrypted network traffic."
                ),
                impact="Network traffic can be intercepted and read by attackers on the same network.",
                remediation="Set cleartextTrafficPermitted='false' and use HTTPS for all communications.",
                file_path="res/xml/network_security_config.xml",
                code_snippet=self._extract_element_xml(element),
                poc_evidence=f"cleartextTrafficPermitted='true' in {config_name}",
                poc_verification="1. Set up HTTP proxy\n2. Force app to use HTTP\n3. Verify traffic is unencrypted",
                poc_commands=[
                    f"apktool d {app.file_path} -o /tmp/apk_out",
                    "grep -r 'cleartextTrafficPermitted' /tmp/apk_out/",
                    "# Intercept with: mitmproxy --mode transparent",
                ],
                cwe_id="CWE-319",
                owasp_masvs_category="MASVS-NETWORK",
                owasp_masvs_control="MASVS-NETWORK-1",
            ))

        # Check trust-anchors
        trust_anchors = element.find("trust-anchors")
        if trust_anchors is not None:
            for cert in trust_anchors.findall("certificates"):
                src = cert.get("src")
                if src == "user":
                    findings.append(self.create_finding(
                        app=app,
                        title=f"User Certificates Trusted in {config_name}",
                        severity="medium",
                        category="Network Security",
                        description=(
                            f"The {config_name} trusts user-installed certificates. "
                            "This allows users to install CA certificates that will be trusted "
                            "by the application, potentially enabling MITM attacks."
                        ),
                        impact="Users can install proxy CA certificates to intercept app traffic.",
                        remediation="Remove user certificates from trust-anchors in production builds.",
                        file_path="res/xml/network_security_config.xml",
                        code_snippet=self._extract_element_xml(trust_anchors),
                        poc_evidence=f"User certificates trusted in {config_name}",
                        poc_verification="1. Install proxy CA on device\n2. Configure proxy\n3. Intercept HTTPS traffic",
                        poc_commands=[
                            "adb push burp_ca.crt /sdcard/",
                            "# Install cert in Settings > Security > Install certificates",
                            "mitmproxy -p 8080",
                        ],
                        owasp_masvs_category="MASVS-NETWORK",
                        owasp_masvs_control="MASVS-NETWORK-1",
                    ))

                if src and src.startswith("@raw/"):
                    cert_name = src.replace("@raw/", "")
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Custom Certificate Bundle in {config_name}",
                        severity="info",
                        category="Network Security",
                        description=f"The app includes a custom certificate bundle: {cert_name}",
                        impact="Custom certificates may be used for pinning or private CA trust.",
                        remediation="Verify the certificate bundle is legitimate and from your organization.",
                        file_path=f"res/raw/{cert_name}",
                        poc_evidence=f"Custom certificate: {src}",
                        owasp_masvs_category="MASVS-NETWORK",
                    ))

        return findings

    async def _analyze_manifest_network(
        self,
        app: MobileApp,
        manifest_xml: str,
    ) -> list[Finding]:
        """Analyze manifest for network security settings."""
        findings: list[Finding] = []

        # Check for usesCleartextTraffic (basic string search since manifest is binary)
        if "cleartextTraffic" in manifest_xml and "true" in manifest_xml:
            findings.append(self.create_finding(
                app=app,
                title="Cleartext Traffic Allowed via Manifest",
                severity="high",
                category="Network Security",
                description=(
                    "The AndroidManifest.xml appears to allow cleartext traffic via "
                    "android:usesCleartextTraffic='true'. This disables network security protections."
                ),
                impact="All network traffic can be sent over unencrypted HTTP.",
                remediation="Set android:usesCleartextTraffic='false' in manifest or use network_security_config.xml.",
                file_path="AndroidManifest.xml",
                code_snippet='<application android:usesCleartextTraffic="true" ...>',
                poc_evidence="usesCleartextTraffic='true' found in manifest",
                poc_verification="1. Decompile APK with apktool\n2. Check AndroidManifest.xml\n3. Test HTTP connections",
                poc_commands=[
                    f"apktool d {app.file_path} -o /tmp/apk_out",
                    "grep -i 'usesCleartextTraffic' /tmp/apk_out/AndroidManifest.xml",
                ],
                cwe_id="CWE-319",
                owasp_masvs_category="MASVS-NETWORK",
                owasp_masvs_control="MASVS-NETWORK-1",
            ))

        return findings

    async def _check_default_config(self, app: MobileApp) -> list[Finding]:
        """Check implications of missing network security config."""
        findings: list[Finding] = []

        # If no config and targeting API < 28, cleartext is allowed by default
        if app.target_sdk_version and app.target_sdk_version < 28:
            findings.append(self.create_finding(
                app=app,
                title="No Network Security Config (API < 28)",
                severity="medium",
                category="Network Security",
                description=(
                    f"The app targets API {app.target_sdk_version} and has no network_security_config.xml. "
                    "On Android 8.1 and below, cleartext traffic is allowed by default."
                ),
                impact="App may transmit data over unencrypted HTTP connections.",
                remediation="Add network_security_config.xml with cleartextTrafficPermitted='false'.",
                file_path="res/xml/network_security_config.xml",
                code_snippet='''<!-- Create res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>''',
                poc_evidence=f"No network_security_config.xml, targetSdk={app.target_sdk_version}",
                poc_verification="1. Check res/xml/ for network_security_config.xml\n2. Test HTTP connections",
                poc_commands=[
                    f"apktool d {app.file_path} -o /tmp/apk_out",
                    "ls -la /tmp/apk_out/res/xml/",
                ],
                owasp_masvs_category="MASVS-NETWORK",
                owasp_masvs_control="MASVS-NETWORK-1",
            ))
        else:
            findings.append(self.create_finding(
                app=app,
                title="Using Default Network Security Config",
                severity="info",
                category="Network Security",
                description=(
                    "The app uses Android's default network security configuration. "
                    "On Android 9+ (API 28+), cleartext traffic is blocked by default."
                ),
                impact="Default configuration provides basic protection but lacks certificate pinning.",
                remediation="Consider adding explicit network_security_config.xml with certificate pinning.",
                file_path="res/xml/network_security_config.xml",
                poc_evidence="No custom network_security_config.xml found",
                owasp_masvs_category="MASVS-NETWORK",
            ))

        return findings

    def _extract_element_xml(self, element: ElementTree.Element) -> str:
        """Extract XML string from an element."""
        try:
            return ElementTree.tostring(element, encoding="unicode", method="xml")
        except Exception:
            return "<error extracting xml>"
