"""Deep link security analyzer for Android applications.

Parses AndroidManifest.xml to extract all deep link handler configurations
(activities with ACTION_VIEW + BROWSABLE intent filters), evaluates their
security posture, and identifies vulnerabilities in URL scheme handling.

Security checks performed:
    - **Custom URL Scheme Hijacking**: Detects custom URL schemes (non-
      http/https) that can be registered by malicious apps to intercept
      OAuth callbacks, tokens, and sensitive navigation.
    - **Missing Host Verification**: Identifies HTTP/HTTPS deep links
      without android:autoVerify="true" (Android App Links), which
      allows URL disambiguation or hijacking by competing apps.
    - **Input Validation in Handlers**: Scans deep link handler activity
      source code for getIntent().getData() calls without corresponding
      URI parameter validation, allowing injection attacks.

OWASP references:
    - MASVS-PLATFORM: Platform Interaction
    - MASVS-PLATFORM-2: Testing Deep Links
    - MASTG-TEST-0028: Testing Deep Links
    - CWE-939: Improper Authorization in Handler for Custom URL Scheme
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


class DeeplinkAnalyzer(BaseAnalyzer):
    """Analyzes deep link configurations for security vulnerabilities.

    Extracts the APK, parses the AndroidManifest.xml (with fallback to
    androguard for binary manifests), extracts all deep link handlers,
    and evaluates custom scheme hijacking risk, missing App Links
    verification, and input validation in handler activities.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform ("android").
    """

    name = "deeplink_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze deep link security in the Android application.

        Args:
            app: The mobile application to analyze.

        Returns:
            A list of Finding objects covering custom scheme hijacking,
            unverified HTTP links, input validation, and a summary.
        """
        if not app.file_path:
            return []

        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="deeplink_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            findings = []

            # Parse AndroidManifest.xml
            manifest_path = extracted_path / "AndroidManifest.xml"
            manifest_xml = None

            if manifest_path.exists():
                try:
                    manifest_xml = manifest_path.read_text(errors='ignore')
                except Exception:
                    pass

            if not manifest_xml:
                # Try to decode binary manifest
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

            # Find all deep link handlers
            deeplinks = self._extract_deeplinks(root)

            if not deeplinks:
                return findings

            # Check for unvalidated deeplinks (custom schemes without host verification)
            custom_scheme_links = [dl for dl in deeplinks if dl["scheme"] not in ("http", "https")]
            http_links = [dl for dl in deeplinks if dl["scheme"] in ("http", "https")]

            # Custom scheme deeplinks (can be hijacked)
            if custom_scheme_links:
                schemes = list(set(dl["scheme"] for dl in custom_scheme_links))
                activities = list(set(dl["activity"] for dl in custom_scheme_links))

                scheme_list = "\n".join(f"- {s}://" for s in schemes)
                activity_list = "\n".join(f"- {a}" for a in activities[:10])

                findings.append(self.create_finding(
                    app=app,
                    title=f"Custom URL Schemes Without Host Verification ({len(schemes)} schemes)",
                    description=(
                        f"The application registers {len(schemes)} custom URL scheme(s) that can be "
                        "hijacked by malicious apps:\n\n"
                        f"**Schemes:**\n{scheme_list}\n\n"
                        f"**Handling activities:**\n{activity_list}\n\n"
                        "Custom URL schemes cannot be verified and any app can register the same scheme."
                    ),
                    severity="high",
                    category="Deep Link Security",
                    impact=(
                        "A malicious app can register the same custom URL scheme and intercept "
                        "links intended for this application. This can lead to credential theft, "
                        "OAuth token interception, or phishing attacks."
                    ),
                    remediation=(
                        "1. Migrate to Android App Links (verified https:// links) for sensitive flows\n"
                        "2. Never pass tokens or credentials through custom URL schemes\n"
                        "3. Validate all parameters received through deep links\n"
                        "4. Use PKCE for OAuth flows using custom scheme redirects"
                    ),
                    file_path="AndroidManifest.xml",
                    code_snippet=self._build_deeplink_snippet(custom_scheme_links[0]),
                    cwe_id="CWE-939",
                    cwe_name="Improper Authorization in Handler for Custom URL Scheme",
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
                    owasp_masvs_category="MASVS-PLATFORM",
                    owasp_masvs_control="MASVS-PLATFORM-2",
                    owasp_mastg_test="MASTG-TEST-0028",
                    poc_commands=[
                        {
                            "type": "adb",
                            "command": f"adb shell am start -W -a android.intent.action.VIEW -d '{schemes[0]}://evil?token=stolen'",
                            "description": "Test deep link handler with crafted URL",
                        },
                        {
                            "type": "bash",
                            "command": f"aapt dump badging {app.file_path} | grep scheme",
                            "description": "List all registered URL schemes",
                        },
                    ],
                ))

            # HTTP/HTTPS links without autoVerify (not App Links)
            unverified_http = [dl for dl in http_links if not dl.get("auto_verify")]
            if unverified_http:
                hosts = list(set(dl.get("host", "*") for dl in unverified_http))
                host_list = "\n".join(f"- {h}" for h in hosts[:10])

                findings.append(self.create_finding(
                    app=app,
                    title=f"HTTP Deep Links Without Host Verification ({len(hosts)} hosts)",
                    description=(
                        "The application handles HTTP/HTTPS deep links but does not use "
                        "Android App Links (autoVerify) for domain verification:\n\n"
                        f"**Unverified hosts:**\n{host_list}\n\n"
                        "Without autoVerify, the system may show a disambiguation dialog "
                        "or another app could handle these URLs."
                    ),
                    severity="medium",
                    category="Deep Link Security",
                    impact=(
                        "Without domain verification, a malicious app could register as a handler "
                        "for the same URLs, potentially intercepting sensitive navigation."
                    ),
                    remediation=(
                        "1. Add android:autoVerify=\"true\" to intent-filter\n"
                        "2. Host a Digital Asset Links file at /.well-known/assetlinks.json\n"
                        "3. Verify the association using: adb shell pm get-app-links <package>"
                    ),
                    file_path="AndroidManifest.xml",
                    cwe_id="CWE-939",
                    cwe_name="Improper Authorization in Handler for Custom URL Scheme",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    owasp_masvs_category="MASVS-PLATFORM",
                    owasp_masvs_control="MASVS-PLATFORM-2",
                    poc_commands=[
                        {
                            "type": "adb",
                            "command": f"adb shell pm get-app-links {app.package_name}",
                            "description": "Check App Links verification status",
                        },
                    ],
                    remediation_code={
                        "xml": (
                            '<intent-filter android:autoVerify="true">\n'
                            '    <action android:name="android.intent.action.VIEW" />\n'
                            '    <category android:name="android.intent.category.DEFAULT" />\n'
                            '    <category android:name="android.intent.category.BROWSABLE" />\n'
                            '    <data android:scheme="https" android:host="example.com" />\n'
                            '</intent-filter>'
                        ),
                    },
                ))

            # Check for input validation in deep link handlers
            validation_findings = await self._check_deeplink_validation(
                extracted_path, deeplinks, app
            )
            findings.extend(validation_findings)

            # Summary finding
            if deeplinks:
                all_schemes = list(set(dl["scheme"] for dl in deeplinks))
                all_hosts = list(set(dl.get("host", "*") for dl in deeplinks if dl.get("host")))

                findings.append(self.create_finding(
                    app=app,
                    title=f"Deep Link Configuration Summary ({len(deeplinks)} handlers)",
                    description=(
                        f"**Total deep link handlers:** {len(deeplinks)}\n"
                        f"**Schemes:** {', '.join(all_schemes)}\n"
                        f"**Hosts:** {', '.join(all_hosts[:10]) if all_hosts else 'None specified'}\n"
                        f"**Custom schemes:** {len(custom_scheme_links)}\n"
                        f"**HTTP/HTTPS links:** {len(http_links)}\n"
                        f"**Verified (App Links):** {len(http_links) - len(unverified_http)}"
                    ),
                    severity="info",
                    category="Deep Link Security",
                    impact="Review all deep link handlers for proper input validation.",
                    remediation="Ensure all deep link parameters are validated before use.",
                    owasp_masvs_category="MASVS-PLATFORM",
                    owasp_masvs_control="MASVS-PLATFORM-2",
                ))

            return findings

        except Exception as e:
            logger.error(f"Deep link analysis failed: {e}")
            return []
        finally:
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    def _extract_deeplinks(self, root: ET.Element) -> list[dict]:
        """Extract all deep link configurations from manifest XML.

        Iterates over all <activity> elements, filters for intent-filters
        with ACTION_VIEW + BROWSABLE category, and extracts scheme, host,
        path, export status, and autoVerify attributes.

        Args:
            root: The parsed XML root element of AndroidManifest.xml.

        Returns:
            A list of dicts with 'activity', 'scheme', 'host', 'path',
            'exported', and 'auto_verify' keys.
        """
        deeplinks = []

        for activity in root.iter("activity"):
            activity_name = activity.get(f"{{{NS['android']}}}name", "")
            if not activity_name:
                activity_name = activity.get("name", "")

            exported = activity.get(f"{{{NS['android']}}}exported", "")

            for intent_filter in activity.findall("intent-filter"):
                # Check for VIEW action
                has_view = False
                for action in intent_filter.findall("action"):
                    action_name = action.get(f"{{{NS['android']}}}name", "")
                    if not action_name:
                        action_name = action.get("name", "")
                    if action_name == "android.intent.action.VIEW":
                        has_view = True
                        break

                if not has_view:
                    continue

                # Check for BROWSABLE category
                has_browsable = False
                for category in intent_filter.findall("category"):
                    cat_name = category.get(f"{{{NS['android']}}}name", "")
                    if not cat_name:
                        cat_name = category.get("name", "")
                    if cat_name == "android.intent.category.BROWSABLE":
                        has_browsable = True
                        break

                if not has_browsable:
                    continue

                # Check autoVerify
                auto_verify = intent_filter.get(f"{{{NS['android']}}}autoVerify", "")

                # Extract data elements
                for data in intent_filter.findall("data"):
                    scheme = data.get(f"{{{NS['android']}}}scheme", "")
                    if not scheme:
                        scheme = data.get("scheme", "")
                    host = data.get(f"{{{NS['android']}}}host", "")
                    if not host:
                        host = data.get("host", "")
                    path = data.get(f"{{{NS['android']}}}path", "")
                    path_prefix = data.get(f"{{{NS['android']}}}pathPrefix", "")

                    if scheme:
                        deeplinks.append({
                            "activity": activity_name,
                            "scheme": scheme,
                            "host": host or None,
                            "path": path or path_prefix or None,
                            "exported": exported.lower() == "true",
                            "auto_verify": auto_verify.lower() == "true",
                        })

        return deeplinks

    def _build_deeplink_snippet(self, deeplink: dict) -> str:
        """Build a representative XML snippet for a deep link configuration.

        Args:
            deeplink: A deep link dict from _extract_deeplinks().

        Returns:
            An XML string showing the activity and intent-filter.
        """
        host_attr = f' android:host="{deeplink["host"]}"' if deeplink.get("host") else ""
        path_attr = f' android:path="{deeplink["path"]}"' if deeplink.get("path") else ""
        return (
            f'<activity android:name="{deeplink["activity"]}">\n'
            f'    <intent-filter>\n'
            f'        <action android:name="android.intent.action.VIEW" />\n'
            f'        <category android:name="android.intent.category.BROWSABLE" />\n'
            f'        <data android:scheme="{deeplink["scheme"]}"{host_attr}{path_attr} />\n'
            f'    </intent-filter>\n'
            f'</activity>'
        )

    async def _check_deeplink_validation(
        self, extracted_path: Path, deeplinks: list[dict], app: MobileApp
    ) -> list[Finding]:
        """Check if deep link handler activities validate incoming URI data.

        Searches for the handler activity source files and checks
        whether getIntent().getData() calls are accompanied by URI
        validation patterns (null checks, Uri.parse, matches).

        Args:
            extracted_path: Root directory of the extracted APK.
            deeplinks: List of deep link dicts from _extract_deeplinks().
            app: The mobile application being analyzed.

        Returns:
            A list of Finding objects for handlers missing input validation.
        """
        findings = []

        # Get activity class names
        activity_names = set(dl["activity"] for dl in deeplinks)

        for activity_name in activity_names:
            # Convert class name to file path
            class_file = activity_name.replace(".", "/") + ".java"
            # Also check short names
            short_name = activity_name.split(".")[-1]

            found_file = None
            for ext in [".java", ".kt"]:
                for source_file in extracted_path.rglob(f"{short_name}{ext}"):
                    found_file = source_file
                    break
                if found_file:
                    break

            if not found_file:
                continue

            try:
                content = found_file.read_text(errors='ignore')

                # Check for getIntent().getData() without validation
                has_get_data = bool(re.search(r'getIntent\(\)\.getData\(\)|intent\.getData\(\)', content))
                has_validation = bool(re.search(
                    r'if\s*\(\s*(?:uri|data|url)\s*[!=]|'
                    r'Uri\.parse|'
                    r'\.getQueryParameter\s*\([^)]+\)\s*!=\s*null|'
                    r'TextUtils\.isEmpty|'
                    r'\.matches\s*\(',
                    content
                ))

                if has_get_data and not has_validation:
                    findings.append(self.create_finding(
                        app=app,
                        title=f"Deep Link Handler Without Input Validation: {short_name}",
                        description=(
                            f"The activity '{activity_name}' handles deep links but does not appear "
                            "to validate the incoming URI data. This could allow injection of "
                            "malicious parameters."
                        ),
                        severity="high",
                        category="Deep Link Security",
                        impact=(
                            "An attacker can craft malicious deep links to inject unexpected parameters, "
                            "potentially leading to XSS, open redirect, or unauthorized actions."
                        ),
                        remediation=(
                            "1. Validate the scheme, host, and path of incoming URIs\n"
                            "2. Sanitize all query parameters\n"
                            "3. Never directly pass deep link data to WebViews or SQL queries\n"
                            "4. Implement allowlists for expected parameters"
                        ),
                        file_path=str(found_file.relative_to(extracted_path)),
                        cwe_id="CWE-939",
                        cwe_name="Improper Authorization in Handler for Custom URL Scheme",
                        cvss_score=7.4,
                        owasp_masvs_category="MASVS-PLATFORM",
                        owasp_masvs_control="MASVS-PLATFORM-2",
                    ))

            except Exception:
                pass

        return findings
