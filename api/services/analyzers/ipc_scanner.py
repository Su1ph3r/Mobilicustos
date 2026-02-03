"""IPC Vulnerability Scanner.

Analyzes Inter-Process Communication components for security issues:
- Android: Activities, Services, Broadcast Receivers, Content Providers
- iOS: URL Schemes, Universal Links, App Extensions
"""

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from api.models.database import MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger(__name__)


@dataclass
class IPCComponent:
    """Represents an IPC component."""
    component_type: str
    name: str
    is_exported: bool = False
    permission_required: str | None = None
    intent_filters: list[dict] = field(default_factory=list)
    url_schemes: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    source_file: str | None = None


class IPCScanner(BaseAnalyzer):
    """Scans for IPC vulnerabilities in mobile applications."""

    name = "ipc_scanner"
    description = "Analyzes IPC components for security vulnerabilities"

    async def analyze(self, app: MobileApp, extracted_path: Path) -> list[AnalyzerResult]:
        """Analyze IPC components."""
        results = []
        components: list[IPCComponent] = []

        if app.platform == "android":
            components.extend(await self._analyze_android(extracted_path))
        elif app.platform == "ios":
            components.extend(await self._analyze_ios(extracted_path))

        # Analyze each component for vulnerabilities
        for component in components:
            self._check_vulnerabilities(component, app.platform)

        # Create findings
        exported_components = [c for c in components if c.is_exported and not c.permission_required]
        if exported_components:
            results.extend(self._create_exported_findings(exported_components, app))

        vulnerable_components = [c for c in components if c.vulnerabilities]
        if vulnerable_components:
            results.extend(self._create_vulnerability_findings(vulnerable_components, app))

        # URL scheme analysis
        url_scheme_components = [c for c in components if c.url_schemes]
        if url_scheme_components:
            results.append(self._create_url_scheme_finding(url_scheme_components, app))

        # Summary
        if components:
            results.append(self._create_summary(components, app))

        return results

    async def _analyze_android(self, extracted_path: Path) -> list[IPCComponent]:
        """Analyze Android IPC components from AndroidManifest.xml."""
        components = []
        manifest_path = extracted_path / "AndroidManifest.xml"

        if not manifest_path.exists():
            return components

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # Define namespace
            ns = {'android': 'http://schemas.android.com/apk/res/android'}

            # Get package name for determining export status
            package_name = root.get('package', '')

            # Analyze Activities
            for activity in root.findall('.//activity', ns) + root.findall('.//activity'):
                name = activity.get('{http://schemas.android.com/apk/res/android}name', '')
                if not name:
                    name = activity.get('name', '')

                exported = self._is_exported(activity, ns)
                permission = activity.get('{http://schemas.android.com/apk/res/android}permission')

                intent_filters = self._parse_intent_filters(activity, ns)

                components.append(IPCComponent(
                    component_type="activity",
                    name=name,
                    is_exported=exported,
                    permission_required=permission,
                    intent_filters=intent_filters,
                    source_file="AndroidManifest.xml"
                ))

            # Analyze Services
            for service in root.findall('.//service', ns) + root.findall('.//service'):
                name = service.get('{http://schemas.android.com/apk/res/android}name', '')
                if not name:
                    name = service.get('name', '')

                exported = self._is_exported(service, ns)
                permission = service.get('{http://schemas.android.com/apk/res/android}permission')

                components.append(IPCComponent(
                    component_type="service",
                    name=name,
                    is_exported=exported,
                    permission_required=permission,
                    intent_filters=self._parse_intent_filters(service, ns),
                    source_file="AndroidManifest.xml"
                ))

            # Analyze Broadcast Receivers
            for receiver in root.findall('.//receiver', ns) + root.findall('.//receiver'):
                name = receiver.get('{http://schemas.android.com/apk/res/android}name', '')
                if not name:
                    name = receiver.get('name', '')

                exported = self._is_exported(receiver, ns)
                permission = receiver.get('{http://schemas.android.com/apk/res/android}permission')

                components.append(IPCComponent(
                    component_type="receiver",
                    name=name,
                    is_exported=exported,
                    permission_required=permission,
                    intent_filters=self._parse_intent_filters(receiver, ns),
                    source_file="AndroidManifest.xml"
                ))

            # Analyze Content Providers
            for provider in root.findall('.//provider', ns) + root.findall('.//provider'):
                name = provider.get('{http://schemas.android.com/apk/res/android}name', '')
                if not name:
                    name = provider.get('name', '')

                exported = self._is_exported(provider, ns)
                permission = provider.get('{http://schemas.android.com/apk/res/android}permission')
                read_perm = provider.get('{http://schemas.android.com/apk/res/android}readPermission')
                write_perm = provider.get('{http://schemas.android.com/apk/res/android}writePermission')

                # Check grantUriPermissions
                grant_uri = provider.get('{http://schemas.android.com/apk/res/android}grantUriPermissions')

                component = IPCComponent(
                    component_type="provider",
                    name=name,
                    is_exported=exported,
                    permission_required=permission or read_perm or write_perm,
                    source_file="AndroidManifest.xml"
                )

                if grant_uri == "true" and exported:
                    component.vulnerabilities.append("grant_uri_permissions_enabled")

                components.append(component)

        except ET.ParseError as e:
            logger.warning(f"Error parsing AndroidManifest.xml: {e}")

        return components

    async def _analyze_ios(self, extracted_path: Path) -> list[IPCComponent]:
        """Analyze iOS IPC components from Info.plist."""
        components = []

        # Find Info.plist
        info_plist = None
        for plist in extracted_path.rglob("Info.plist"):
            info_plist = plist
            break

        if not info_plist:
            return components

        try:
            content = info_plist.read_text(errors='ignore')

            # Parse URL schemes
            url_schemes = self._parse_ios_url_schemes(content)
            if url_schemes:
                components.append(IPCComponent(
                    component_type="url_scheme",
                    name="URL Schemes",
                    is_exported=True,
                    url_schemes=url_schemes,
                    source_file="Info.plist"
                ))

            # Parse Universal Links (Associated Domains)
            associated_domains = self._parse_associated_domains(content)
            if associated_domains:
                components.append(IPCComponent(
                    component_type="universal_link",
                    name="Universal Links",
                    is_exported=True,
                    url_schemes=associated_domains,
                    source_file="Info.plist"
                ))

            # Parse App Extensions
            extensions = self._parse_app_extensions(extracted_path)
            components.extend(extensions)

            # Parse Document Types
            doc_types = self._parse_document_types(content)
            if doc_types:
                components.append(IPCComponent(
                    component_type="document_type",
                    name="Document Types",
                    is_exported=True,
                    url_schemes=doc_types,
                    source_file="Info.plist"
                ))

        except Exception as e:
            logger.warning(f"Error parsing Info.plist: {e}")

        return components

    def _is_exported(self, element, ns: dict) -> bool:
        """Determine if an Android component is exported."""
        # Explicit exported attribute
        exported_attr = element.get('{http://schemas.android.com/apk/res/android}exported')
        if exported_attr is not None:
            return exported_attr.lower() == 'true'

        # If has intent-filter, it's implicitly exported (pre-Android 12)
        intent_filters = element.findall('.//intent-filter', ns) + element.findall('.//intent-filter')
        return len(intent_filters) > 0

    def _parse_intent_filters(self, element, ns: dict) -> list[dict]:
        """Parse intent filters from an Android component."""
        filters = []

        for intent_filter in element.findall('.//intent-filter', ns) + element.findall('.//intent-filter'):
            filter_info = {
                "actions": [],
                "categories": [],
                "data": []
            }

            # Actions
            for action in intent_filter.findall('.//action', ns) + intent_filter.findall('.//action'):
                name = action.get('{http://schemas.android.com/apk/res/android}name', '')
                if not name:
                    name = action.get('name', '')
                if name:
                    filter_info["actions"].append(name)

            # Categories
            for category in intent_filter.findall('.//category', ns) + intent_filter.findall('.//category'):
                name = category.get('{http://schemas.android.com/apk/res/android}name', '')
                if not name:
                    name = category.get('name', '')
                if name:
                    filter_info["categories"].append(name)

            # Data (schemes, hosts, etc.)
            for data in intent_filter.findall('.//data', ns) + intent_filter.findall('.//data'):
                data_info = {}
                for attr in ['scheme', 'host', 'path', 'pathPrefix', 'pathPattern', 'mimeType']:
                    val = data.get(f'{{http://schemas.android.com/apk/res/android}}{attr}')
                    if not val:
                        val = data.get(attr)
                    if val:
                        data_info[attr] = val
                if data_info:
                    filter_info["data"].append(data_info)

            filters.append(filter_info)

        return filters

    def _parse_ios_url_schemes(self, content: str) -> list[str]:
        """Parse URL schemes from iOS Info.plist."""
        schemes = []

        # Simple regex parsing (not full plist parsing)
        scheme_pattern = r'<key>CFBundleURLSchemes</key>\s*<array>(.*?)</array>'
        match = re.search(scheme_pattern, content, re.DOTALL)
        if match:
            array_content = match.group(1)
            string_pattern = r'<string>([^<]+)</string>'
            schemes = re.findall(string_pattern, array_content)

        return schemes

    def _parse_associated_domains(self, content: str) -> list[str]:
        """Parse associated domains from entitlements."""
        domains = []

        # Look for associated domains
        domain_pattern = r'<key>com\.apple\.developer\.associated-domains</key>\s*<array>(.*?)</array>'
        match = re.search(domain_pattern, content, re.DOTALL)
        if match:
            array_content = match.group(1)
            string_pattern = r'<string>([^<]+)</string>'
            domains = re.findall(string_pattern, array_content)

        return domains

    def _parse_document_types(self, content: str) -> list[str]:
        """Parse document types from Info.plist."""
        doc_types = []

        # Look for CFBundleDocumentTypes
        if 'CFBundleDocumentTypes' in content:
            # Extract UTIs
            uti_pattern = r'<key>LSItemContentTypes</key>\s*<array>(.*?)</array>'
            matches = re.findall(uti_pattern, content, re.DOTALL)
            for match in matches:
                string_pattern = r'<string>([^<]+)</string>'
                doc_types.extend(re.findall(string_pattern, match))

        return doc_types

    def _parse_app_extensions(self, extracted_path: Path) -> list[IPCComponent]:
        """Parse iOS app extensions."""
        extensions = []

        # Look for extension plists in Plugins directory
        plugins_dir = extracted_path / "Plugins"
        if plugins_dir.exists():
            for ext_dir in plugins_dir.iterdir():
                if ext_dir.is_dir():
                    ext_plist = ext_dir / "Info.plist"
                    if ext_plist.exists():
                        try:
                            content = ext_plist.read_text(errors='ignore')
                            # Get extension point
                            ext_point_pattern = r'<key>NSExtensionPointIdentifier</key>\s*<string>([^<]+)</string>'
                            match = re.search(ext_point_pattern, content)
                            ext_point = match.group(1) if match else "unknown"

                            extensions.append(IPCComponent(
                                component_type="app_extension",
                                name=ext_dir.name,
                                is_exported=True,
                                url_schemes=[ext_point],
                                source_file=f"Plugins/{ext_dir.name}/Info.plist"
                            ))
                        except:
                            pass

        return extensions

    def _check_vulnerabilities(self, component: IPCComponent, platform: str):
        """Check component for specific vulnerabilities."""
        if platform == "android":
            self._check_android_vulnerabilities(component)
        else:
            self._check_ios_vulnerabilities(component)

    def _check_android_vulnerabilities(self, component: IPCComponent):
        """Check Android component for vulnerabilities."""
        # Exported without permission
        if component.is_exported and not component.permission_required:
            if component.component_type == "provider":
                component.vulnerabilities.append("exported_provider_no_permission")
            elif component.component_type == "service":
                component.vulnerabilities.append("exported_service_no_permission")
            elif component.component_type == "receiver":
                component.vulnerabilities.append("exported_receiver_no_permission")
            elif component.component_type == "activity":
                # Check if activity handles sensitive actions
                for filter_info in component.intent_filters:
                    for action in filter_info.get("actions", []):
                        if any(sensitive in action.lower() for sensitive in
                               ["login", "auth", "payment", "settings", "admin"]):
                            component.vulnerabilities.append("sensitive_activity_exported")
                            break

        # Check for browsable activities (deep links)
        for filter_info in component.intent_filters:
            if "android.intent.category.BROWSABLE" in filter_info.get("categories", []):
                # Check for data validation
                data_schemes = [d.get("scheme") for d in filter_info.get("data", [])]
                if data_schemes:
                    component.vulnerabilities.append("browsable_activity")
                    component.url_schemes.extend([s for s in data_schemes if s])

        # Check for implicit intents in services
        if component.component_type == "service":
            for filter_info in component.intent_filters:
                if filter_info.get("actions") and component.is_exported:
                    component.vulnerabilities.append("implicit_intent_service")

    def _check_ios_vulnerabilities(self, component: IPCComponent):
        """Check iOS component for vulnerabilities."""
        if component.component_type == "url_scheme":
            # All URL schemes are potentially vulnerable to hijacking
            component.vulnerabilities.append("url_scheme_hijacking_risk")

            # Check for sensitive schemes
            for scheme in component.url_schemes:
                if any(sensitive in scheme.lower() for sensitive in
                       ["auth", "login", "oauth", "callback", "pay"]):
                    component.vulnerabilities.append("sensitive_url_scheme")
                    break

    def _create_exported_findings(
        self,
        components: list[IPCComponent],
        app: MobileApp
    ) -> list[AnalyzerResult]:
        """Create findings for exported components without permissions."""
        results = []

        # Group by type
        by_type = {}
        for c in components:
            if c.component_type not in by_type:
                by_type[c.component_type] = []
            by_type[c.component_type].append(c)

        for comp_type, comps in by_type.items():
            severity = "high" if comp_type in ["provider", "service"] else "medium"

            component_list = "\n".join([f"- {c.name}" for c in comps[:10]])

            results.append(AnalyzerResult(
                title=f"Exported {comp_type.title()}s Without Permission ({len(comps)})",
                description=f"The following {comp_type}s are exported without requiring permissions:\n\n{component_list}",
                severity=severity,
                category="IPC Security",
                impact=f"Any app can interact with these {comp_type}s, potentially leading to data leakage, unauthorized actions, or denial of service.",
                remediation=f"1. Set android:exported='false' if not needed\n2. Add permission requirement with android:permission\n3. Validate all input from external sources",
                file_path="AndroidManifest.xml",
                cwe_id="CWE-926",
                cwe_name="Improper Export of Android Application Components",
                owasp_masvs_category="MASVS-PLATFORM",
                owasp_masvs_control="MSTG-PLATFORM-1",
                poc_commands=[
                    f"adb shell am start -n {app.package_name}/{comps[0].name}" if comp_type == "activity" else None,
                    f"adb shell content query --uri content://{app.package_name}" if comp_type == "provider" else None,
                ],
                metadata={
                    "component_type": comp_type,
                    "components": [c.name for c in comps],
                }
            ))

        return results

    def _create_vulnerability_findings(
        self,
        components: list[IPCComponent],
        app: MobileApp
    ) -> list[AnalyzerResult]:
        """Create findings for specific vulnerabilities."""
        results = []

        # Group vulnerabilities
        vuln_components = {}
        for c in components:
            for v in c.vulnerabilities:
                if v not in vuln_components:
                    vuln_components[v] = []
                vuln_components[v].append(c)

        vuln_info = {
            "grant_uri_permissions_enabled": {
                "title": "Content Provider with grantUriPermissions",
                "severity": "high",
                "description": "Content providers with grantUriPermissions enabled may allow unauthorized access to protected data through URI permissions.",
                "remediation": "1. Remove grantUriPermissions if not needed\n2. Use path-permission to restrict access\n3. Validate URI patterns carefully",
            },
            "browsable_activity": {
                "title": "Browsable Activity (Deep Link Handler)",
                "severity": "medium",
                "description": "Activities with BROWSABLE category can be invoked via URLs, which may be exploited for phishing or unauthorized actions.",
                "remediation": "1. Validate all parameters from deep links\n2. Don't trust deep link data for authentication\n3. Use App Links for verified domains",
            },
            "url_scheme_hijacking_risk": {
                "title": "URL Scheme Hijacking Risk",
                "severity": "medium",
                "description": "Custom URL schemes can be registered by malicious apps, potentially intercepting sensitive callbacks.",
                "remediation": "1. Use Universal Links instead of custom schemes\n2. Don't pass sensitive data via URL schemes\n3. Implement proper validation of scheme callbacks",
            },
            "sensitive_url_scheme": {
                "title": "Sensitive Data in URL Scheme",
                "severity": "high",
                "description": "URL schemes appear to handle authentication or payment flows, which are high-value attack targets.",
                "remediation": "1. Use Universal Links with domain verification\n2. Implement proper state validation\n3. Don't pass tokens directly in URLs",
            },
        }

        for vuln_type, comps in vuln_components.items():
            if vuln_type in vuln_info:
                info = vuln_info[vuln_type]
                component_list = "\n".join([f"- {c.name}" for c in comps[:10]])

                results.append(AnalyzerResult(
                    title=f"{info['title']} ({len(comps)} components)",
                    description=f"{info['description']}\n\n**Affected components:**\n{component_list}",
                    severity=info["severity"],
                    category="IPC Security",
                    impact="May allow unauthorized access or actions from other applications.",
                    remediation=info["remediation"],
                    cwe_id="CWE-927",
                    cwe_name="Use of Implicit Intent for Sensitive Communication",
                    owasp_masvs_category="MASVS-PLATFORM",
                    owasp_masvs_control="MSTG-PLATFORM-1",
                    metadata={
                        "vulnerability_type": vuln_type,
                        "components": [c.name for c in comps],
                    }
                ))

        return results

    def _create_url_scheme_finding(
        self,
        components: list[IPCComponent],
        app: MobileApp
    ) -> AnalyzerResult:
        """Create finding for URL scheme handlers."""
        all_schemes = []
        for c in components:
            all_schemes.extend(c.url_schemes)

        scheme_list = "\n".join([f"- {s}" for s in set(all_schemes)])

        return AnalyzerResult(
            title=f"URL Schemes Registered ({len(set(all_schemes))})",
            description=f"The application registers the following URL schemes:\n\n{scheme_list}",
            severity="info",
            category="IPC Security",
            impact="URL schemes can be invoked by other apps or web pages. Ensure proper validation of all incoming data.",
            remediation="1. Validate all URL parameters\n2. Don't auto-execute sensitive actions\n3. Use Universal Links where possible (iOS)\n4. Use App Links where possible (Android)",
            owasp_masvs_category="MASVS-PLATFORM",
            owasp_masvs_control="MSTG-PLATFORM-3",
            poc_verification="1. Test URL schemes with adb/xcrun\n2. Check parameter handling\n3. Verify authentication requirements",
            poc_commands=[
                f"adb shell am start -a android.intent.action.VIEW -d '{all_schemes[0]}://test'" if all_schemes else None,
            ],
            metadata={
                "schemes": list(set(all_schemes)),
            }
        )

    def _create_summary(self, components: list[IPCComponent], app: MobileApp) -> AnalyzerResult:
        """Create summary of all IPC components."""
        by_type = {}
        for c in components:
            if c.component_type not in by_type:
                by_type[c.component_type] = {"total": 0, "exported": 0, "vulnerable": 0}
            by_type[c.component_type]["total"] += 1
            if c.is_exported:
                by_type[c.component_type]["exported"] += 1
            if c.vulnerabilities:
                by_type[c.component_type]["vulnerable"] += 1

        summary_lines = []
        for comp_type, counts in by_type.items():
            summary_lines.append(
                f"- {comp_type.title()}: {counts['total']} total, {counts['exported']} exported, {counts['vulnerable']} with issues"
            )

        return AnalyzerResult(
            title=f"IPC Components Summary ({len(components)} total)",
            description=f"**Component breakdown:**\n\n" + "\n".join(summary_lines),
            severity="info",
            category="IPC Security",
            impact="Review exported components for proper access controls.",
            remediation="Minimize exported components and implement proper permission checks.",
            owasp_masvs_category="MASVS-PLATFORM",
            owasp_masvs_control="MSTG-PLATFORM-1",
            metadata={
                "by_type": by_type,
                "total_components": len(components),
                "total_exported": sum(1 for c in components if c.is_exported),
                "total_vulnerable": sum(1 for c in components if c.vulnerabilities),
            }
        )
