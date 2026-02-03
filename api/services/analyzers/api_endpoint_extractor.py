"""API Endpoint Extractor.

Extracts and analyzes API endpoints from mobile applications,
including REST, GraphQL, and WebSocket endpoints.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from api.models.database import MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint."""
    url: str
    method: str | None = None
    api_type: str = "rest"  # rest, graphql, websocket, grpc
    source_file: str | None = None
    line_number: int | None = None
    parameters: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    uses_https: bool = True
    is_authenticated: bool | None = None
    security_issues: list[str] = field(default_factory=list)


# URL patterns
URL_PATTERNS = [
    # Standard HTTP/HTTPS URLs
    r'https?://[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?::\d+)?(?:/[^\s\'"<>)}\]]*)?',
    # URLs with path variables
    r'https?://[^\s\'"<>]+\{[^}]+\}[^\s\'"<>]*',
]

# API patterns (relative paths)
API_PATH_PATTERNS = [
    r'["\'](?:/api/v?\d*[^\s\'"<>]*)["\']',
    r'["\'](?:/v\d+/[^\s\'"<>]*)["\']',
    r'["\'](?:/rest/[^\s\'"<>]*)["\']',
    r'["\'](?:/graphql)["\']',
]

# Base URL patterns
BASE_URL_PATTERNS = [
    r'(?:baseUrl|base_url|apiUrl|api_url|endpoint|host)\s*[:=]\s*["\']([^"\']+)["\']',
    r'BASE_URL\s*=\s*["\']([^"\']+)["\']',
    r'API_URL\s*=\s*["\']([^"\']+)["\']',
    r'SERVER_URL\s*=\s*["\']([^"\']+)["\']',
]

# HTTP method patterns
HTTP_METHOD_PATTERNS = {
    "GET": [
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'@GET\s*\(\s*["\']([^"\']+)["\']',
        r'method\s*:\s*["\']GET["\']',
    ],
    "POST": [
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'@POST\s*\(\s*["\']([^"\']+)["\']',
        r'method\s*:\s*["\']POST["\']',
    ],
    "PUT": [
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'@PUT\s*\(\s*["\']([^"\']+)["\']',
    ],
    "DELETE": [
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
        r'@DELETE\s*\(\s*["\']([^"\']+)["\']',
    ],
    "PATCH": [
        r'\.patch\s*\(\s*["\']([^"\']+)["\']',
        r'@PATCH\s*\(\s*["\']([^"\']+)["\']',
    ],
}

# Security-sensitive patterns
SECURITY_PATTERNS = {
    "hardcoded_api_key": r'(?:api[_-]?key|apikey|api_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
    "hardcoded_auth": r'(?:authorization|auth[_-]?token|bearer)\s*[:=]\s*["\']([^"\']{20,})["\']',
    "debug_endpoint": r'/debug|/test|/staging|/dev/',
    "admin_endpoint": r'/admin|/management|/internal|/private',
    "swagger_endpoint": r'/swagger|/api-docs|/openapi',
}

# Known vulnerable endpoint patterns
VULNERABLE_PATTERNS = {
    "graphql_introspection": r'/graphql.*introspection',
    "actuator": r'/actuator|/health|/metrics|/env',
    "debug_vars": r'/debug/vars|/__debug__',
}


class APIEndpointExtractor(BaseAnalyzer):
    """Extracts and analyzes API endpoints from mobile apps."""

    name = "api_endpoint_extractor"
    description = "Extracts API endpoints and analyzes them for security issues"

    async def analyze(self, app: MobileApp, extracted_path: Path) -> list[AnalyzerResult]:
        """Extract and analyze API endpoints."""
        results = []
        endpoints: list[APIEndpoint] = []
        base_urls: list[str] = []

        # Source file extensions to scan
        source_extensions = [".java", ".kt", ".swift", ".m", ".js", ".ts", ".dart", ".json", ".xml", ".plist"]

        for ext in source_extensions:
            for source_file in extracted_path.rglob(f"*{ext}"):
                # Skip common non-relevant files
                if any(skip in str(source_file) for skip in ["node_modules", "test", "mock", ".gradle"]):
                    continue

                try:
                    content = source_file.read_text(errors='ignore')
                    rel_path = str(source_file.relative_to(extracted_path))

                    # Extract base URLs
                    for pattern in BASE_URL_PATTERNS:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        base_urls.extend(matches)

                    # Extract full URLs
                    for pattern in URL_PATTERNS:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            url = match.group(0)
                            if self._is_valid_api_url(url):
                                endpoint = self._create_endpoint(url, content, rel_path, match.start())
                                endpoints.append(endpoint)

                    # Extract API paths with methods
                    for method, patterns in HTTP_METHOD_PATTERNS.items():
                        for pattern in patterns:
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                path = match.group(1) if match.lastindex else match.group(0)
                                endpoint = APIEndpoint(
                                    url=path,
                                    method=method,
                                    source_file=rel_path,
                                    line_number=content[:match.start()].count('\n') + 1
                                )
                                endpoints.append(endpoint)

                except Exception as e:
                    logger.debug(f"Error processing {source_file}: {e}")

        # Parse network_security_config.xml for Android
        nsc_endpoints = await self._parse_network_security_config(extracted_path)
        endpoints.extend(nsc_endpoints)

        # Deduplicate endpoints
        unique_endpoints = self._deduplicate_endpoints(endpoints)

        # Analyze endpoints for security issues
        for endpoint in unique_endpoints:
            self._analyze_endpoint_security(endpoint)

        # Create findings
        if unique_endpoints:
            results.append(self._create_summary_finding(unique_endpoints, base_urls, app))

        # Create findings for security issues
        insecure_endpoints = [e for e in unique_endpoints if not e.uses_https]
        if insecure_endpoints:
            results.append(self._create_insecure_transport_finding(insecure_endpoints, app))

        debug_endpoints = [e for e in unique_endpoints if any('debug' in i or 'test' in i for i in e.security_issues)]
        if debug_endpoints:
            results.append(self._create_debug_endpoint_finding(debug_endpoints, app))

        exposed_endpoints = [e for e in unique_endpoints if any('swagger' in i or 'admin' in i for i in e.security_issues)]
        if exposed_endpoints:
            results.append(self._create_exposed_endpoint_finding(exposed_endpoints, app))

        return results

    def _is_valid_api_url(self, url: str) -> bool:
        """Check if URL is a valid API endpoint."""
        # Skip common non-API URLs
        skip_patterns = [
            r'\.(?:png|jpg|jpeg|gif|svg|ico|css|js|woff|ttf|eot)$',
            r'googleapis\.com/(?:auth|oauth)',
            r'firebase.*\.com',
            r'crashlytics',
            r'analytics',
            r'play\.google\.com',
            r'itunes\.apple\.com',
            r'github\.com',
            r'stackoverflow\.com',
            r'example\.com',
            r'localhost',
            r'127\.0\.0\.1',
            r'10\.0\.2\.2',  # Android emulator localhost
        ]

        for pattern in skip_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False

        # Must have a valid host
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc and parsed.netloc != 'localhost')
        except:
            return False

    def _create_endpoint(self, url: str, content: str, file_path: str, position: int) -> APIEndpoint:
        """Create an endpoint object from extracted URL."""
        parsed = urlparse(url)

        endpoint = APIEndpoint(
            url=url,
            source_file=file_path,
            line_number=content[:position].count('\n') + 1,
            uses_https=parsed.scheme == 'https',
        )

        # Detect API type
        if 'graphql' in url.lower():
            endpoint.api_type = 'graphql'
        elif 'ws://' in url or 'wss://' in url:
            endpoint.api_type = 'websocket'
        elif 'grpc' in url.lower():
            endpoint.api_type = 'grpc'

        return endpoint

    def _analyze_endpoint_security(self, endpoint: APIEndpoint):
        """Analyze endpoint for security issues."""
        url_lower = endpoint.url.lower()

        # Check for HTTP
        if not endpoint.uses_https and not url_lower.startswith('wss://'):
            endpoint.security_issues.append("insecure_transport")

        # Check for debug/test endpoints
        if re.search(SECURITY_PATTERNS["debug_endpoint"], url_lower):
            endpoint.security_issues.append("debug_endpoint")

        # Check for admin endpoints
        if re.search(SECURITY_PATTERNS["admin_endpoint"], url_lower):
            endpoint.security_issues.append("admin_endpoint")

        # Check for Swagger/API docs exposure
        if re.search(SECURITY_PATTERNS["swagger_endpoint"], url_lower):
            endpoint.security_issues.append("swagger_exposed")

        # Check for vulnerable patterns
        for issue, pattern in VULNERABLE_PATTERNS.items():
            if re.search(pattern, url_lower):
                endpoint.security_issues.append(issue)

    async def _parse_network_security_config(self, extracted_path: Path) -> list[APIEndpoint]:
        """Parse Android network_security_config.xml."""
        endpoints = []
        nsc_file = extracted_path / "res" / "xml" / "network_security_config.xml"

        if nsc_file.exists():
            try:
                content = nsc_file.read_text(errors='ignore')

                # Extract domain configs
                domain_pattern = r'<domain[^>]*>([^<]+)</domain>'
                domains = re.findall(domain_pattern, content)

                # Check for cleartext traffic
                cleartext_pattern = r'cleartextTrafficPermitted\s*=\s*["\']true["\']'
                allows_cleartext = bool(re.search(cleartext_pattern, content))

                for domain in domains:
                    endpoint = APIEndpoint(
                        url=f"https://{domain}",
                        source_file="res/xml/network_security_config.xml",
                        uses_https=not allows_cleartext,
                    )
                    if allows_cleartext:
                        endpoint.security_issues.append("cleartext_allowed")
                    endpoints.append(endpoint)

            except Exception as e:
                logger.debug(f"Error parsing network_security_config.xml: {e}")

        return endpoints

    def _deduplicate_endpoints(self, endpoints: list[APIEndpoint]) -> list[APIEndpoint]:
        """Remove duplicate endpoints."""
        seen = set()
        unique = []

        for endpoint in endpoints:
            # Normalize URL for comparison
            normalized = endpoint.url.lower().rstrip('/')
            if normalized not in seen:
                seen.add(normalized)
                unique.append(endpoint)

        return unique

    def _create_summary_finding(
        self,
        endpoints: list[APIEndpoint],
        base_urls: list[str],
        app: MobileApp
    ) -> AnalyzerResult:
        """Create summary finding for extracted endpoints."""
        # Group by host
        hosts = {}
        for ep in endpoints:
            try:
                parsed = urlparse(ep.url)
                host = parsed.netloc or "unknown"
                if host not in hosts:
                    hosts[host] = []
                hosts[host].append(ep)
            except:
                pass

        host_summary = "\n".join([
            f"- {host}: {len(eps)} endpoints"
            for host, eps in sorted(hosts.items(), key=lambda x: -len(x[1]))
        ])

        unique_base_urls = list(set(base_urls))
        base_url_text = "\n".join([f"- {url}" for url in unique_base_urls]) if unique_base_urls else "None detected"

        # Count issues
        insecure_count = len([e for e in endpoints if not e.uses_https])
        debug_count = len([e for e in endpoints if "debug_endpoint" in e.security_issues])

        return AnalyzerResult(
            title=f"API Endpoints Extracted ({len(endpoints)} endpoints)",
            description=f"Extracted {len(endpoints)} API endpoints from the application.\n\n**Hosts:**\n{host_summary}\n\n**Base URLs:**\n{base_url_text}",
            severity="info",
            category="API Analysis",
            impact=f"Found {insecure_count} endpoints using insecure transport, {debug_count} debug/test endpoints.",
            remediation="1. Review all endpoints for proper authentication\n2. Ensure HTTPS is used everywhere\n3. Remove debug endpoints from production\n4. Implement proper API security controls",
            owasp_masvs_category="MASVS-NETWORK",
            owasp_masvs_control="MSTG-NETWORK-1",
            metadata={
                "total_endpoints": len(endpoints),
                "unique_hosts": len(hosts),
                "base_urls": unique_base_urls,
                "insecure_count": insecure_count,
                "endpoints": [
                    {"url": e.url, "method": e.method, "file": e.source_file}
                    for e in endpoints[:50]
                ],
            }
        )

    def _create_insecure_transport_finding(
        self,
        endpoints: list[APIEndpoint],
        app: MobileApp
    ) -> AnalyzerResult:
        """Create finding for endpoints using HTTP."""
        endpoint_list = "\n".join([
            f"- {e.url} ({e.source_file}:{e.line_number or '?'})"
            for e in endpoints
        ])

        return AnalyzerResult(
            title=f"Insecure Transport: {len(endpoints)} HTTP Endpoints",
            description=f"The following endpoints use unencrypted HTTP:\n\n{endpoint_list}",
            severity="high",
            category="Network Security",
            impact="Data transmitted over HTTP can be intercepted and modified by attackers on the same network (MITM attacks).",
            remediation="1. Change all HTTP URLs to HTTPS\n2. Implement certificate pinning\n3. Use network security config to block cleartext traffic",
            cwe_id="CWE-319",
            cwe_name="Cleartext Transmission of Sensitive Information",
            owasp_masvs_category="MASVS-NETWORK",
            owasp_masvs_control="MSTG-NETWORK-1",
            poc_verification="1. Configure proxy (Burp/mitmproxy)\n2. Intercept app traffic\n3. Observe unencrypted requests",
            metadata={
                "endpoints": [e.url for e in endpoints],
            }
        )

    def _create_debug_endpoint_finding(
        self,
        endpoints: list[APIEndpoint],
        app: MobileApp
    ) -> AnalyzerResult:
        """Create finding for debug/test endpoints."""
        endpoint_list = "\n".join([f"- {e.url}" for e in endpoints])

        return AnalyzerResult(
            title=f"Debug/Test Endpoints Detected ({len(endpoints)})",
            description=f"Debug or test endpoints found ({len(endpoints)}):\n\n{endpoint_list}",
            severity="medium",
            category="API Security",
            impact="Debug endpoints may expose sensitive functionality, bypass authentication, or leak information.",
            remediation="1. Remove debug endpoints from production builds\n2. Use build variants to exclude test code\n3. Implement proper access controls",
            cwe_id="CWE-489",
            cwe_name="Active Debug Code",
            owasp_masvs_category="MASVS-CODE",
            owasp_masvs_control="MSTG-CODE-2",
            metadata={
                "endpoints": [e.url for e in endpoints],
            }
        )

    def _create_exposed_endpoint_finding(
        self,
        endpoints: list[APIEndpoint],
        app: MobileApp
    ) -> AnalyzerResult:
        """Create finding for exposed admin/swagger endpoints."""
        endpoint_list = "\n".join([f"- {e.url}" for e in endpoints])

        return AnalyzerResult(
            title=f"Sensitive Endpoints Exposed ({len(endpoints)})",
            description=f"Admin or API documentation endpoints found ({len(endpoints)}):\n\n{endpoint_list}",
            severity="medium",
            category="API Security",
            impact="Exposed admin endpoints or API documentation can provide attackers with valuable information about the API structure and potential attack vectors.",
            remediation="1. Restrict access to admin endpoints\n2. Disable Swagger/API docs in production\n3. Implement proper authentication for sensitive endpoints",
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information",
            owasp_masvs_category="MASVS-NETWORK",
            owasp_masvs_control="MSTG-NETWORK-1",
            metadata={
                "endpoints": [e.url for e in endpoints],
            }
        )

    def generate_burp_import(self, endpoints: list[APIEndpoint]) -> str:
        """Generate Burp Suite import file (XML format)."""
        xml_items = []
        for ep in endpoints:
            try:
                parsed = urlparse(ep.url)
                host = parsed.netloc.split(':')[0]
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                path = parsed.path or '/'

                xml_items.append(f"""
  <item>
    <host>{host}</host>
    <port>{port}</port>
    <protocol>{parsed.scheme}</protocol>
    <method>{ep.method or 'GET'}</method>
    <path>{path}</path>
  </item>""")
            except:
                pass

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<items burpVersion="2023.1" exportTime="{__import__('datetime').datetime.now().isoformat()}">
{''.join(xml_items)}
</items>"""

    def generate_openapi_spec(self, endpoints: list[APIEndpoint], base_url: str) -> dict:
        """Generate basic OpenAPI spec from extracted endpoints."""
        paths = {}

        for ep in endpoints:
            try:
                parsed = urlparse(ep.url)
                path = parsed.path or '/'

                if path not in paths:
                    paths[path] = {}

                method = (ep.method or 'get').lower()
                paths[path][method] = {
                    "summary": f"Extracted endpoint from {ep.source_file or 'unknown'}",
                    "responses": {
                        "200": {"description": "Success"}
                    }
                }
            except:
                pass

        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Extracted API Endpoints",
                "version": "1.0.0",
            },
            "servers": [{"url": base_url}] if base_url else [],
            "paths": paths,
        }
