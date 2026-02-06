"""
Network Traffic Analyzer Service

Captures and analyzes network traffic from mobile apps:
- MITM proxy integration
- SSL/TLS inspection
- API endpoint discovery
- Sensitive data leak detection
- Certificate validation testing
"""

import asyncio
import hashlib
import json
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class TrafficCaptureMethod(str, Enum):
    """Traffic capture method."""
    MITMPROXY = "mitmproxy"
    BURP = "burp"
    CHARLES = "charles"
    FRIDA = "frida"


class TrafficAnalyzer:
    """Analyzes captured network traffic."""

    # Patterns for sensitive data detection
    SENSITIVE_PATTERNS = {
        "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
        "api_key": r"(?i)(api[_-]?key|apikey|access[_-]?token)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_-]{16,})",
        "password": r"(?i)(password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?([^\s\"'&]+)",
        "bearer_token": r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "jwt": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "aws_key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    }

    # Insecure patterns
    INSECURE_PATTERNS = {
        "http_endpoint": r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
        "hardcoded_ip": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "internal_api": r"(?i)(internal|staging|dev|test)\.(api|service|backend)",
        "debug_endpoint": r"(?i)/debug|/test|/dev|/staging",
    }

    def __init__(self):
        self.compiled_sensitive = {
            name: re.compile(pattern)
            for name, pattern in self.SENSITIVE_PATTERNS.items()
        }
        self.compiled_insecure = {
            name: re.compile(pattern)
            for name, pattern in self.INSECURE_PATTERNS.items()
        }

    def analyze_request(self, request: dict) -> list[dict]:
        """Analyze a single HTTP request."""
        findings = []

        url = request.get("url", "")
        headers = request.get("headers", {})
        body = request.get("body", "")
        method = request.get("method", "GET")

        # Check for sensitive data in URL
        findings.extend(self._check_sensitive_data(url, "url", request))

        # Check for sensitive data in headers
        for header_name, header_value in headers.items():
            findings.extend(
                self._check_sensitive_data(
                    f"{header_name}: {header_value}",
                    f"header:{header_name}",
                    request
                )
            )

        # Check for sensitive data in body
        if body:
            findings.extend(self._check_sensitive_data(body, "body", request))

        # Check for insecure patterns
        findings.extend(self._check_insecure_patterns(url, request))

        # Check for missing security headers in response
        if "response" in request:
            findings.extend(self._check_security_headers(request["response"]))

        return findings

    def _check_sensitive_data(
        self, content: str, location: str, request: dict
    ) -> list[dict]:
        """Check content for sensitive data patterns."""
        findings = []

        for pattern_name, pattern in self.compiled_sensitive.items():
            matches = pattern.findall(content)
            if matches:
                findings.append({
                    "type": "sensitive_data_exposure",
                    "subtype": pattern_name,
                    "location": location,
                    "url": request.get("url", ""),
                    "method": request.get("method", ""),
                    "severity": "high" if pattern_name in ["credit_card", "ssn", "private_key", "aws_key"] else "medium",
                    "description": f"Potential {pattern_name.replace('_', ' ')} detected in {location}",
                    "match_count": len(matches) if isinstance(matches, list) else 1,
                })

        return findings

    def _check_insecure_patterns(self, url: str, request: dict) -> list[dict]:
        """Check for insecure patterns."""
        findings = []

        for pattern_name, pattern in self.compiled_insecure.items():
            if pattern.search(url):
                findings.append({
                    "type": "insecure_communication",
                    "subtype": pattern_name,
                    "url": url,
                    "method": request.get("method", ""),
                    "severity": "medium" if pattern_name == "http_endpoint" else "low",
                    "description": f"Insecure pattern detected: {pattern_name.replace('_', ' ')}",
                })

        return findings

    def _check_security_headers(self, response: dict) -> list[dict]:
        """Check for missing security headers in response."""
        findings = []
        headers = response.get("headers", {})

        # Normalize header names to lowercase
        headers_lower = {k.lower(): v for k, v in headers.items()}

        required_headers = {
            "strict-transport-security": "Missing HSTS header",
            "x-content-type-options": "Missing X-Content-Type-Options header",
            "x-frame-options": "Missing X-Frame-Options header",
            "content-security-policy": "Missing Content-Security-Policy header",
        }

        for header, description in required_headers.items():
            if header not in headers_lower:
                findings.append({
                    "type": "missing_security_header",
                    "subtype": header,
                    "url": response.get("url", ""),
                    "severity": "low",
                    "description": description,
                })

        return findings

    def extract_endpoints(self, requests: list[dict]) -> list[dict]:
        """Extract unique API endpoints from traffic."""
        endpoints = {}

        for req in requests:
            url = req.get("url", "")
            method = req.get("method", "GET")

            # Parse URL to extract base endpoint
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)

            # Normalize path by replacing IDs with placeholders
            path = re.sub(r'/\d+(?=/|$)', '/{id}', parsed.path)
            path = re.sub(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '/{uuid}', path)

            key = f"{method}:{parsed.netloc}{path}"

            if key not in endpoints:
                endpoints[key] = {
                    "method": method,
                    "host": parsed.netloc,
                    "path": path,
                    "query_params": list(parse_qs(parsed.query).keys()),
                    "content_types": set(),
                    "status_codes": set(),
                    "request_count": 0,
                }

            endpoints[key]["request_count"] += 1

            if "content-type" in req.get("headers", {}):
                endpoints[key]["content_types"].add(req["headers"]["content-type"])

            if "response" in req and "status_code" in req["response"]:
                endpoints[key]["status_codes"].add(req["response"]["status_code"])

        # Convert sets to lists for JSON serialization
        for endpoint in endpoints.values():
            endpoint["content_types"] = list(endpoint["content_types"])
            endpoint["status_codes"] = list(endpoint["status_codes"])

        return list(endpoints.values())


class NetworkTrafficService:
    """Service for network traffic capture and analysis."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.analyzer = TrafficAnalyzer()

    async def create_capture_session(
        self,
        app_id: str,
        device_id: str,
        capture_method: str = "mitmproxy",
        proxy_port: int = 8080,
    ) -> dict:
        """Create a new traffic capture session."""
        session_id = str(uuid4())

        query = """
            INSERT INTO traffic_capture_sessions (
                session_id, app_id, device_id, capture_method,
                proxy_port, status, started_at
            ) VALUES (
                :session_id, :app_id, :device_id, :capture_method,
                :proxy_port, 'active', :started_at
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "app_id": app_id,
            "device_id": device_id,
            "capture_method": capture_method,
            "proxy_port": proxy_port,
            "started_at": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else {"session_id": session_id}

    async def stop_capture_session(self, session_id: str) -> bool:
        """Stop a traffic capture session."""
        query = """
            UPDATE traffic_capture_sessions
            SET status = 'stopped', completed_at = :completed_at
            WHERE session_id = :session_id AND status = 'active'
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "completed_at": datetime.utcnow(),
        })
        await self.db.commit()

        return result.rowcount > 0

    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get capture session details."""
        query = """
            SELECT * FROM traffic_capture_sessions
            WHERE session_id = :session_id
        """
        result = await self.db.execute(query, {"session_id": session_id})
        row = result.fetchone()
        return dict(row._mapping) if row else None

    async def list_sessions(
        self,
        app_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict]:
        """List traffic capture sessions."""
        query = """
            SELECT * FROM traffic_capture_sessions
            WHERE (:app_id IS NULL OR app_id = :app_id)
            AND (:status IS NULL OR status = :status)
            ORDER BY started_at DESC
        """

        result = await self.db.execute(query, {
            "app_id": app_id,
            "status": status,
        })

        return [dict(row._mapping) for row in result.fetchall()]

    async def add_captured_request(
        self,
        session_id: str,
        request_data: dict,
    ) -> dict:
        """Add a captured HTTP request to the session."""
        request_id = str(uuid4())

        # Calculate request hash for deduplication
        request_hash = hashlib.md5(
            json.dumps(request_data, sort_keys=True).encode()
        ).hexdigest()

        query = """
            INSERT INTO captured_requests (
                request_id, session_id, request_hash,
                method, url, headers, body,
                response_status, response_headers, response_body,
                timestamp
            ) VALUES (
                :request_id, :session_id, :request_hash,
                :method, :url, :headers, :body,
                :response_status, :response_headers, :response_body,
                :timestamp
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "request_id": request_id,
            "session_id": session_id,
            "request_hash": request_hash,
            "method": request_data.get("method", "GET"),
            "url": request_data.get("url", ""),
            "headers": json.dumps(request_data.get("headers", {})),
            "body": request_data.get("body"),
            "response_status": request_data.get("response", {}).get("status_code"),
            "response_headers": json.dumps(request_data.get("response", {}).get("headers", {})),
            "response_body": request_data.get("response", {}).get("body"),
            "timestamp": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else {"request_id": request_id}

    async def get_captured_requests(
        self,
        session_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Get captured requests for a session."""
        query = """
            SELECT * FROM captured_requests
            WHERE session_id = :session_id
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "limit": limit,
            "offset": offset,
        })

        requests = []
        for row in result.fetchall():
            req = dict(row._mapping)
            # Parse JSON fields
            if req.get("headers"):
                req["headers"] = json.loads(req["headers"])
            if req.get("response_headers"):
                req["response_headers"] = json.loads(req["response_headers"])
            requests.append(req)

        return requests

    async def analyze_session(self, session_id: str) -> dict:
        """Analyze all traffic in a capture session."""
        requests = await self.get_captured_requests(session_id, limit=10000)

        all_findings = []
        for req in requests:
            # Convert to format expected by analyzer
            request_data = {
                "url": req.get("url", ""),
                "method": req.get("method", "GET"),
                "headers": req.get("headers", {}),
                "body": req.get("body", ""),
                "response": {
                    "status_code": req.get("response_status"),
                    "headers": req.get("response_headers", {}),
                    "body": req.get("response_body", ""),
                }
            }
            findings = self.analyzer.analyze_request(request_data)
            all_findings.extend(findings)

        # Extract endpoints
        endpoints = self.analyzer.extract_endpoints([
            {
                "url": r.get("url", ""),
                "method": r.get("method", "GET"),
                "headers": r.get("headers", {}),
                "response": {"status_code": r.get("response_status")},
            }
            for r in requests
        ])

        # Summary statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in all_findings:
            sev = finding.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "session_id": session_id,
            "total_requests": len(requests),
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "findings": all_findings[:100],  # Limit for response size
            "endpoints": endpoints,
            "analyzed_at": datetime.utcnow().isoformat(),
        }

    async def create_findings_from_analysis(
        self,
        session_id: str,
        app_id: str,
        scan_id: Optional[str] = None,
    ) -> list[str]:
        """Create findings from traffic analysis."""
        analysis = await self.analyze_session(session_id)

        finding_ids = []
        for traffic_finding in analysis.get("findings", []):
            finding_id = str(uuid4())

            query = """
                INSERT INTO findings (
                    finding_id, app_id, scan_id, title, description,
                    severity, category, tool, status, created_at
                ) VALUES (
                    :finding_id, :app_id, :scan_id, :title, :description,
                    :severity, :category, :tool, 'open', :created_at
                )
                RETURNING finding_id
            """

            await self.db.execute(query, {
                "finding_id": finding_id,
                "app_id": app_id,
                "scan_id": scan_id,
                "title": f"Network: {traffic_finding['type'].replace('_', ' ').title()}",
                "description": traffic_finding.get("description", ""),
                "severity": traffic_finding.get("severity", "medium"),
                "category": "network",
                "tool": "network_traffic_analyzer",
                "created_at": datetime.utcnow(),
            })

            finding_ids.append(finding_id)

        await self.db.commit()
        return finding_ids

    async def get_mitmproxy_config(self, session_id: str) -> dict:
        """Get mitmproxy configuration for a session."""
        session = await self.get_session(session_id)
        if not session:
            raise ValueError("Session not found")

        return {
            "mode": "regular",
            "listen_port": session.get("proxy_port", 8080),
            "ssl_insecure": True,
            "scripts": [
                "mobilicustos_addon.py"  # Custom mitmproxy addon
            ],
            "webhook_url": f"/api/traffic/sessions/{session_id}/requests",
            "session_id": session_id,
        }

    async def export_har(self, session_id: str) -> dict:
        """Export captured traffic as HAR format."""
        requests = await self.get_captured_requests(session_id, limit=10000)

        entries = []
        for req in requests:
            entry = {
                "startedDateTime": req.get("timestamp", "").isoformat() if req.get("timestamp") else "",
                "request": {
                    "method": req.get("method", "GET"),
                    "url": req.get("url", ""),
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in req.get("headers", {}).items()
                    ],
                    "postData": {
                        "text": req.get("body", "")
                    } if req.get("body") else None,
                },
                "response": {
                    "status": req.get("response_status", 0),
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in req.get("response_headers", {}).items()
                    ],
                    "content": {
                        "text": req.get("response_body", "")
                    }
                },
            }
            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Mobilicustos",
                    "version": "0.1.1"
                },
                "entries": entries
            }
        }
