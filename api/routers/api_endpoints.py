"""API Endpoints discovery router."""

import csv
import io
import json
import logging
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Finding
from api.services.analyzers.api_endpoint_extractor import APIEndpoint, APIEndpointExtractor

router = APIRouter()
logger = logging.getLogger(__name__)

# Common paths to probe for hidden endpoints
COMMON_PROBE_PATHS = [
    "/admin",
    "/debug",
    "/actuator",
    "/graphql",
    "/swagger.json",
    "/swagger-ui",
    "/.env",
    "/wp-admin",
    "/api/v1/docs",
    "/health",
    "/metrics",
    "/trace",
    "/info",
]


class ProbeRequest(BaseModel):
    """Request body for endpoint probing."""
    base_urls: list[str]


class ProbeResult(BaseModel):
    """Result of a single probe."""
    url: str
    status_code: int
    response_size: int


def _parse_endpoints_from_findings(findings: list[Finding]) -> list[dict]:
    """Parse structured endpoint data from findings."""
    endpoints = []
    seen_urls = set()

    for finding in findings:
        # Try to extract endpoint list from poc_evidence or description
        # The summary finding stores endpoint data in its description/metadata
        if finding.title and "API Endpoints Extracted" in finding.title:
            # Parse the description for host info and endpoint data
            # The metadata stored in poc_evidence may have structured data
            if finding.poc_evidence:
                try:
                    data = json.loads(finding.poc_evidence)
                    if isinstance(data, dict) and "endpoints" in data:
                        for ep_data in data["endpoints"]:
                            url = ep_data.get("url", "")
                            if url and url not in seen_urls:
                                seen_urls.add(url)
                                parsed = urlparse(url)
                                endpoints.append({
                                    "url": url,
                                    "method": ep_data.get("method"),
                                    "host": parsed.netloc or "unknown",
                                    "source_file": ep_data.get("file"),
                                    "is_https": parsed.scheme == "https",
                                    "security_issues": [],
                                })
                except (json.JSONDecodeError, TypeError):
                    pass

        # Also extract from description text for individual endpoint findings
        if finding.description and finding.category in (
            "API Analysis", "API Security", "Network Security"
        ):
            # Try to find URLs in the description
            import re
            url_pattern = r'https?://[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?::\d+)?(?:/[^\s\'"<>)}\]]*)?'
            urls_found = re.findall(url_pattern, finding.description)

            # Determine security issues from the finding
            security_issues = []
            if finding.title:
                title_lower = finding.title.lower()
                if "insecure" in title_lower or "http" in title_lower:
                    security_issues.append("insecure_transport")
                if "debug" in title_lower:
                    security_issues.append("debug_endpoint")
                if "admin" in title_lower or "sensitive" in title_lower:
                    security_issues.append("admin_endpoint")
                if "swagger" in title_lower:
                    security_issues.append("swagger_exposed")

            for url in urls_found:
                if url not in seen_urls:
                    seen_urls.add(url)
                    parsed = urlparse(url)
                    endpoints.append({
                        "url": url,
                        "method": None,
                        "host": parsed.netloc or "unknown",
                        "source_file": finding.file_path,
                        "is_https": parsed.scheme == "https",
                        "security_issues": security_issues,
                    })

    return endpoints


def _endpoints_to_api_objects(endpoints: list[dict]) -> list[APIEndpoint]:
    """Convert endpoint dicts to APIEndpoint objects for export methods."""
    api_endpoints = []
    for ep in endpoints:
        parsed = urlparse(ep["url"])
        api_ep = APIEndpoint(
            url=ep["url"],
            method=ep.get("method"),
            source_file=ep.get("source_file"),
            uses_https=ep.get("is_https", parsed.scheme == "https"),
            security_issues=ep.get("security_issues", []),
        )
        api_endpoints.append(api_ep)
    return api_endpoints


@router.get("/{app_id}")
async def list_api_endpoints(
    app_id: str,
    db: AsyncSession = Depends(get_db),
):
    """List all discovered API endpoints for an app."""
    # Query findings related to API endpoint extraction
    query = select(Finding).where(
        Finding.app_id == app_id,
        or_(
            Finding.category.ilike("%API%"),
            Finding.category.ilike("%endpoint%"),
            Finding.tool == "api_endpoint_extractor",
        ),
    )
    result = await db.execute(query)
    findings = list(result.scalars().all())

    if not findings:
        return {
            "app_id": app_id,
            "endpoints": [],
            "total": 0,
            "unique_hosts": 0,
            "insecure_count": 0,
            "security_issues_count": 0,
        }

    endpoints = _parse_endpoints_from_findings(findings)

    # Compute summary stats
    unique_hosts = len(set(ep["host"] for ep in endpoints))
    insecure_count = len([ep for ep in endpoints if not ep["is_https"]])
    security_issues_count = len([ep for ep in endpoints if ep["security_issues"]])

    return {
        "app_id": app_id,
        "endpoints": endpoints,
        "total": len(endpoints),
        "unique_hosts": unique_hosts,
        "insecure_count": insecure_count,
        "security_issues_count": security_issues_count,
    }


@router.get("/{app_id}/export")
async def export_endpoints(
    app_id: str,
    format: str = Query(..., description="Export format: burp, openapi, postman, csv"),
    db: AsyncSession = Depends(get_db),
):
    """Export discovered API endpoints in various formats."""
    # Get endpoints
    query = select(Finding).where(
        Finding.app_id == app_id,
        or_(
            Finding.category.ilike("%API%"),
            Finding.category.ilike("%endpoint%"),
            Finding.tool == "api_endpoint_extractor",
        ),
    )
    result = await db.execute(query)
    findings = list(result.scalars().all())
    endpoint_dicts = _parse_endpoints_from_findings(findings)
    endpoints = _endpoints_to_api_objects(endpoint_dicts)

    if not endpoints:
        raise HTTPException(status_code=404, detail="No API endpoints found for this app")

    extractor = APIEndpointExtractor()

    if format == "burp":
        xml_content = extractor.generate_burp_import(endpoints)
        return StreamingResponse(
            io.BytesIO(xml_content.encode("utf-8")),
            media_type="application/xml",
            headers={"Content-Disposition": f"attachment; filename=api_endpoints_{app_id}.xml"},
        )

    elif format == "openapi":
        # Determine base URL from first endpoint
        base_url = ""
        if endpoints:
            parsed = urlparse(endpoints[0].url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        spec = extractor.generate_openapi_spec(endpoints, base_url)
        content = json.dumps(spec, indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=api_endpoints_{app_id}_openapi.json"},
        )

    elif format == "postman":
        collection = extractor.generate_postman_collection(endpoints, app_name=app_id)
        content = json.dumps(collection, indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=api_endpoints_{app_id}_postman.json"},
        )

    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["URL", "Method", "Host", "Source File", "HTTPS", "Security Issues"])
        for ep in endpoints:
            parsed = urlparse(ep.url)
            writer.writerow([
                ep.url,
                ep.method or "",
                parsed.netloc or "",
                ep.source_file or "",
                "Yes" if ep.uses_https else "No",
                ", ".join(ep.security_issues),
            ])
        csv_content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(csv_content.encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=api_endpoints_{app_id}.csv"},
        )

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}. Use burp, openapi, postman, or csv.")


@router.post("/{app_id}/probe")
async def probe_endpoints(
    app_id: str,
    request: ProbeRequest,
):
    """Probe hidden/common endpoints against provided base URLs."""
    if not request.base_urls:
        raise HTTPException(status_code=400, detail="At least one base URL is required")

    results: list[dict] = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(5.0, connect=3.0),
        follow_redirects=False,
        verify=False,
    ) as client:
        for base_url in request.base_urls:
            # Normalize base URL
            base = base_url.rstrip("/")

            for path in COMMON_PROBE_PATHS:
                probe_url = f"{base}{path}"
                try:
                    response = await client.head(probe_url)
                    results.append({
                        "url": probe_url,
                        "status_code": response.status_code,
                        "response_size": len(response.content),
                    })
                except httpx.TimeoutException:
                    results.append({
                        "url": probe_url,
                        "status_code": 0,
                        "response_size": 0,
                        "error": "timeout",
                    })
                except httpx.RequestError as e:
                    results.append({
                        "url": probe_url,
                        "status_code": 0,
                        "response_size": 0,
                        "error": str(e)[:100],
                    })

    # Filter to only responding paths (non-error status codes)
    responding = [r for r in results if r["status_code"] > 0]

    return {
        "app_id": app_id,
        "probed_count": len(results),
        "responding_count": len(responding),
        "results": results,
    }
