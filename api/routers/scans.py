"""Scans router."""

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Finding, MobileApp, Scan
from api.models.schemas import PaginatedResponse, ScanCreate, ScanResponse
from api.services.scan_orchestrator import STATIC_ANALYZERS, run_scan

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("", response_model=PaginatedResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    app_id: str | None = None,
    status: str | None = None,
    scan_type: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all scans with pagination and filters."""
    query = select(Scan)

    if app_id:
        query = query.where(Scan.app_id == app_id)
    if status:
        query = query.where(Scan.status == status)
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(Scan.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    scans = result.scalars().all()

    return PaginatedResponse(
        items=[ScanResponse.model_validate(scan) for scan in scans],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.delete("/purge/{app_id}")
async def purge_scans(app_id: str, db: AsyncSession = Depends(get_db)):
    """Delete ALL scans (and cascade-delete findings) for a given app_id."""
    result = await db.execute(
        select(Scan).where(Scan.app_id == app_id)
    )
    scans = result.scalars().all()

    if not scans:
        raise HTTPException(status_code=404, detail="No scans found for this app")

    # Block if any scan is currently running
    running = [s for s in scans if s.status == "running"]
    if running:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot purge: {len(running)} scan(s) still running. Cancel them first.",
        )

    deleted_count = len(scans)
    for scan in scans:
        await db.delete(scan)

    await db.commit()

    return {"message": f"Purged {deleted_count} scans", "deleted_count": deleted_count}


@router.post("/bulk-delete")
async def bulk_delete_scans(
    scan_ids: list[UUID],
    db: AsyncSession = Depends(get_db),
):
    """Bulk delete selected scans and their associated findings."""
    if not scan_ids:
        raise HTTPException(status_code=422, detail="No scan IDs provided")

    result = await db.execute(
        select(Scan).where(Scan.scan_id.in_(scan_ids))
    )
    scans = result.scalars().all()

    if not scans:
        raise HTTPException(status_code=404, detail="No scans found")

    # Block if any selected scan is running
    running = [s for s in scans if s.status == "running"]
    if running:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete {len(running)} running scan(s). Cancel them first.",
        )

    deleted_count = len(scans)
    for scan in scans:
        await db.delete(scan)

    await db.commit()

    return {"message": f"Deleted {deleted_count} scans", "deleted_count": deleted_count}


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get a scan by ID."""
    result = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse.model_validate(scan)


@router.post("", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create and start a new scan."""
    # Verify app exists
    result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == scan_data.app_id)
    )
    app = result.scalar_one_or_none()

    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Create scan
    scan = Scan(
        app_id=scan_data.app_id,
        scan_type=scan_data.scan_type,
        analyzers_enabled=scan_data.analyzers_enabled,
        status="pending",
    )

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Start scan in background
    background_tasks.add_task(run_scan, scan.scan_id)

    return ScanResponse.model_validate(scan)


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    """Cancel a running scan."""
    result = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("pending", "running"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan with status: {scan.status}",
        )

    scan.status = "cancelled"
    scan.completed_at = datetime.utcnow()
    await db.commit()

    return {"message": "Scan cancelled successfully"}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    """Delete a scan and all associated findings."""
    result = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status == "running":
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a running scan. Cancel it first.",
        )

    await db.delete(scan)
    await db.commit()

    return {"message": "Scan deleted successfully"}


@router.get("/{scan_id}/progress")
async def get_scan_progress(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get real-time progress of a scan."""
    result = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": str(scan.scan_id),
        "status": scan.status,
        "progress": scan.progress,
        "current_analyzer": scan.current_analyzer,
        "findings_count": scan.findings_count,
        "analyzer_errors": scan.analyzer_errors,
    }


# Analyzer registry metadata — maps analyzer name to display info
ANALYZER_REGISTRY: dict[str, dict] = {
    "manifest_analyzer": {"description": "Android manifest security analysis", "category": "static", "platform": "android"},
    "dex_analyzer": {"description": "DEX bytecode analysis", "category": "static", "platform": "android"},
    "network_security_config_analyzer": {"description": "Network security config analysis", "category": "static", "platform": "android"},
    "native_lib_analyzer": {"description": "Native library analysis", "category": "static", "platform": "android"},
    "resource_analyzer": {"description": "Resource file analysis", "category": "static", "platform": "android"},
    "secret_scanner": {"description": "Hardcoded secret detection with live validation", "category": "static", "platform": "cross-platform"},
    "ssl_pinning_analyzer": {"description": "SSL/TLS pinning detection", "category": "static", "platform": "cross-platform"},
    "code_quality_analyzer": {"description": "Code quality and security patterns", "category": "static", "platform": "cross-platform"},
    "firebase_analyzer": {"description": "Firebase configuration security with live validation", "category": "static", "platform": "cross-platform"},
    "authentication_analyzer": {"description": "Authentication flow analysis", "category": "static", "platform": "cross-platform"},
    "data_leakage_analyzer": {"description": "Data leakage detection", "category": "static", "platform": "cross-platform"},
    "api_endpoint_extractor": {"description": "API endpoint, GraphQL, and gRPC detection", "category": "static", "platform": "cross-platform"},
    "binary_protection_analyzer": {"description": "Binary protection analysis", "category": "static", "platform": "android"},
    "crypto_auditor": {"description": "Cryptographic implementation audit", "category": "static", "platform": "cross-platform"},
    "dependency_analyzer": {"description": "Dependency SCA with transitive resolution", "category": "static", "platform": "cross-platform"},
    "ipc_scanner": {"description": "Inter-process communication analysis", "category": "static", "platform": "android"},
    "privacy_analyzer": {"description": "Privacy and PII detection", "category": "static", "platform": "cross-platform"},
    "secure_storage_analyzer": {"description": "Secure storage analysis", "category": "static", "platform": "android"},
    "webview_auditor": {"description": "WebView security audit", "category": "static", "platform": "android"},
    "obfuscation_analyzer": {"description": "Code obfuscation analysis", "category": "static", "platform": "android"},
    "deeplink_analyzer": {"description": "Deep link security analysis", "category": "static", "platform": "android"},
    "backup_analyzer": {"description": "Backup configuration analysis", "category": "static", "platform": "android"},
    "component_security_analyzer": {"description": "Exported component analysis", "category": "static", "platform": "android"},
    "logging_analyzer": {"description": "Sensitive logging detection", "category": "static", "platform": "android"},
    "permissions_analyzer": {"description": "Permission usage analysis", "category": "static", "platform": "android"},
    "semgrep_analyzer": {"description": "Semgrep SAST with OWASP MASTG rules", "category": "static", "platform": "cross-platform"},
    "plist_analyzer": {"description": "Info.plist security analysis", "category": "static", "platform": "ios"},
    "ios_binary_analyzer": {"description": "iOS binary protection analysis", "category": "static", "platform": "ios"},
    "entitlements_analyzer": {"description": "iOS entitlements analysis", "category": "static", "platform": "ios"},
    "flutter_analyzer": {"description": "Flutter/Dart security analysis with pub.dev scanning", "category": "framework", "platform": "cross-platform"},
    "react_native_analyzer": {"description": "React Native security analysis", "category": "framework", "platform": "cross-platform"},
    "ml_model_analyzer": {"description": "ML model security analysis", "category": "framework", "platform": "cross-platform"},
    "runtime_analyzer": {"description": "Frida runtime instrumentation (Android + iOS)", "category": "dynamic", "platform": "cross-platform"},
    "network_analyzer": {"description": "Network traffic analysis (Android + iOS)", "category": "dynamic", "platform": "cross-platform"},
}


@router.get("/registry/analyzers")
async def list_analyzers():
    """Return the analyzer registry with name, description, category, and platform."""
    return [
        {"name": name, **info}
        for name, info in ANALYZER_REGISTRY.items()
    ]


# MASTG test coverage mapping — maps analyzer to MASTG test IDs it covers
MASTG_COVERAGE: dict[str, list[str]] = {
    "secret_scanner": ["MASTG-TEST-0001", "MASTG-TEST-0012"],
    "ssl_pinning_analyzer": ["MASTG-TEST-0021", "MASTG-TEST-0022"],
    "crypto_auditor": ["MASTG-TEST-0013", "MASTG-TEST-0014", "MASTG-TEST-0015"],
    "authentication_analyzer": ["MASTG-TEST-0016", "MASTG-TEST-0017"],
    "data_leakage_analyzer": ["MASTG-TEST-0002", "MASTG-TEST-0003", "MASTG-TEST-0004", "MASTG-TEST-0005"],
    "secure_storage_analyzer": ["MASTG-TEST-0001", "MASTG-TEST-0011"],
    "logging_analyzer": ["MASTG-TEST-0006"],
    "backup_analyzer": ["MASTG-TEST-0007"],
    "webview_auditor": ["MASTG-TEST-0031", "MASTG-TEST-0032"],
    "binary_protection_analyzer": ["MASTG-TEST-0038", "MASTG-TEST-0039"],
    "obfuscation_analyzer": ["MASTG-TEST-0040"],
    "permissions_analyzer": ["MASTG-TEST-0041"],
    "ipc_scanner": ["MASTG-TEST-0033", "MASTG-TEST-0034"],
    "deeplink_analyzer": ["MASTG-TEST-0035"],
    "component_security_analyzer": ["MASTG-TEST-0033"],
    "privacy_analyzer": ["MASTG-TEST-0042"],
    "manifest_analyzer": ["MASTG-TEST-0037"],
    "network_security_config_analyzer": ["MASTG-TEST-0020"],
    "firebase_analyzer": ["MASTG-TEST-0012"],
    "runtime_analyzer": ["MASTG-TEST-0010", "MASTG-TEST-0043"],
    "network_analyzer": ["MASTG-TEST-0019", "MASTG-TEST-0020", "MASTG-TEST-0021"],
    "dependency_analyzer": ["MASTG-TEST-0044"],
    "semgrep_analyzer": ["MASTG-TEST-0001", "MASTG-TEST-0013", "MASTG-TEST-0016"],
}


@router.get("/{scan_id}/mastg-coverage")
async def get_mastg_coverage(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    """Return MASTG test coverage matrix for a completed scan.

    Shows which MASTG tests were covered by the scan's analyzers and whether
    they produced findings (pass/fail) or require manual testing.
    """
    result = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get analyzers that ran
    ran_analyzers = scan.analyzers_enabled or []

    # Get findings for this scan
    findings_result = await db.execute(
        select(Finding.tool, Finding.owasp_mastg_test)
        .where(Finding.scan_id == scan_id)
        .where(Finding.owasp_mastg_test.isnot(None))
    )
    finding_tests: set[str] = set()
    for row in findings_result.all():
        if row[1]:
            finding_tests.add(row[1])

    # Build coverage matrix
    coverage = []
    all_tests: set[str] = set()
    for tests in MASTG_COVERAGE.values():
        all_tests.update(tests)

    for test_id in sorted(all_tests):
        # Find which analyzers cover this test
        covering_analyzers = [
            a for a, tests in MASTG_COVERAGE.items() if test_id in tests
        ]
        ran = any(a in ran_analyzers for a in covering_analyzers)

        if not ran:
            status = "not_covered"
        elif test_id in finding_tests:
            status = "automated_fail"
        else:
            status = "automated_pass"

        coverage.append({
            "test_id": test_id,
            "status": status,
            "analyzers": covering_analyzers,
        })

    return {"scan_id": str(scan_id), "coverage": coverage}


@router.get("/{scan_id}/export/burp")
async def export_burp_xml(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    """Export discovered API endpoints as Burp Suite XML sitemap."""
    result = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get api_endpoint_extractor findings
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .where(Finding.tool == "api_endpoint_extractor")
    )
    findings = findings_result.scalars().all()

    # Build Burp XML
    import re
    from urllib.parse import urlparse
    from xml.sax.saxutils import escape

    items = []
    for f in findings:
        desc = f.description or ""
        # Extract URLs from description
        urls = re.findall(r'https?://[^\s<>"\']+', desc)
        for url in urls:
            parsed = urlparse(url)
            items.append(
                f'  <item>\n'
                f'    <url>{escape(url)}</url>\n'
                f'    <host>{escape(parsed.hostname or "")}</host>\n'
                f'    <path>{escape(parsed.path or "/")}</path>\n'
                f'    <method>GET</method>\n'
                f'    <status>0</status>\n'
                f'    <responselength>0</responselength>\n'
                f'    <comment>{escape(f.title or "")}</comment>\n'
                f'  </item>'
            )

    xml = (
        '<?xml version="1.0"?>\n'
        '<items burpVersion="0.0" exportTime="">\n'
        + "\n".join(items) + "\n"
        "</items>\n"
    )

    return Response(
        content=xml,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-burp.xml"'},
    )


@router.get("/{scan_id}/export/har")
async def export_har(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    """Export discovered API endpoints as HAR format."""
    import json as json_lib
    import re

    result = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .where(Finding.tool == "api_endpoint_extractor")
    )
    findings = findings_result.scalars().all()

    entries = []
    for f in findings:
        desc = f.description or ""
        urls = re.findall(r'https?://[^\s<>"\']+', desc)
        for url in urls:
            entries.append({
                "request": {
                    "method": "GET",
                    "url": url,
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [],
                    "queryString": [],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": 0,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [],
                    "content": {"size": 0, "mimeType": ""},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
                "comment": f.title or "",
            })

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "mobilicustos", "version": "0.1.1"},
            "entries": entries,
        }
    }

    return Response(
        content=json_lib.dumps(har, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.har"'},
    )
