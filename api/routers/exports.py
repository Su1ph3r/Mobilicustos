"""Exports router for generating reports."""

import io
import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Finding, MobileApp, Scan

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/findings/{app_id}")
async def export_findings(
    app_id: str,
    format: str = Query("json", pattern="^(json|csv|sarif)$"),
    severity: list[str] | None = Query(None),
    status: list[str] | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Export findings for an app in various formats.

    Use app_id='all' to export findings across all apps.
    """
    app = None

    # Handle 'all' app_id for exporting all findings
    if app_id.lower() != "all":
        # Verify app exists
        result = await db.execute(
            select(MobileApp).where(MobileApp.app_id == app_id)
        )
        app = result.scalar_one_or_none()
        if not app:
            raise HTTPException(status_code=404, detail="App not found")

    # Get findings
    if app_id.lower() == "all":
        query = select(Finding)
    else:
        query = select(Finding).where(Finding.app_id == app_id)

    if severity:
        query = query.where(Finding.severity.in_(severity))
    if status:
        query = query.where(Finding.status.in_(status))

    findings_result = await db.execute(query)
    findings = findings_result.scalars().all()

    if format == "json":
        return _export_json(app, findings)
    elif format == "csv":
        return _export_csv(app, findings)
    elif format == "sarif":
        return _export_sarif(app, findings)


def _export_json(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings as JSON."""
    data = {
        "app": {
            "app_id": app.app_id if app else "all",
            "package_name": app.package_name if app else "all_apps",
            "app_name": app.app_name if app else "All Applications",
            "platform": app.platform if app else "mixed",
            "version": app.version_name if app else None,
        } if app else None,
        "exported_at": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": [
            {
                "finding_id": f.finding_id,
                "app_id": f.app_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "category": f.category,
                "description": f.description,
                "impact": f.impact,
                "remediation": f.remediation,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "cwe_id": f.cwe_id,
                "cvss_score": float(f.cvss_score) if f.cvss_score else None,
                "owasp_masvs_category": f.owasp_masvs_category,
                "owasp_masvs_control": f.owasp_masvs_control,
                "poc_evidence": f.poc_evidence,
                "poc_verification": f.poc_verification,
            }
            for f in findings
        ],
    }

    filename = f"{app.package_name}_findings.json" if app else "all_findings.json"
    content = json.dumps(data, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


def _export_csv(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings as CSV."""
    import csv

    output = io.StringIO()
    writer = csv.writer(output)

    # Header - include App ID when exporting all apps
    header = [
        "Finding ID",
        "Title",
        "Severity",
        "Status",
        "Category",
        "File Path",
        "Line",
        "CWE",
        "CVSS",
        "MASVS Category",
        "MASVS Control",
        "Description",
        "Impact",
        "Remediation",
    ]
    if not app:
        header.insert(1, "App ID")
    writer.writerow(header)

    # Data
    for f in findings:
        row = [
            f.finding_id,
            f.title,
            f.severity,
            f.status,
            f.category,
            f.file_path,
            f.line_number,
            f.cwe_id,
            float(f.cvss_score) if f.cvss_score else "",
            f.owasp_masvs_category,
            f.owasp_masvs_control,
            f.description[:200] if f.description else "",  # Truncate for CSV
            f.impact[:200] if f.impact else "",
            f.remediation[:200] if f.remediation else "",
        ]
        if not app:
            row.insert(1, f.app_id)
        writer.writerow(row)

    filename = f"{app.package_name}_findings.csv" if app else "all_findings.csv"
    content = output.getvalue()
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


def _export_sarif(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings in SARIF format (Static Analysis Results Interchange Format)."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Mobilicustos",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/mobilicustos",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    # Build rules and results
    rules_map = {}
    for f in findings:
        rule_id = f.category or f.tool
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.category or f.tool},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(f.severity)
                },
            }

        result = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(f.severity),
            "message": {"text": f.title},
            "locations": [],
        }

        if f.file_path:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                }
            }
            if f.line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": f.line_number
                }
            result["locations"].append(location)

        sarif["runs"][0]["results"].append(result)

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())

    filename = f"{app.package_name}_findings.sarif" if app else "all_findings.sarif"
    content = json.dumps(sarif, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


def _severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity, "note")


@router.get("/report/{app_id}")
async def export_full_report(
    app_id: str,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export a full security assessment report."""
    # Verify app
    result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Get scans
    scans_result = await db.execute(
        select(Scan)
        .where(Scan.app_id == app_id)
        .order_by(Scan.created_at.desc())
    )
    scans = scans_result.scalars().all()

    # Get findings
    findings_result = await db.execute(
        select(Finding).where(Finding.app_id == app_id)
    )
    findings = findings_result.scalars().all()

    # Build report
    report = {
        "title": f"Security Assessment Report - {app.app_name or app.package_name}",
        "generated_at": datetime.utcnow().isoformat(),
        "app": {
            "app_id": app.app_id,
            "package_name": app.package_name,
            "app_name": app.app_name,
            "platform": app.platform,
            "version": app.version_name,
            "framework": app.framework,
            "file_hash": app.file_hash_sha256,
        },
        "executive_summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "info": sum(1 for f in findings if f.severity == "info"),
        },
        "scans": [
            {
                "scan_id": str(s.scan_id),
                "scan_type": s.scan_type,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in scans
        ],
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "category": f.category,
                "description": f.description,
                "impact": f.impact,
                "remediation": f.remediation,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet,
                "poc_evidence": f.poc_evidence,
                "poc_verification": f.poc_verification,
                "cwe_id": f.cwe_id,
                "cvss_score": float(f.cvss_score) if f.cvss_score else None,
                "owasp_masvs_category": f.owasp_masvs_category,
            }
            for f in findings
        ],
    }

    if format == "json":
        content = json.dumps(report, indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename={app.package_name}_report.json"
            },
        )
    elif format == "html":
        # Would generate HTML report
        raise HTTPException(status_code=501, detail="HTML export not yet implemented")
    elif format == "pdf":
        # Would generate PDF report
        raise HTTPException(status_code=501, detail="PDF export not yet implemented")
