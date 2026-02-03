"""
Reports Router

API endpoints for generating security reports.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["Reports"])


# Request Models

class ComplianceReportRequest(BaseModel):
    """Request for compliance report."""
    framework: str = Field(default="masvs", pattern="^(masvs|owasp)$")
    include_findings: bool = Field(default=True)
    include_recommendations: bool = Field(default=True)


class DiffReportRequest(BaseModel):
    """Request for diff report."""
    baseline_scan_id: str
    comparison_scan_id: str


class VersionCompareRequest(BaseModel):
    """Request for version comparison."""
    version1: str
    version2: str


# Endpoints

@router.post("/compliance/{app_id}")
async def generate_compliance_report(
    app_id: str,
    request: ComplianceReportRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a compliance report for an application.

    Supports MASVS and OWASP Mobile Top 10 frameworks.
    """
    service = ReportService(db)

    try:
        report = await service.generate_compliance_report(
            app_id=app_id,
            framework=request.framework,
            include_findings=request.include_findings,
            include_recommendations=request.include_recommendations,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return report


@router.post("/compliance/{app_id}/export")
async def export_compliance_report(
    app_id: str,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
    framework: str = Query("masvs", pattern="^(masvs|owasp)$"),
    db: AsyncSession = Depends(get_db),
):
    """
    Export a compliance report in various formats.

    Supported formats: json, html, pdf
    """
    service = ReportService(db)

    try:
        report = await service.generate_compliance_report(
            app_id=app_id,
            framework=framework,
            include_findings=True,
            include_recommendations=True,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    if format == "html":
        html = await service.export_report_html(report)
        return Response(
            content=html,
            media_type="text/html",
            headers={
                "Content-Disposition": f"attachment; filename=compliance-report-{app_id}.html"
            }
        )
    elif format == "pdf":
        pdf = await service.export_report_pdf(report)
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=compliance-report-{app_id}.pdf"
            }
        )
    else:
        return report


@router.post("/diff/{app_id}")
async def generate_diff_report(
    app_id: str,
    request: DiffReportRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a diff report comparing two scans.

    Shows new findings, fixed findings, and changes between scans.
    """
    service = ReportService(db)

    try:
        report = await service.generate_diff_report(
            app_id=app_id,
            baseline_scan_id=request.baseline_scan_id,
            comparison_scan_id=request.comparison_scan_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return report


@router.post("/version-compare/{app_id}")
async def generate_version_comparison(
    app_id: str,
    request: VersionCompareRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Compare security findings between two app versions.

    Useful for tracking security improvements across releases.
    """
    service = ReportService(db)

    try:
        report = await service.generate_version_comparison(
            app_id=app_id,
            version1=request.version1,
            version2=request.version2,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return report


@router.get("/templates")
async def get_report_templates():
    """Get available report templates."""
    return {
        "templates": [
            {
                "id": "compliance-masvs",
                "name": "MASVS Compliance Report",
                "description": "OWASP Mobile Application Security Verification Standard compliance report",
                "framework": "masvs",
            },
            {
                "id": "compliance-owasp",
                "name": "OWASP Mobile Top 10 Report",
                "description": "OWASP Mobile Top 10 risks assessment report",
                "framework": "owasp",
            },
            {
                "id": "executive-summary",
                "name": "Executive Summary",
                "description": "High-level security posture summary for executives",
            },
            {
                "id": "technical-detailed",
                "name": "Technical Detailed Report",
                "description": "Detailed technical findings with remediation guidance",
            },
            {
                "id": "diff-report",
                "name": "Scan Comparison Report",
                "description": "Compare findings between two scans",
            },
        ]
    }


@router.get("/history/{app_id}")
async def get_report_history(
    app_id: str,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Get previously generated reports for an app."""
    # This would query a reports table - for now return empty
    return {
        "app_id": app_id,
        "reports": [],
    }
