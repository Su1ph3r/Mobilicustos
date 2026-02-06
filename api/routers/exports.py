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
    format: str = Query("json", pattern="^(json|csv|sarif|html|pdf)$"),
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
    elif format == "html":
        return _export_findings_html(app, findings)
    elif format == "pdf":
        return _export_findings_pdf(app, findings)


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


def _export_findings_html(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings as a styled HTML document."""
    from html import escape

    app_name = escape(app.app_name or app.package_name) if app else "All Applications"
    title = f"Security Findings - {app_name}"

    # Severity summary counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    # Build findings table rows
    findings_rows = ""
    for f in findings:
        sev = escape(f.severity or "")
        sev_color = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280",
        }.get(sev, "#6b7280")

        findings_rows += f"""<tr>
            <td><span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">{escape(sev.upper())}</span></td>
            <td>{escape(f.title or '')}</td>
            <td>{escape(f.category or '')}</td>
            <td>{escape(f.cwe_id or '')}</td>
            <td>{escape(f.status or '')}</td>
        </tr>"""

    # Build detailed findings
    detailed_findings = ""
    for i, f in enumerate(findings, 1):
        sev = f.severity or "info"
        sev_color = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280",
        }.get(sev, "#6b7280")

        file_info = ""
        if f.file_path:
            file_info = f"<p><strong>File:</strong> {escape(f.file_path)}"
            if f.line_number:
                file_info += f" (line {f.line_number})"
            file_info += "</p>"

        poc = ""
        if f.poc_evidence:
            poc = f"<p><strong>Evidence:</strong></p><pre>{escape(f.poc_evidence)}</pre>"

        code = ""
        if f.code_snippet:
            code = f"<p><strong>Code:</strong></p><pre>{escape(f.code_snippet)}</pre>"

        detailed_findings += f"""
        <div style="border:1px solid #e5e7eb;border-left:4px solid {sev_color};border-radius:4px;padding:16px;margin-bottom:16px;">
            <h3 style="margin:0 0 8px;">{i}. {escape(f.title or '')}</h3>
            <p><span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">{escape(sev.upper())}</span>
               <span style="margin-left:8px;color:#6b7280;">{escape(f.category or '')}</span>
               {' | CWE: ' + escape(f.cwe_id) if f.cwe_id else ''}
               {' | CVSS: ' + str(float(f.cvss_score)) if f.cvss_score else ''}
            </p>
            <p><strong>Description:</strong> {escape(f.description or '')}</p>
            <p><strong>Impact:</strong> {escape(f.impact or '')}</p>
            <p><strong>Remediation:</strong> {escape(f.remediation or '')}</p>
            {file_info}{poc}{code}
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{escape(title)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; color: #1f2937; line-height: 1.6; }}
h1 {{ color: #111827; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }}
h2 {{ color: #374151; margin-top: 32px; }}
table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
th {{ background: #f9fafb; font-weight: 600; }}
pre {{ background: #f3f4f6; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
.summary-grid {{ display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }}
.summary-card {{ flex: 1; min-width: 100px; padding: 16px; border-radius: 8px; text-align: center; }}
.summary-card .count {{ font-size: 28px; font-weight: 700; }}
.summary-card .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
</style>
</head>
<body>
<h1>{escape(title)}</h1>
<p style="color:#6b7280;">Exported: {datetime.utcnow().isoformat()}</p>

<h2>Summary</h2>
<div class="summary-grid">
<div class="summary-card" style="background:#fef2f2;"><div class="count" style="color:#dc2626;">{counts['critical']}</div><div class="label" style="color:#dc2626;">Critical</div></div>
<div class="summary-card" style="background:#fff7ed;"><div class="count" style="color:#ea580c;">{counts['high']}</div><div class="label" style="color:#ea580c;">High</div></div>
<div class="summary-card" style="background:#fefce8;"><div class="count" style="color:#ca8a04;">{counts['medium']}</div><div class="label" style="color:#ca8a04;">Medium</div></div>
<div class="summary-card" style="background:#eff6ff;"><div class="count" style="color:#2563eb;">{counts['low']}</div><div class="label" style="color:#2563eb;">Low</div></div>
<div class="summary-card" style="background:#f9fafb;"><div class="count" style="color:#6b7280;">{counts['info']}</div><div class="label" style="color:#6b7280;">Info</div></div>
</div>
<p><strong>Total findings:</strong> {len(findings)}</p>

<h2>Findings Overview</h2>
<table>
<thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>CWE</th><th>Status</th></tr></thead>
<tbody>{findings_rows}</tbody>
</table>

<h2>Detailed Findings</h2>
{detailed_findings}

<hr style="margin-top:40px;">
<p style="color:#9ca3af;font-size:12px;text-align:center;">Generated by Mobilicustos Security Assessment Platform</p>
</body>
</html>"""

    filename = f"{app.package_name}_findings.html" if app else "all_findings.html"
    return StreamingResponse(
        io.BytesIO(html_content.encode()),
        media_type="text/html",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        },
    )


def _export_findings_pdf(app: MobileApp | None, findings: list[Finding]) -> StreamingResponse:
    """Export findings as a PDF document."""
    from fpdf import FPDF

    app_name = (app.app_name or app.package_name) if app else "All Applications"

    class FindingsPDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(100, 100, 100)
            self.cell(0, 8, "Mobilicustos Security Findings", align="R")
            self.ln(12)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    pdf = FindingsPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(17, 24, 39)
    pdf.cell(0, 14, f"Security Findings - {app_name}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(0, 8, f"Exported: {datetime.utcnow().isoformat()}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Summary
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1

    sev_colors = {
        "critical": (220, 38, 38), "high": (234, 88, 12),
        "medium": (202, 138, 4), "low": (37, 99, 235), "info": (107, 114, 128),
    }

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(31, 41, 55)
    pdf.cell(0, 8, f"Total Findings: {len(findings)}", new_x="LMARGIN", new_y="NEXT")
    for sev_name in ["critical", "high", "medium", "low", "info"]:
        r, g, b = sev_colors[sev_name]
        pdf.set_text_color(r, g, b)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(30, 7, f"  {sev_name.upper()}:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, str(counts.get(sev_name, 0)), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(31, 41, 55)
    pdf.ln(6)

    # Findings
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    for i, f in enumerate(findings, 1):
        if pdf.get_y() > 250:
            pdf.add_page()

        sev = f.severity or "info"
        r, g, b = sev_colors.get(sev, (107, 114, 128))

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(31, 41, 55)
        title_text = (f.title or "")[:80]
        pdf.cell(0, 8, f"{i}. {title_text}", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(r, g, b)
        pdf.cell(25, 6, sev.upper())
        pdf.set_text_color(107, 114, 128)
        pdf.set_font("Helvetica", "", 9)
        meta = f.category or ""
        if f.cwe_id:
            meta += f" | {f.cwe_id}"
        if f.cvss_score:
            meta += f" | CVSS: {float(f.cvss_score)}"
        pdf.cell(0, 6, meta, new_x="LMARGIN", new_y="NEXT")

        pdf.set_text_color(55, 65, 81)
        pdf.set_font("Helvetica", "", 9)
        desc = (f.description or "")[:500]
        if desc:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(w=0, h=5, text=desc, new_x="LMARGIN", new_y="NEXT")

        impact = (f.impact or "")[:300]
        if impact:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(w=0, h=5, text=f"Impact: {impact}", new_x="LMARGIN", new_y="NEXT")

        rem = (f.remediation or "")[:300]
        if rem:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(w=0, h=5, text=f"Remediation: {rem}", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(4)

    pdf_bytes = pdf.output()
    filename = f"{app.package_name}_findings.pdf" if app else "all_findings.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
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
        html_content = _render_html_report(report)
        return StreamingResponse(
            io.BytesIO(html_content.encode()),
            media_type="text/html",
            headers={
                "Content-Disposition": f"attachment; filename={app.package_name}_report.html"
            },
        )
    elif format == "pdf":
        pdf_bytes = _generate_pdf(report)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={app.package_name}_report.pdf"
            },
        )


def _render_html_report(report: dict) -> str:
    """Render a security assessment report as HTML."""
    from html import escape

    summary = report["executive_summary"]
    app_info = report["app"]

    # Build findings rows
    findings_rows = ""
    for f in report["findings"]:
        sev = escape(f.get("severity", ""))
        sev_class = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280",
        }.get(sev, "#6b7280")

        findings_rows += f"""<tr>
            <td><span style="background:{sev_class};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">{escape(sev.upper())}</span></td>
            <td>{escape(f.get('title', ''))}</td>
            <td>{escape(f.get('category', ''))}</td>
            <td>{escape(f.get('cwe_id', '') or '')}</td>
            <td>{escape(f.get('status', ''))}</td>
        </tr>"""

    # Build detailed findings
    detailed_findings = ""
    for i, f in enumerate(report["findings"], 1):
        sev = f.get("severity", "info")
        sev_color = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280",
        }.get(sev, "#6b7280")

        file_info = ""
        if f.get("file_path"):
            file_info = f"<p><strong>File:</strong> {escape(f['file_path'])}"
            if f.get("line_number"):
                file_info += f" (line {f['line_number']})"
            file_info += "</p>"

        poc = ""
        if f.get("poc_evidence"):
            poc = f"<p><strong>Evidence:</strong></p><pre>{escape(f['poc_evidence'])}</pre>"

        code = ""
        if f.get("code_snippet"):
            code = f"<p><strong>Code:</strong></p><pre>{escape(f['code_snippet'])}</pre>"

        detailed_findings += f"""
        <div style="border:1px solid #e5e7eb;border-left:4px solid {sev_color};border-radius:4px;padding:16px;margin-bottom:16px;">
            <h3 style="margin:0 0 8px;">{i}. {escape(f.get('title', ''))}</h3>
            <p><span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">{escape(sev.upper())}</span>
               <span style="margin-left:8px;color:#6b7280;">{escape(f.get('category', ''))}</span>
               {' | CWE: ' + escape(f.get('cwe_id', '')) if f.get('cwe_id') else ''}
               {' | CVSS: ' + str(f.get('cvss_score', '')) if f.get('cvss_score') else ''}
            </p>
            <p><strong>Description:</strong> {escape(f.get('description', '') or '')}</p>
            <p><strong>Impact:</strong> {escape(f.get('impact', '') or '')}</p>
            <p><strong>Remediation:</strong> {escape(f.get('remediation', '') or '')}</p>
            {file_info}{poc}{code}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{escape(report['title'])}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; color: #1f2937; line-height: 1.6; }}
h1 {{ color: #111827; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }}
h2 {{ color: #374151; margin-top: 32px; }}
table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
th {{ background: #f9fafb; font-weight: 600; }}
pre {{ background: #f3f4f6; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
.summary-grid {{ display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }}
.summary-card {{ flex: 1; min-width: 100px; padding: 16px; border-radius: 8px; text-align: center; }}
.summary-card .count {{ font-size: 28px; font-weight: 700; }}
.summary-card .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
</style>
</head>
<body>
<h1>{escape(report['title'])}</h1>
<p style="color:#6b7280;">Generated: {escape(report['generated_at'])}</p>

<h2>Application Information</h2>
<table>
<tr><td><strong>Package</strong></td><td>{escape(app_info.get('package_name', ''))}</td></tr>
<tr><td><strong>Name</strong></td><td>{escape(app_info.get('app_name', '') or '')}</td></tr>
<tr><td><strong>Platform</strong></td><td>{escape(app_info.get('platform', ''))}</td></tr>
<tr><td><strong>Version</strong></td><td>{escape(app_info.get('version', '') or '')}</td></tr>
<tr><td><strong>Framework</strong></td><td>{escape(app_info.get('framework', '') or '')}</td></tr>
<tr><td><strong>SHA-256</strong></td><td style="font-family:monospace;font-size:13px;">{escape(app_info.get('file_hash', '') or '')}</td></tr>
</table>

<h2>Executive Summary</h2>
<div class="summary-grid">
<div class="summary-card" style="background:#fef2f2;"><div class="count" style="color:#dc2626;">{summary['critical']}</div><div class="label" style="color:#dc2626;">Critical</div></div>
<div class="summary-card" style="background:#fff7ed;"><div class="count" style="color:#ea580c;">{summary['high']}</div><div class="label" style="color:#ea580c;">High</div></div>
<div class="summary-card" style="background:#fefce8;"><div class="count" style="color:#ca8a04;">{summary['medium']}</div><div class="label" style="color:#ca8a04;">Medium</div></div>
<div class="summary-card" style="background:#eff6ff;"><div class="count" style="color:#2563eb;">{summary['low']}</div><div class="label" style="color:#2563eb;">Low</div></div>
<div class="summary-card" style="background:#f9fafb;"><div class="count" style="color:#6b7280;">{summary['info']}</div><div class="label" style="color:#6b7280;">Info</div></div>
</div>
<p><strong>Total findings:</strong> {summary['total_findings']}</p>

<h2>Findings Overview</h2>
<table>
<thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>CWE</th><th>Status</th></tr></thead>
<tbody>{findings_rows}</tbody>
</table>

<h2>Detailed Findings</h2>
{detailed_findings}

<hr style="margin-top:40px;">
<p style="color:#9ca3af;font-size:12px;text-align:center;">Generated by Mobilicustos Security Assessment Platform</p>
</body>
</html>"""


def _generate_pdf(report: dict) -> bytes:
    """Generate a PDF security assessment report."""
    from fpdf import FPDF

    class ReportPDF(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(100, 100, 100)
            self.cell(0, 8, "Mobilicustos Security Assessment", align="R")
            self.ln(12)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(17, 24, 39)
    pdf.cell(0, 14, report["title"], new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(0, 8, f"Generated: {report['generated_at']}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # App Information
    app_info = report["app"]
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Application Information", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(31, 41, 55)
    for label, key in [
        ("Package", "package_name"), ("Name", "app_name"), ("Platform", "platform"),
        ("Version", "version"), ("Framework", "framework"), ("SHA-256", "file_hash"),
    ]:
        val = app_info.get(key, "") or ""
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(35, 7, f"{label}:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, str(val), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Executive Summary
    summary = report["executive_summary"]
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    sev_colors = {
        "critical": (220, 38, 38), "high": (234, 88, 12),
        "medium": (202, 138, 4), "low": (37, 99, 235), "info": (107, 114, 128),
    }
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, f"Total Findings: {summary['total_findings']}", new_x="LMARGIN", new_y="NEXT")
    for sev_name in ["critical", "high", "medium", "low", "info"]:
        r, g, b = sev_colors[sev_name]
        pdf.set_text_color(r, g, b)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(30, 7, f"  {sev_name.upper()}:")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, str(summary.get(sev_name, 0)), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(31, 41, 55)
    pdf.ln(6)

    # Findings Table
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 10, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    for i, f in enumerate(report["findings"], 1):
        # Check if we need a new page
        if pdf.get_y() > 250:
            pdf.add_page()

        sev = f.get("severity", "info")
        r, g, b = sev_colors.get(sev, (107, 114, 128))

        # Finding header
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(31, 41, 55)
        pdf.cell(0, 8, f"{i}. {f.get('title', '')[:80]}", new_x="LMARGIN", new_y="NEXT")

        # Severity + category line
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(r, g, b)
        pdf.cell(25, 6, sev.upper())
        pdf.set_text_color(107, 114, 128)
        pdf.set_font("Helvetica", "", 9)
        meta = f.get("category", "")
        if f.get("cwe_id"):
            meta += f" | {f['cwe_id']}"
        if f.get("cvss_score"):
            meta += f" | CVSS: {f['cvss_score']}"
        pdf.cell(0, 6, meta, new_x="LMARGIN", new_y="NEXT")

        # Description
        pdf.set_text_color(55, 65, 81)
        pdf.set_font("Helvetica", "", 9)
        desc = f.get("description", "") or ""
        if desc:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(w=0, h=5, text=desc[:500], new_x="LMARGIN", new_y="NEXT")

        # Impact
        impact = f.get("impact", "") or ""
        if impact:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(w=0, h=5, text=f"Impact: {impact[:300]}", new_x="LMARGIN", new_y="NEXT")

        # Remediation
        rem = f.get("remediation", "") or ""
        if rem:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(w=0, h=5, text=f"Remediation: {rem[:300]}", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(4)

    return pdf.output()
