"""
Report Generation Service

Generates various security reports:
- Compliance reports (MASVS, OWASP)
- Diff/comparison reports
- Executive summaries
- Detailed technical reports
"""

import io
import json
import logging
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class ReportService:
    """Service for generating security reports."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_compliance_report(
        self,
        app_id: str,
        framework: str = "masvs",  # masvs, owasp-mobile-top-10
        include_findings: bool = True,
        include_recommendations: bool = True,
    ) -> dict:
        """
        Generate a compliance report for an app.

        Args:
            app_id: The app to generate report for
            framework: Compliance framework (masvs, owasp)
            include_findings: Include detailed findings
            include_recommendations: Include remediation recommendations
        """
        # Get app info
        app_result = await self.db.execute(
            "SELECT * FROM mobile_apps WHERE app_id = :app_id",
            {"app_id": app_id}
        )
        app = app_result.fetchone()

        if not app:
            raise ValueError("App not found")

        app = dict(app._mapping)

        # Get findings
        findings_result = await self.db.execute(
            """
            SELECT * FROM findings
            WHERE app_id = :app_id
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                created_at DESC
            """,
            {"app_id": app_id}
        )
        findings = [dict(row._mapping) for row in findings_result.fetchall()]

        # Build compliance structure based on framework
        if framework == "masvs":
            compliance = await self._build_masvs_compliance(findings)
        else:
            compliance = await self._build_owasp_compliance(findings)

        report = {
            "report_id": str(uuid4()),
            "generated_at": datetime.utcnow().isoformat(),
            "framework": framework,
            "app": {
                "app_id": app["app_id"],
                "app_name": app["app_name"],
                "package_name": app["package_name"],
                "version": app.get("version"),
                "platform": app["platform"],
            },
            "summary": {
                "total_findings": len(findings),
                "open_findings": sum(1 for f in findings if f["status"] not in ("fixed", "closed", "false_positive")),
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "high": sum(1 for f in findings if f["severity"] == "high"),
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "low": sum(1 for f in findings if f["severity"] == "low"),
                "compliance_score": compliance["overall_score"],
            },
            "compliance": compliance,
        }

        if include_findings:
            report["findings"] = [
                {
                    "finding_id": f["finding_id"],
                    "title": f["title"],
                    "severity": f["severity"],
                    "category": f["category"],
                    "status": f["status"],
                    "description": f["description"],
                    "impact": f.get("impact"),
                    "remediation": f.get("remediation"),
                    "tool": f.get("tool"),
                    "tool_sources": f.get("tool_sources", []),
                    "platform": f.get("platform"),
                    "resource_type": f.get("resource_type"),
                    "file_path": f.get("file_path"),
                    "line_number": f.get("line_number"),
                    "code_snippet": f.get("code_snippet"),
                    "poc_evidence": f.get("poc_evidence"),
                    "poc_verification": f.get("poc_verification"),
                    "poc_commands": f.get("poc_commands", []),
                    "poc_frida_script": f.get("poc_frida_script"),
                    "poc_screenshot_path": f.get("poc_screenshot_path"),
                    "remediation_commands": f.get("remediation_commands", []),
                    "remediation_code": f.get("remediation_code", {}),
                    "remediation_resources": f.get("remediation_resources", []),
                    "risk_score": f.get("risk_score"),
                    "cvss_score": f.get("cvss_score"),
                    "cvss_vector": f.get("cvss_vector"),
                    "cwe_id": f.get("cwe_id"),
                    "cwe_name": f.get("cwe_name"),
                    "owasp_masvs_category": f.get("owasp_masvs_category"),
                    "owasp_masvs_control": f.get("owasp_masvs_control"),
                    "owasp_mastg_test": f.get("owasp_mastg_test"),
                    "canonical_id": f.get("canonical_id"),
                    "first_seen": str(f["first_seen"]) if f.get("first_seen") else None,
                    "last_seen": str(f["last_seen"]) if f.get("last_seen") else None,
                    "created_at": str(f["created_at"]) if f.get("created_at") else None,
                }
                for f in findings
            ]

        if include_recommendations:
            report["recommendations"] = self._generate_recommendations(findings, compliance)

        return report

    async def _build_masvs_compliance(self, findings: list[dict]) -> dict:
        """Build MASVS compliance structure."""
        categories = {
            "MASVS-STORAGE": {
                "name": "Data Storage",
                "description": "Secure storage of sensitive data",
                "controls": [],
                "findings_count": 0,
                "status": "pass",
            },
            "MASVS-CRYPTO": {
                "name": "Cryptography",
                "description": "Proper use of cryptographic functions",
                "controls": [],
                "findings_count": 0,
                "status": "pass",
            },
            "MASVS-AUTH": {
                "name": "Authentication",
                "description": "User authentication and session management",
                "controls": [],
                "findings_count": 0,
                "status": "pass",
            },
            "MASVS-NETWORK": {
                "name": "Network Communication",
                "description": "Secure network communications",
                "controls": [],
                "findings_count": 0,
                "status": "pass",
            },
            "MASVS-PLATFORM": {
                "name": "Platform Interaction",
                "description": "Secure platform interaction",
                "controls": [],
                "findings_count": 0,
                "status": "pass",
            },
            "MASVS-CODE": {
                "name": "Code Quality",
                "description": "Secure coding practices",
                "controls": [],
                "findings_count": 0,
                "status": "pass",
            },
            "MASVS-RESILIENCE": {
                "name": "Resilience",
                "description": "Defense against reverse engineering",
                "controls": [],
                "findings_count": 0,
                "status": "pass",
            },
            "MASVS-PRIVACY": {
                "name": "Privacy",
                "description": "User privacy protection",
                "controls": [],
                "findings_count": 0,
                "status": "pass",
            },
        }

        # Count findings per category
        for finding in findings:
            category = finding.get("category")
            if category in categories:
                categories[category]["findings_count"] += 1
                if finding["status"] not in ("fixed", "closed", "false_positive"):
                    if finding["severity"] in ("critical", "high"):
                        categories[category]["status"] = "fail"
                    elif categories[category]["status"] != "fail":
                        categories[category]["status"] = "partial"

        # Calculate overall score
        total_categories = len(categories)
        passing = sum(1 for c in categories.values() if c["status"] == "pass")
        partial = sum(1 for c in categories.values() if c["status"] == "partial")

        overall_score = round(((passing + partial * 0.5) / total_categories) * 100, 1)

        return {
            "categories": categories,
            "overall_score": overall_score,
            "passing_categories": passing,
            "total_categories": total_categories,
        }

    async def _build_owasp_compliance(self, findings: list[dict]) -> dict:
        """Build OWASP Mobile Top 10 compliance structure."""
        categories = {
            "M1": {"name": "Improper Platform Usage", "findings_count": 0, "status": "pass"},
            "M2": {"name": "Insecure Data Storage", "findings_count": 0, "status": "pass"},
            "M3": {"name": "Insecure Communication", "findings_count": 0, "status": "pass"},
            "M4": {"name": "Insecure Authentication", "findings_count": 0, "status": "pass"},
            "M5": {"name": "Insufficient Cryptography", "findings_count": 0, "status": "pass"},
            "M6": {"name": "Insecure Authorization", "findings_count": 0, "status": "pass"},
            "M7": {"name": "Client Code Quality", "findings_count": 0, "status": "pass"},
            "M8": {"name": "Code Tampering", "findings_count": 0, "status": "pass"},
            "M9": {"name": "Reverse Engineering", "findings_count": 0, "status": "pass"},
            "M10": {"name": "Extraneous Functionality", "findings_count": 0, "status": "pass"},
        }

        # Map findings to OWASP categories
        for finding in findings:
            owasp_cat = finding.get("owasp_category")
            if owasp_cat in categories:
                categories[owasp_cat]["findings_count"] += 1
                if finding["status"] not in ("fixed", "closed", "false_positive"):
                    categories[owasp_cat]["status"] = "fail"

        passing = sum(1 for c in categories.values() if c["status"] == "pass")
        overall_score = round((passing / len(categories)) * 100, 1)

        return {
            "categories": categories,
            "overall_score": overall_score,
            "passing_categories": passing,
            "total_categories": len(categories),
        }

    def _generate_recommendations(
        self,
        findings: list[dict],
        compliance: dict,
    ) -> list[dict]:
        """Generate remediation recommendations."""
        recommendations = []

        # Priority recommendations based on findings
        critical_findings = [f for f in findings if f["severity"] == "critical" and f["status"] not in ("fixed", "closed")]
        if critical_findings:
            recommendations.append({
                "priority": "immediate",
                "title": "Address Critical Vulnerabilities",
                "description": f"There are {len(critical_findings)} critical vulnerabilities that require immediate attention.",
                "findings": [f["finding_id"] for f in critical_findings[:5]],
            })

        # Category-specific recommendations
        categories = compliance.get("categories", {})
        for cat_id, cat_data in categories.items():
            if cat_data.get("status") == "fail":
                recommendations.append({
                    "priority": "high",
                    "title": f"Improve {cat_data.get('name', cat_id)}",
                    "description": f"Category {cat_id} has failing controls. Review and remediate {cat_data.get('findings_count', 0)} findings.",
                    "category": cat_id,
                })

        return recommendations

    async def generate_diff_report(
        self,
        app_id: str,
        baseline_scan_id: str,
        comparison_scan_id: str,
    ) -> dict:
        """
        Generate a diff report comparing two scans.

        Shows new, fixed, and unchanged findings between scans.
        """
        # Get baseline findings
        baseline_result = await self.db.execute(
            """
            SELECT * FROM findings
            WHERE app_id = :app_id AND scan_id = :scan_id
            """,
            {"app_id": app_id, "scan_id": baseline_scan_id}
        )
        baseline_findings = {
            f["canonical_id"] or f["finding_id"]: dict(f._mapping)
            for f in baseline_result.fetchall()
        }

        # Get comparison findings
        comparison_result = await self.db.execute(
            """
            SELECT * FROM findings
            WHERE app_id = :app_id AND scan_id = :scan_id
            """,
            {"app_id": app_id, "scan_id": comparison_scan_id}
        )
        comparison_findings = {
            f["canonical_id"] or f["finding_id"]: dict(f._mapping)
            for f in comparison_result.fetchall()
        }

        # Calculate differences
        baseline_keys = set(baseline_findings.keys())
        comparison_keys = set(comparison_findings.keys())

        new_keys = comparison_keys - baseline_keys
        fixed_keys = baseline_keys - comparison_keys
        unchanged_keys = baseline_keys & comparison_keys

        # Get scan info
        baseline_scan = await self.db.execute(
            "SELECT * FROM scans WHERE scan_id = :scan_id",
            {"scan_id": baseline_scan_id}
        )
        comparison_scan = await self.db.execute(
            "SELECT * FROM scans WHERE scan_id = :scan_id",
            {"scan_id": comparison_scan_id}
        )

        baseline_scan = dict(baseline_scan.fetchone()._mapping) if baseline_scan else {}
        comparison_scan = dict(comparison_scan.fetchone()._mapping) if comparison_scan else {}

        return {
            "report_id": str(uuid4()),
            "generated_at": datetime.utcnow().isoformat(),
            "app_id": app_id,
            "baseline": {
                "scan_id": baseline_scan_id,
                "created_at": baseline_scan.get("created_at", "").isoformat() if baseline_scan.get("created_at") else None,
                "findings_count": len(baseline_findings),
            },
            "comparison": {
                "scan_id": comparison_scan_id,
                "created_at": comparison_scan.get("created_at", "").isoformat() if comparison_scan.get("created_at") else None,
                "findings_count": len(comparison_findings),
            },
            "summary": {
                "new_findings": len(new_keys),
                "fixed_findings": len(fixed_keys),
                "unchanged_findings": len(unchanged_keys),
                "delta": len(comparison_findings) - len(baseline_findings),
            },
            "new_findings": [
                {
                    "finding_id": comparison_findings[k]["finding_id"],
                    "title": comparison_findings[k]["title"],
                    "severity": comparison_findings[k]["severity"],
                    "category": comparison_findings[k].get("category"),
                }
                for k in new_keys
            ],
            "fixed_findings": [
                {
                    "finding_id": baseline_findings[k]["finding_id"],
                    "title": baseline_findings[k]["title"],
                    "severity": baseline_findings[k]["severity"],
                    "category": baseline_findings[k].get("category"),
                }
                for k in fixed_keys
            ],
            "severity_delta": {
                "critical": sum(1 for k in new_keys if comparison_findings[k]["severity"] == "critical") -
                           sum(1 for k in fixed_keys if baseline_findings[k]["severity"] == "critical"),
                "high": sum(1 for k in new_keys if comparison_findings[k]["severity"] == "high") -
                       sum(1 for k in fixed_keys if baseline_findings[k]["severity"] == "high"),
                "medium": sum(1 for k in new_keys if comparison_findings[k]["severity"] == "medium") -
                         sum(1 for k in fixed_keys if baseline_findings[k]["severity"] == "medium"),
                "low": sum(1 for k in new_keys if comparison_findings[k]["severity"] == "low") -
                      sum(1 for k in fixed_keys if baseline_findings[k]["severity"] == "low"),
            },
        }

    async def generate_version_comparison(
        self,
        app_id: str,
        version1: str,
        version2: str,
    ) -> dict:
        """
        Compare findings between two app versions.
        """
        # Get findings for each version
        v1_result = await self.db.execute(
            """
            SELECT f.* FROM findings f
            JOIN scans s ON f.scan_id = s.scan_id
            JOIN mobile_apps a ON f.app_id = a.app_id
            WHERE f.app_id = :app_id AND a.version = :version
            ORDER BY f.created_at DESC
            """,
            {"app_id": app_id, "version": version1}
        )

        v2_result = await self.db.execute(
            """
            SELECT f.* FROM findings f
            JOIN scans s ON f.scan_id = s.scan_id
            JOIN mobile_apps a ON f.app_id = a.app_id
            WHERE f.app_id = :app_id AND a.version = :version
            ORDER BY f.created_at DESC
            """,
            {"app_id": app_id, "version": version2}
        )

        v1_findings = [dict(row._mapping) for row in v1_result.fetchall()]
        v2_findings = [dict(row._mapping) for row in v2_result.fetchall()]

        # Compare using canonical IDs
        v1_ids = {f.get("canonical_id") or f["finding_id"] for f in v1_findings}
        v2_ids = {f.get("canonical_id") or f["finding_id"] for f in v2_findings}

        return {
            "report_id": str(uuid4()),
            "generated_at": datetime.utcnow().isoformat(),
            "app_id": app_id,
            "version1": {
                "version": version1,
                "findings_count": len(v1_findings),
                "critical": sum(1 for f in v1_findings if f["severity"] == "critical"),
                "high": sum(1 for f in v1_findings if f["severity"] == "high"),
            },
            "version2": {
                "version": version2,
                "findings_count": len(v2_findings),
                "critical": sum(1 for f in v2_findings if f["severity"] == "critical"),
                "high": sum(1 for f in v2_findings if f["severity"] == "high"),
            },
            "comparison": {
                "new_in_v2": len(v2_ids - v1_ids),
                "fixed_in_v2": len(v1_ids - v2_ids),
                "persistent": len(v1_ids & v2_ids),
                "security_improved": len(v1_findings) > len(v2_findings),
            },
        }

    async def export_report_pdf(
        self,
        report: dict,
    ) -> bytes:
        """Export report as PDF using fpdf2."""
        from api.routers.exports import (
            SEVERITY_COLORS_RGB,
            SEVERITY_LEVELS,
            _render_finding_to_pdf,
            _severity_sort_key,
        )
        from fpdf import FPDF

        class CompliancePDF(FPDF):
            def header(self):
                self.set_font("Helvetica", "B", 10)
                self.set_text_color(100, 100, 100)
                self.cell(0, 8, "Mobilicustos Compliance Report", align="R")
                self.ln(12)

            def footer(self):
                self.set_y(-15)
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(150, 150, 150)
                self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

        pdf = CompliancePDF()
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(17, 24, 39)
        app_name = report.get("app", {}).get("app_name", "Unknown")
        from api.routers.exports import _pdf_safe_text
        pdf.cell(0, 12, f"Compliance Report - {_pdf_safe_text(app_name)}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(107, 114, 128)
        pdf.cell(0, 8, f"Generated: {report.get('generated_at', '')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)

        # Summary
        summary = report.get("summary", {})
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(55, 65, 81)
        pdf.cell(0, 10, "Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(59, 130, 246)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(31, 41, 55)
        score = report.get("compliance", {}).get("overall_score", 0)
        pdf.cell(0, 7, f"Compliance Score: {score}%", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 7, f"Total Findings: {summary.get('total_findings', 0)}", new_x="LMARGIN", new_y="NEXT")
        for sev_name in SEVERITY_LEVELS:
            r, g, b = SEVERITY_COLORS_RGB[sev_name]
            pdf.set_text_color(r, g, b)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(30, 7, f"  {sev_name.upper()}:")
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 7, str(summary.get(sev_name, 0)), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(31, 41, 55)
        pdf.ln(6)

        # Compliance Categories
        categories = report.get("compliance", {}).get("categories", {})
        if categories:
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(55, 65, 81)
            pdf.cell(0, 10, "Compliance Categories", new_x="LMARGIN", new_y="NEXT")
            pdf.set_draw_color(59, 130, 246)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(4)

            for cat_id, cat_data in categories.items():
                status = cat_data.get("status", "N/A").upper()
                if status == "PASS":
                    pdf.set_text_color(34, 197, 94)
                elif status == "FAIL":
                    pdf.set_text_color(220, 38, 38)
                else:
                    pdf.set_text_color(202, 138, 4)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(50, 7, f"{cat_id}")
                pdf.set_font("Helvetica", "", 10)
                pdf.cell(60, 7, cat_data.get("name", ""))
                pdf.cell(20, 7, status)
                pdf.set_text_color(107, 114, 128)
                pdf.cell(0, 7, f"{cat_data.get('findings_count', 0)} findings", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(6)

        # Findings
        findings = report.get("findings", [])
        if findings:
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(55, 65, 81)
            pdf.cell(0, 10, "Findings", new_x="LMARGIN", new_y="NEXT")
            pdf.set_draw_color(59, 130, 246)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(4)

            sorted_findings = sorted(findings, key=_severity_sort_key)
            for i, f in enumerate(sorted_findings, 1):
                _render_finding_to_pdf(pdf, f, i)

        return pdf.output()

    async def export_report_html(
        self,
        report: dict,
    ) -> str:
        """Export report as HTML with accordion findings."""
        from html import escape

        from api.routers.exports import (
            SEVERITY_BG_COLORS,
            SEVERITY_COLORS,
            SEVERITY_LEVELS,
            _accordion_js_css,
            _build_finding_accordion_html,
            _severity_sort_key,
        )

        app_name = escape(report.get("app", {}).get("app_name", "Unknown"))
        summary = report.get("summary", {})
        compliance = report.get("compliance", {})

        # Summary cards
        summary_cards = ""
        for sev_name in SEVERITY_LEVELS:
            color = SEVERITY_COLORS[sev_name]
            bg = SEVERITY_BG_COLORS[sev_name]
            summary_cards += (
                f'<div class="summary-card" style="background:{bg};">'
                f'<div class="count" style="color:{color};">'
                f'{summary.get(sev_name, 0)}</div>'
                f'<div class="label" style="color:{color};">'
                f'{sev_name.title()}</div></div>'
            )

        # Compliance categories table
        categories_html = ""
        for cat_id, cat_data in compliance.get("categories", {}).items():
            status = cat_data.get("status", "N/A")
            if status == "pass":
                status_color = "#22c55e"
            elif status == "fail":
                status_color = "#dc2626"
            else:
                status_color = "#ca8a04"
            categories_html += (
                f'<tr><td>{escape(cat_id)} - {escape(cat_data.get("name", ""))}</td>'
                f'<td style="color:{status_color};font-weight:600;">'
                f'{escape(status.upper())}</td>'
                f'<td>{cat_data.get("findings_count", 0)}</td></tr>'
            )

        # Findings accordions
        findings_html = ""
        findings = report.get("findings", [])
        if findings:
            sorted_findings = sorted(findings, key=_severity_sort_key)
            idx = 1
            for sev_name in SEVERITY_LEVELS:
                sev_findings = [
                    f for f in sorted_findings if f.get("severity") == sev_name
                ]
                if not sev_findings:
                    continue
                color = SEVERITY_COLORS[sev_name]
                findings_html += (
                    f'<h3 style="color:{color};margin-top:24px;margin-bottom:8px;'
                    f'border-bottom:2px solid {color};padding-bottom:4px;">'
                    f'{escape(sev_name.upper())} ({len(sev_findings)})</h3>'
                )
                for f in sev_findings:
                    findings_html += _build_finding_accordion_html(f, idx)
                    idx += 1

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Compliance Report - {app_name}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; color: #1f2937; line-height: 1.6; }}
h1 {{ color: #111827; border-bottom: 2px solid #3b82f6; padding-bottom: 8px; }}
h2 {{ color: #374151; margin-top: 32px; }}
table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
th {{ background: #f9fafb; font-weight: 600; }}
.summary-grid {{ display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }}
.summary-card {{ flex: 1; min-width: 100px; padding: 16px; border-radius: 8px; text-align: center; }}
.summary-card .count {{ font-size: 28px; font-weight: 700; }}
.summary-card .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
</style>
{_accordion_js_css()}
</head>
<body>
<h1>Security Compliance Report</h1>
<p style="color:#6b7280;">Generated: {escape(report.get('generated_at', 'N/A'))}</p>

<h2>Application</h2>
<table>
<tr><td><strong>Name</strong></td><td>{app_name}</td></tr>
<tr><td><strong>Package</strong></td><td>{escape(report.get('app', {}).get('package_name', 'N/A'))}</td></tr>
<tr><td><strong>Platform</strong></td><td>{escape(report.get('app', {}).get('platform', 'N/A'))}</td></tr>
</table>

<h2>Summary</h2>
<div class="summary-grid">
{summary_cards}
</div>
<p><strong>Compliance Score:</strong> {compliance.get('overall_score', 0)}%</p>
<p><strong>Total Findings:</strong> {summary.get('total_findings', 0)}</p>

<h2>Compliance Categories</h2>
<table>
<thead><tr><th>Category</th><th>Status</th><th>Findings</th></tr></thead>
<tbody>{categories_html}</tbody>
</table>

<h2>Findings</h2>
<div class="no-print" style="margin-bottom:12px;">
<button onclick="expandAll()" style="padding:6px 14px;border:1px solid #d1d5db;border-radius:4px;background:#fff;cursor:pointer;margin-right:4px;">Expand All</button>
<button onclick="collapseAll()" style="padding:6px 14px;border:1px solid #d1d5db;border-radius:4px;background:#fff;cursor:pointer;">Collapse All</button>
</div>
{findings_html}

<hr style="margin-top:40px;">
<p style="color:#9ca3af;font-size:12px;text-align:center;">Generated by Mobilicustos Security Assessment Platform</p>
</body>
</html>"""
        return html
