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
                    "file_path": f.get("file_path"),
                    "line_number": f.get("line_number"),
                    "cwe_id": f.get("cwe_id"),
                    "cvss_score": f.get("cvss_score"),
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
        """Export report as PDF (placeholder - would use reportlab or similar)."""
        # In production, use reportlab, weasyprint, or similar
        # For now, return JSON as bytes
        return json.dumps(report, indent=2, default=str).encode()

    async def export_report_html(
        self,
        report: dict,
    ) -> str:
        """Export report as HTML."""
        # Simple HTML template
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {report.get('app', {}).get('app_name', 'Unknown')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Security Compliance Report</h1>
    <p>Generated: {report.get('generated_at', 'N/A')}</p>

    <h2>Application</h2>
    <p><strong>{report.get('app', {}).get('app_name', 'N/A')}</strong></p>
    <p>Package: {report.get('app', {}).get('package_name', 'N/A')}</p>
    <p>Platform: {report.get('app', {}).get('platform', 'N/A')}</p>

    <h2>Summary</h2>
    <div class="summary">
        <p>Compliance Score: <strong>{report.get('compliance', {}).get('overall_score', 0)}%</strong></p>
        <p>Total Findings: {report.get('summary', {}).get('total_findings', 0)}</p>
        <p>
            <span class="severity-critical">Critical: {report.get('summary', {}).get('critical', 0)}</span> |
            <span class="severity-high">High: {report.get('summary', {}).get('high', 0)}</span> |
            <span class="severity-medium">Medium: {report.get('summary', {}).get('medium', 0)}</span> |
            <span class="severity-low">Low: {report.get('summary', {}).get('low', 0)}</span>
        </p>
    </div>

    <h2>Compliance Categories</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Status</th>
            <th>Findings</th>
        </tr>
"""

        for cat_id, cat_data in report.get("compliance", {}).get("categories", {}).items():
            status_class = "severity-low" if cat_data.get("status") == "pass" else "severity-high"
            html += f"""
        <tr>
            <td>{cat_id} - {cat_data.get('name', '')}</td>
            <td class="{status_class}">{cat_data.get('status', 'N/A').upper()}</td>
            <td>{cat_data.get('findings_count', 0)}</td>
        </tr>
"""

        html += """
    </table>
</body>
</html>
"""
        return html
