"""
Executive Dashboard Service

Provides aggregated metrics and insights for executive reporting:
- Security posture overview
- Trend analysis
- Risk metrics
- Team performance
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class DashboardService:
    """Service for executive dashboard metrics."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_overview_metrics(
        self,
        days: int = 30,
    ) -> dict:
        """Get high-level overview metrics."""
        cutoff = datetime.utcnow() - timedelta(days=days)

        # Total apps
        apps_result = await self.db.execute("SELECT COUNT(*) FROM mobile_apps")
        total_apps = apps_result.scalar() or 0

        # Total findings
        findings_result = await self.db.execute("SELECT COUNT(*) FROM findings")
        total_findings = findings_result.scalar() or 0

        # Open findings (not fixed/closed/false_positive)
        open_result = await self.db.execute(
            """
            SELECT COUNT(*) FROM findings
            WHERE status NOT IN ('fixed', 'closed', 'false_positive', 'verified', 'ignored', 'wont_fix')
            """
        )
        open_findings = open_result.scalar() or 0

        # Critical/High findings
        critical_high_result = await self.db.execute(
            """
            SELECT COUNT(*) FROM findings
            WHERE severity IN ('critical', 'high')
              AND status NOT IN ('fixed', 'closed', 'false_positive', 'verified')
            """
        )
        critical_high = critical_high_result.scalar() or 0

        # Scans this period
        scans_result = await self.db.execute(
            """
            SELECT COUNT(*) FROM scans
            WHERE created_at >= :cutoff
            """,
            {"cutoff": cutoff}
        )
        scans_this_period = scans_result.scalar() or 0

        # Average findings per app
        avg_result = await self.db.execute(
            """
            SELECT AVG(finding_count) FROM (
                SELECT COUNT(*) as finding_count
                FROM findings
                GROUP BY app_id
            ) sub
            """
        )
        avg_findings_per_app = round(avg_result.scalar() or 0, 1)

        # Fix rate (fixed / total confirmed)
        fix_rate_result = await self.db.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE status IN ('fixed', 'verified', 'closed')) as fixed,
                COUNT(*) FILTER (WHERE status != 'new') as confirmed
            FROM findings
            """
        )
        fix_rate_row = fix_rate_result.fetchone()
        fix_rate = 0
        if fix_rate_row and fix_rate_row[1] > 0:
            fix_rate = round((fix_rate_row[0] / fix_rate_row[1]) * 100, 1)

        return {
            "total_apps": total_apps,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_high_findings": critical_high,
            "scans_this_period": scans_this_period,
            "avg_findings_per_app": avg_findings_per_app,
            "fix_rate_percent": fix_rate,
            "period_days": days,
        }

    async def get_severity_distribution(
        self,
        app_id: Optional[str] = None,
    ) -> dict:
        """Get findings distribution by severity."""
        conditions = []
        params = {}

        if app_id:
            conditions.append("app_id = :app_id")
            params["app_id"] = app_id

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        query = f"""
            SELECT
                severity,
                COUNT(*) as count,
                COUNT(*) FILTER (WHERE status NOT IN ('fixed', 'closed', 'false_positive', 'verified')) as open_count
            FROM findings
            {where_clause}
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END
        """

        result = await self.db.execute(query, params)
        rows = result.fetchall()

        distribution = []
        for row in rows:
            distribution.append({
                "severity": row[0] or "unknown",
                "total": row[1],
                "open": row[2],
            })

        return {"distribution": distribution}

    async def get_category_distribution(
        self,
        app_id: Optional[str] = None,
    ) -> dict:
        """Get findings distribution by MASVS category."""
        conditions = []
        params = {}

        if app_id:
            conditions.append("app_id = :app_id")
            params["app_id"] = app_id

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        query = f"""
            SELECT
                COALESCE(category, 'Uncategorized') as category,
                COUNT(*) as count,
                COUNT(*) FILTER (WHERE severity IN ('critical', 'high')) as critical_high
            FROM findings
            {where_clause}
            GROUP BY category
            ORDER BY count DESC
        """

        result = await self.db.execute(query, params)
        rows = result.fetchall()

        distribution = []
        for row in rows:
            distribution.append({
                "category": row[0],
                "count": row[1],
                "critical_high": row[2],
            })

        return {"distribution": distribution}

    async def get_trend_data(
        self,
        days: int = 30,
        interval: str = "day",  # day, week, month
    ) -> dict:
        """Get findings trend over time."""
        cutoff = datetime.utcnow() - timedelta(days=days)

        # Determine date truncation based on interval
        trunc_map = {
            "day": "day",
            "week": "week",
            "month": "month",
        }
        trunc = trunc_map.get(interval, "day")

        query = f"""
            SELECT
                DATE_TRUNC(:trunc, created_at) as period,
                COUNT(*) as new_findings,
                COUNT(*) FILTER (WHERE severity IN ('critical', 'high')) as critical_high
            FROM findings
            WHERE created_at >= :cutoff
            GROUP BY DATE_TRUNC(:trunc, created_at)
            ORDER BY period
        """

        result = await self.db.execute(query, {
            "trunc": trunc,
            "cutoff": cutoff,
        })

        trend = []
        for row in result.fetchall():
            trend.append({
                "period": row[0].isoformat() if row[0] else None,
                "new_findings": row[1],
                "critical_high": row[2],
            })

        # Also get scan trend
        scan_query = f"""
            SELECT
                DATE_TRUNC(:trunc, created_at) as period,
                COUNT(*) as scans,
                COUNT(*) FILTER (WHERE status = 'completed') as completed
            FROM scans
            WHERE created_at >= :cutoff
            GROUP BY DATE_TRUNC(:trunc, created_at)
            ORDER BY period
        """

        scan_result = await self.db.execute(scan_query, {
            "trunc": trunc,
            "cutoff": cutoff,
        })

        scan_trend = []
        for row in scan_result.fetchall():
            scan_trend.append({
                "period": row[0].isoformat() if row[0] else None,
                "scans": row[1],
                "completed": row[2],
            })

        return {
            "findings_trend": trend,
            "scan_trend": scan_trend,
            "interval": interval,
            "days": days,
        }

    async def get_top_vulnerable_apps(
        self,
        limit: int = 10,
    ) -> dict:
        """Get apps with most open critical/high findings."""
        query = """
            SELECT
                a.app_id,
                a.app_name,
                a.package_name,
                a.platform,
                COUNT(*) as total_findings,
                COUNT(*) FILTER (WHERE f.severity = 'critical') as critical,
                COUNT(*) FILTER (WHERE f.severity = 'high') as high,
                COUNT(*) FILTER (WHERE f.severity = 'medium') as medium
            FROM mobile_apps a
            JOIN findings f ON a.app_id = f.app_id
            WHERE f.status NOT IN ('fixed', 'closed', 'false_positive', 'verified')
            GROUP BY a.app_id, a.app_name, a.package_name, a.platform
            ORDER BY critical DESC, high DESC, total_findings DESC
            LIMIT :limit
        """

        result = await self.db.execute(query, {"limit": limit})

        apps = []
        for row in result.fetchall():
            apps.append({
                "app_id": row[0],
                "app_name": row[1],
                "package_name": row[2],
                "platform": row[3],
                "total_findings": row[4],
                "critical": row[5],
                "high": row[6],
                "medium": row[7],
                "risk_score": row[5] * 10 + row[6] * 5 + row[7] * 2,
            })

        return {"apps": apps}

    async def get_compliance_summary(self) -> dict:
        """Get MASVS compliance summary across all apps."""
        # Get all categories
        categories = [
            "MASVS-STORAGE",
            "MASVS-CRYPTO",
            "MASVS-AUTH",
            "MASVS-NETWORK",
            "MASVS-PLATFORM",
            "MASVS-CODE",
            "MASVS-RESILIENCE",
            "MASVS-PRIVACY",
        ]

        query = """
            SELECT
                category,
                COUNT(DISTINCT app_id) as affected_apps,
                COUNT(*) as total_findings,
                COUNT(*) FILTER (WHERE status NOT IN ('fixed', 'closed', 'false_positive', 'verified')) as open_findings
            FROM findings
            WHERE category IS NOT NULL
            GROUP BY category
        """

        result = await self.db.execute(query)

        category_data = {row[0]: {
            "affected_apps": row[1],
            "total_findings": row[2],
            "open_findings": row[3],
        } for row in result.fetchall()}

        summary = []
        for cat in categories:
            data = category_data.get(cat, {
                "affected_apps": 0,
                "total_findings": 0,
                "open_findings": 0,
            })
            summary.append({
                "category": cat,
                **data,
            })

        return {"categories": summary}

    async def get_mean_time_to_fix(
        self,
        days: int = 90,
    ) -> dict:
        """Calculate mean time to fix by severity."""
        cutoff = datetime.utcnow() - timedelta(days=days)

        query = """
            SELECT
                severity,
                AVG(EXTRACT(EPOCH FROM (updated_at - created_at)) / 86400) as avg_days
            FROM findings
            WHERE status IN ('fixed', 'verified', 'closed')
              AND updated_at >= :cutoff
              AND severity IS NOT NULL
            GROUP BY severity
        """

        result = await self.db.execute(query, {"cutoff": cutoff})

        mttf = {}
        for row in result.fetchall():
            if row[0] and row[1]:
                mttf[row[0]] = round(row[1], 1)

        return {
            "mean_time_to_fix_days": mttf,
            "period_days": days,
        }

    async def get_recent_activity(
        self,
        limit: int = 20,
    ) -> dict:
        """Get recent activity (scans, findings, status changes)."""
        # Recent scans
        scans_query = """
            SELECT s.scan_id, s.status, s.created_at, a.app_name
            FROM scans s
            JOIN mobile_apps a ON s.app_id = a.app_id
            ORDER BY s.created_at DESC
            LIMIT :limit
        """

        scans_result = await self.db.execute(scans_query, {"limit": limit})
        recent_scans = [
            {
                "type": "scan",
                "scan_id": row[0],
                "status": row[1],
                "timestamp": row[2].isoformat() if row[2] else None,
                "app_name": row[3],
            }
            for row in scans_result.fetchall()
        ]

        # Recent high-severity findings
        findings_query = """
            SELECT f.finding_id, f.title, f.severity, f.created_at, a.app_name
            FROM findings f
            JOIN mobile_apps a ON f.app_id = a.app_id
            WHERE f.severity IN ('critical', 'high')
            ORDER BY f.created_at DESC
            LIMIT :limit
        """

        findings_result = await self.db.execute(findings_query, {"limit": limit})
        recent_findings = [
            {
                "type": "finding",
                "finding_id": row[0],
                "title": row[1],
                "severity": row[2],
                "timestamp": row[3].isoformat() if row[3] else None,
                "app_name": row[4],
            }
            for row in findings_result.fetchall()
        ]

        # Merge and sort by timestamp
        activity = recent_scans + recent_findings
        activity.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

        return {"activity": activity[:limit]}

    async def get_security_score(
        self,
        app_id: Optional[str] = None,
    ) -> dict:
        """Calculate overall security score (0-100)."""
        conditions = []
        params = {}

        if app_id:
            conditions.append("app_id = :app_id")
            params["app_id"] = app_id

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        # Weight factors for severity
        weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1,
        }

        query = f"""
            SELECT
                COALESCE(SUM(
                    CASE severity
                        WHEN 'critical' THEN 25
                        WHEN 'high' THEN 15
                        WHEN 'medium' THEN 8
                        WHEN 'low' THEN 3
                        WHEN 'info' THEN 1
                        ELSE 0
                    END
                ), 0) as weighted_score,
                COUNT(*) as total_findings
            FROM findings
            {where_clause}
            {"AND" if conditions else "WHERE"} status NOT IN ('fixed', 'closed', 'false_positive', 'verified')
        """

        result = await self.db.execute(query, params)
        row = result.fetchone()

        weighted_score = row[0] or 0
        total_findings = row[1] or 0

        # Calculate score (higher is better, so we invert)
        # Max penalty is 100 points per critical finding
        max_penalty = 500  # Represents a "very insecure" app
        penalty = min(weighted_score, max_penalty)
        score = max(0, 100 - (penalty / max_penalty * 100))

        # Determine grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": round(score, 1),
            "grade": grade,
            "open_findings": total_findings,
            "weighted_penalty": weighted_score,
        }
