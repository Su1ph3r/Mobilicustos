"""
Executive Dashboard Router

API endpoints for executive dashboard metrics and reporting.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["Executive Dashboard"])


@router.get("/overview")
async def get_overview(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get high-level security overview metrics.

    Returns key metrics including total apps, findings, fix rate, and more.
    """
    service = DashboardService(db)
    return await service.get_overview_metrics(days)


@router.get("/severity-distribution")
async def get_severity_distribution(
    app_id: Optional[str] = Query(None, description="Filter by app ID"),
    db: AsyncSession = Depends(get_db),
):
    """Get findings distribution by severity level."""
    service = DashboardService(db)
    return await service.get_severity_distribution(app_id)


@router.get("/category-distribution")
async def get_category_distribution(
    app_id: Optional[str] = Query(None, description="Filter by app ID"),
    db: AsyncSession = Depends(get_db),
):
    """Get findings distribution by MASVS category."""
    service = DashboardService(db)
    return await service.get_category_distribution(app_id)


@router.get("/trends")
async def get_trends(
    days: int = Query(30, ge=7, le=365, description="Number of days to analyze"),
    interval: str = Query("day", pattern="^(day|week|month)$", description="Aggregation interval"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get findings and scan trends over time.

    Returns time-series data for charts and graphs.
    """
    service = DashboardService(db)
    return await service.get_trend_data(days, interval)


@router.get("/top-vulnerable-apps")
async def get_top_vulnerable_apps(
    limit: int = Query(10, ge=1, le=50, description="Number of apps to return"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get apps with the most open critical/high findings.

    Useful for prioritizing remediation efforts.
    """
    service = DashboardService(db)
    return await service.get_top_vulnerable_apps(limit)


@router.get("/compliance-summary")
async def get_compliance_summary(
    db: AsyncSession = Depends(get_db),
):
    """
    Get MASVS compliance summary across all apps.

    Shows findings count per MASVS category.
    """
    service = DashboardService(db)
    return await service.get_compliance_summary()


@router.get("/mean-time-to-fix")
async def get_mean_time_to_fix(
    days: int = Query(90, ge=7, le=365, description="Period to analyze"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get mean time to fix by severity.

    Helps track remediation efficiency over time.
    """
    service = DashboardService(db)
    return await service.get_mean_time_to_fix(days)


@router.get("/recent-activity")
async def get_recent_activity(
    limit: int = Query(20, ge=1, le=100, description="Number of activities to return"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get recent security activity.

    Includes recent scans, new findings, and status changes.
    """
    service = DashboardService(db)
    return await service.get_recent_activity(limit)


@router.get("/security-score")
async def get_security_score(
    app_id: Optional[str] = Query(None, description="Calculate for specific app"),
    db: AsyncSession = Depends(get_db),
):
    """
    Calculate overall security score (0-100).

    Score is based on open findings weighted by severity.
    Higher score = better security posture.
    """
    service = DashboardService(db)
    return await service.get_security_score(app_id)


@router.get("/executive-summary")
async def get_executive_summary(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    """
    Get complete executive summary in a single call.

    Combines overview, score, trends, and top issues for executive reporting.
    """
    service = DashboardService(db)

    overview = await service.get_overview_metrics(days)
    score = await service.get_security_score()
    severity = await service.get_severity_distribution()
    top_apps = await service.get_top_vulnerable_apps(5)
    mttf = await service.get_mean_time_to_fix(days)
    trends = await service.get_trend_data(days, "week")

    return {
        "generated_at": "now",  # Would use datetime.utcnow().isoformat()
        "period_days": days,
        "overview": overview,
        "security_score": score,
        "severity_distribution": severity,
        "top_vulnerable_apps": top_apps,
        "mean_time_to_fix": mttf,
        "trends": trends,
    }
