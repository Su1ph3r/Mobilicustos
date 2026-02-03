"""Findings router."""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Finding
from api.models.schemas import (
    FindingCreate,
    FindingFilters,
    FindingResponse,
    PaginatedResponse,
)

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("", response_model=PaginatedResponse)
async def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: list[str] | None = Query(None),
    status: list[str] | None = Query(None),
    platform: list[str] | None = Query(None),
    category: list[str] | None = Query(None),
    tool: list[str] | None = Query(None),
    owasp_masvs_category: list[str] | None = Query(None),
    cwe_id: list[str] | None = Query(None),
    app_id: str | None = None,
    scan_id: UUID | None = None,
    search: str | None = None,
    sort_by: str = Query("severity", pattern="^(severity|title|created_at|status|tool)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
):
    """List all findings with pagination, filters, and sorting."""
    query = select(Finding)

    # Apply filters
    if severity:
        query = query.where(Finding.severity.in_(severity))
    if status:
        query = query.where(Finding.status.in_(status))
    if platform:
        query = query.where(Finding.platform.in_(platform))
    if category:
        query = query.where(Finding.category.in_(category))
    if tool:
        query = query.where(Finding.tool.in_(tool))
    if owasp_masvs_category:
        query = query.where(Finding.owasp_masvs_category.in_(owasp_masvs_category))
    if cwe_id:
        query = query.where(Finding.cwe_id.in_(cwe_id))
    if app_id:
        query = query.where(Finding.app_id == app_id)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if search:
        query = query.where(
            or_(
                Finding.title.ilike(f"%{search}%"),
                Finding.description.ilike(f"%{search}%"),
            )
        )

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply sorting
    if sort_by == "severity":
        # Use array_position for severity ordering with COALESCE for NULL handling
        severity_order = func.array_position(
            ["critical", "high", "medium", "low", "info"],
            func.coalesce(Finding.severity, "info"),
        )
        if sort_order == "asc":
            query = query.order_by(severity_order.desc())  # Reverse for asc (info first)
        else:
            query = query.order_by(severity_order)  # Default desc (critical first)
    elif sort_by == "title":
        order_col = Finding.title.asc() if sort_order == "asc" else Finding.title.desc()
        query = query.order_by(order_col)
    elif sort_by == "created_at":
        order_col = Finding.created_at.asc() if sort_order == "asc" else Finding.created_at.desc()
        query = query.order_by(order_col)
    elif sort_by == "status":
        order_col = Finding.status.asc() if sort_order == "asc" else Finding.status.desc()
        query = query.order_by(order_col)
    elif sort_by == "tool":
        order_col = Finding.tool.asc() if sort_order == "asc" else Finding.tool.desc()
        query = query.order_by(order_col)

    # Secondary sort by created_at if not already sorting by it
    if sort_by != "created_at":
        query = query.order_by(Finding.created_at.desc())

    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    findings = result.scalars().all()

    return PaginatedResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/summary")
async def get_findings_summary(
    app_id: str | None = None,
    scan_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Get findings summary statistics."""
    # Build base filter conditions
    conditions = []
    if app_id:
        conditions.append(Finding.app_id == app_id)
    if scan_id:
        conditions.append(Finding.scan_id == scan_id)

    # By severity
    severity_query = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    if conditions:
        for cond in conditions:
            severity_query = severity_query.where(cond)
    severity_result = await db.execute(severity_query)
    by_severity = dict(severity_result.all())

    # By status
    status_query = select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
    if conditions:
        for cond in conditions:
            status_query = status_query.where(cond)
    status_result = await db.execute(status_query)
    by_status = dict(status_result.all())

    # By category
    category_query = (
        select(Finding.category, func.count(Finding.id))
        .where(Finding.category.isnot(None))
        .group_by(Finding.category)
    )
    if conditions:
        for cond in conditions:
            category_query = category_query.where(cond)
    category_result = await db.execute(category_query)
    by_category = dict(category_result.all())

    # By OWASP MASVS
    masvs_query = (
        select(Finding.owasp_masvs_category, func.count(Finding.id))
        .where(Finding.owasp_masvs_category.isnot(None))
        .group_by(Finding.owasp_masvs_category)
    )
    if conditions:
        for cond in conditions:
            masvs_query = masvs_query.where(cond)
    masvs_result = await db.execute(masvs_query)
    by_masvs = dict(masvs_result.all())

    # By tool
    tool_query = select(Finding.tool, func.count(Finding.id)).group_by(Finding.tool)
    if conditions:
        for cond in conditions:
            tool_query = tool_query.where(cond)
    tool_result = await db.execute(tool_query)
    by_tool = dict(tool_result.all())

    # Total count
    total = sum(by_severity.values()) if by_severity else 0

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_category": by_category,
        "by_masvs": by_masvs,
        "by_tool": by_tool,
    }


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Get a finding by ID."""
    result = await db.execute(
        select(Finding).where(Finding.finding_id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingResponse.model_validate(finding)


@router.patch("/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    new_status: str = Query(..., pattern="^(open|confirmed|false_positive|accepted_risk|remediated)$"),
    db: AsyncSession = Depends(get_db),
):
    """Update the status of a finding."""
    result = await db.execute(
        select(Finding).where(Finding.finding_id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = new_status
    await db.commit()

    return {"message": "Status updated successfully", "new_status": new_status}


@router.post("/bulk-status")
async def bulk_update_status(
    finding_ids: list[str],
    new_status: str = Query(..., pattern="^(open|confirmed|false_positive|accepted_risk|remediated)$"),
    db: AsyncSession = Depends(get_db),
):
    """Bulk update the status of multiple findings."""
    # Limit bulk updates to prevent DoS
    if len(finding_ids) > 1000:
        raise HTTPException(
            status_code=422,
            detail="Cannot update more than 1000 findings at once"
        )

    result = await db.execute(
        select(Finding).where(Finding.finding_id.in_(finding_ids))
    )
    findings = result.scalars().all()

    if not findings:
        raise HTTPException(status_code=404, detail="No findings found")

    for finding in findings:
        finding.status = new_status

    await db.commit()

    return {
        "message": f"Updated {len(findings)} findings",
        "new_status": new_status,
    }


@router.delete("/{finding_id}")
async def delete_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a finding by ID."""
    result = await db.execute(
        select(Finding).where(Finding.finding_id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    await db.delete(finding)
    await db.commit()

    return {"message": "Finding deleted successfully"}


@router.post("/bulk-delete")
async def bulk_delete_findings(
    finding_ids: list[str],
    db: AsyncSession = Depends(get_db),
):
    """Bulk delete multiple findings."""
    # Limit bulk deletes to prevent DoS
    if len(finding_ids) > 1000:
        raise HTTPException(
            status_code=422,
            detail="Cannot delete more than 1000 findings at once"
        )

    result = await db.execute(
        select(Finding).where(Finding.finding_id.in_(finding_ids))
    )
    findings = result.scalars().all()

    if not findings:
        raise HTTPException(status_code=404, detail="No findings found")

    deleted_count = len(findings)
    for finding in findings:
        await db.delete(finding)

    await db.commit()

    return {"message": f"Deleted {deleted_count} findings"}


@router.get("/filters/options")
async def get_filter_options(db: AsyncSession = Depends(get_db)):
    """Get available filter options for findings."""
    # Get unique categories
    categories = await db.execute(
        select(Finding.category).where(Finding.category.isnot(None)).distinct()
    )
    category_list = [c[0] for c in categories.all()]

    # Get unique tools
    tools = await db.execute(select(Finding.tool).distinct())
    tool_list = [t[0] for t in tools.all()]

    # Get unique MASVS categories
    masvs = await db.execute(
        select(Finding.owasp_masvs_category)
        .where(Finding.owasp_masvs_category.isnot(None))
        .distinct()
    )
    masvs_list = [m[0] for m in masvs.all()]

    # Get unique CWE IDs
    cwes = await db.execute(
        select(Finding.cwe_id).where(Finding.cwe_id.isnot(None)).distinct()
    )
    cwe_list = [c[0] for c in cwes.all()]

    return {
        "severities": ["critical", "high", "medium", "low", "info"],
        "statuses": ["open", "confirmed", "false_positive", "accepted_risk", "remediated"],
        "platforms": ["android", "ios", "cross-platform"],
        "categories": category_list,
        "tools": tool_list,
        "masvs_categories": masvs_list,
        "cwe_ids": cwe_list,
    }
