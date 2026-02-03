"""Scans router."""

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import MobileApp, Scan
from api.models.schemas import PaginatedResponse, ScanCreate, ScanResponse
from api.services.scan_orchestrator import run_scan

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
