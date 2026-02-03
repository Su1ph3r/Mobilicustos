"""
Scheduled Scans Router

API endpoints for managing scheduled/recurring scans.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.scheduled_scan_service import ScheduledScanService

router = APIRouter(prefix="/scheduled-scans", tags=["Scheduled Scans"])


# Request/Response Models

class ScheduleCreateRequest(BaseModel):
    """Request to create a scheduled scan."""
    app_id: str = Field(..., description="ID of the app to scan")
    name: str = Field(..., min_length=1, max_length=256, description="Name for this schedule")
    cron_expression: str = Field(..., description="Cron expression (e.g., '0 2 * * *' for daily at 2 AM)")
    analyzers: list[str] = Field(default=[], description="List of analyzers to run (empty = all)")
    is_active: bool = Field(default=True, description="Whether the schedule is active")
    webhook_url: Optional[str] = Field(None, description="Webhook URL to call on completion")
    notify_email: Optional[str] = Field(None, description="Email for notifications")


class ScheduleUpdateRequest(BaseModel):
    """Request to update a scheduled scan."""
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    cron_expression: Optional[str] = None
    analyzers: Optional[list[str]] = None
    is_active: Optional[bool] = None
    webhook_url: Optional[str] = None
    notify_email: Optional[str] = None


class ScheduleResponse(BaseModel):
    """Response for a scheduled scan."""
    schedule_id: str
    app_id: str
    app_name: Optional[str] = None
    package_name: Optional[str] = None
    name: str
    cron_expression: str
    cron_description: Optional[str] = None
    analyzers: list[str]
    is_active: bool
    next_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    last_scan_id: Optional[str] = None
    run_count: int = 0
    webhook_url: Optional[str] = None
    notify_email: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None


class CronValidateRequest(BaseModel):
    """Request to validate a cron expression."""
    cron_expression: str


class CronValidateResponse(BaseModel):
    """Response for cron validation."""
    valid: bool
    message: str
    description: Optional[str] = None
    next_runs: list[str] = []


# Endpoints

@router.post("", response_model=ScheduleResponse)
async def create_schedule(
    request: ScheduleCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new scheduled scan.

    The cron expression follows standard cron format:
    - `0 2 * * *` - Daily at 2 AM
    - `0 0 * * 0` - Weekly on Sunday at midnight
    - `0 0 1 * *` - Monthly on the 1st at midnight
    - `*/15 * * * *` - Every 15 minutes
    """
    service = ScheduledScanService(db)

    # Validate cron expression
    valid, message = service.validate_cron_expression(request.cron_expression)
    if not valid:
        raise HTTPException(status_code=400, detail=message)

    # Verify app exists
    app_check = await db.execute(
        "SELECT app_id FROM mobile_apps WHERE app_id = :app_id",
        {"app_id": request.app_id}
    )
    if not app_check.fetchone():
        raise HTTPException(status_code=404, detail="App not found")

    schedule = await service.create_schedule(
        app_id=request.app_id,
        name=request.name,
        cron_expression=request.cron_expression,
        analyzers=request.analyzers,
        is_active=request.is_active,
        webhook_url=request.webhook_url,
        notify_email=request.notify_email,
    )

    schedule["cron_description"] = service.describe_cron(request.cron_expression)

    return schedule


@router.get("", response_model=dict)
async def list_schedules(
    app_id: Optional[str] = Query(None, description="Filter by app ID"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
):
    """List all scheduled scans with optional filters."""
    service = ScheduledScanService(db)

    result = await service.list_schedules(
        app_id=app_id,
        is_active=is_active,
        page=page,
        page_size=page_size,
    )

    # Add cron descriptions
    for schedule in result["items"]:
        schedule["cron_description"] = service.describe_cron(
            schedule.get("cron_expression", "")
        )

    return result


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a scheduled scan by ID."""
    service = ScheduledScanService(db)

    schedule = await service.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule["cron_description"] = service.describe_cron(
        schedule.get("cron_expression", "")
    )

    return schedule


@router.put("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: str,
    request: ScheduleUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update an existing scheduled scan."""
    service = ScheduledScanService(db)

    # Validate cron expression if provided
    if request.cron_expression:
        valid, message = service.validate_cron_expression(request.cron_expression)
        if not valid:
            raise HTTPException(status_code=400, detail=message)

    schedule = await service.update_schedule(
        schedule_id=schedule_id,
        name=request.name,
        cron_expression=request.cron_expression,
        analyzers=request.analyzers,
        is_active=request.is_active,
        webhook_url=request.webhook_url,
        notify_email=request.notify_email,
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule["cron_description"] = service.describe_cron(
        schedule.get("cron_expression", "")
    )

    return schedule


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scheduled scan."""
    service = ScheduledScanService(db)

    deleted = await service.delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")

    return {"message": "Schedule deleted successfully"}


@router.post("/{schedule_id}/run")
async def trigger_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger a scheduled scan to run immediately."""
    service = ScheduledScanService(db)

    schedule = await service.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Import scan orchestrator to start scan
    from api.services.scan_orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator(db)

    # Start the scan
    scan = await orchestrator.start_scan(
        app_id=schedule["app_id"],
        scan_type="scheduled",
        analyzers=schedule.get("analyzers") or None,
    )

    # Mark the schedule as run
    await service.mark_schedule_run(schedule_id, scan["scan_id"])

    return {
        "message": "Scan triggered successfully",
        "scan_id": scan["scan_id"],
        "schedule_id": schedule_id,
    }


@router.post("/{schedule_id}/pause")
async def pause_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Pause a scheduled scan."""
    service = ScheduledScanService(db)

    schedule = await service.update_schedule(
        schedule_id=schedule_id,
        is_active=False,
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    return {"message": "Schedule paused", "schedule_id": schedule_id}


@router.post("/{schedule_id}/resume")
async def resume_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Resume a paused scheduled scan."""
    service = ScheduledScanService(db)

    schedule = await service.update_schedule(
        schedule_id=schedule_id,
        is_active=True,
    )

    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    return {"message": "Schedule resumed", "schedule_id": schedule_id}


@router.get("/{schedule_id}/history")
async def get_schedule_history(
    schedule_id: str,
    limit: int = Query(10, ge=1, le=50, description="Number of scans to return"),
    db: AsyncSession = Depends(get_db),
):
    """Get scan history for a scheduled scan."""
    service = ScheduledScanService(db)

    schedule = await service.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    history = await service.get_schedule_history(schedule_id, limit)

    return {
        "schedule_id": schedule_id,
        "schedule_name": schedule.get("name"),
        "scans": history,
    }


@router.post("/validate-cron", response_model=CronValidateResponse)
async def validate_cron(
    request: CronValidateRequest,
):
    """
    Validate a cron expression and get next run times.

    Returns validation result, human-readable description,
    and the next 5 scheduled run times.
    """
    valid, message = ScheduledScanService.validate_cron_expression(
        request.cron_expression
    )

    response = {
        "valid": valid,
        "message": message,
        "description": None,
        "next_runs": [],
    }

    if valid:
        response["description"] = ScheduledScanService.describe_cron(
            request.cron_expression
        )
        response["next_runs"] = ScheduledScanService.get_next_runs(
            request.cron_expression, count=5
        )

    return response


@router.get("/due/list")
async def list_due_schedules(
    db: AsyncSession = Depends(get_db),
):
    """
    List all schedules that are due to run.

    This endpoint is used by the scheduler worker to find
    schedules that need to be executed.
    """
    service = ScheduledScanService(db)
    schedules = await service.get_due_schedules()

    return {
        "count": len(schedules),
        "schedules": schedules,
    }
