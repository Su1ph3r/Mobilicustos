"""Drozer router for dynamic Android security testing."""

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Device, DrozerResult, DrozerSession, MobileApp
from api.models.schemas import PaginatedResponse
from api.services.drozer_service import DrozerService

router = APIRouter()
logger = logging.getLogger(__name__)


# Request/Response Models
class DrozerSessionCreate(BaseModel):
    """Request to start a Drozer session."""
    device_id: str
    package_name: str


class DrozerModuleRun(BaseModel):
    """Request to run a Drozer module."""
    module_name: str
    args: dict = {}


class DrozerSessionResponse(BaseModel):
    """Drozer session response."""
    session_id: UUID
    device_id: str
    package_name: str
    status: str
    drozer_port: int | None = None
    started_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None

    class Config:
        from_attributes = True


class DrozerResultResponse(BaseModel):
    """Drozer result response."""
    result_id: UUID
    session_id: UUID
    module_name: str
    module_args: dict
    result_type: str
    result_data: dict
    raw_output: str | None = None
    finding_id: str | None = None
    executed_at: datetime

    class Config:
        from_attributes = True


@router.get("/modules")
async def list_modules():
    """List available Drozer modules grouped by category."""
    service = DrozerService()
    modules = await service.list_modules()
    return {"modules": modules}


@router.get("/status")
async def check_drozer_status():
    """Check if Drozer is installed and available."""
    service = DrozerService()
    installed = await service.check_drozer_installed()
    return {
        "installed": installed,
        "message": "Drozer is available" if installed else "Drozer is not installed",
    }


@router.post("/sessions", response_model=DrozerSessionResponse)
async def start_session(
    request: DrozerSessionCreate,
    db: AsyncSession = Depends(get_db),
):
    """Start a new Drozer session on a device."""
    # Verify device exists and is connected
    device_result = await db.execute(
        select(Device).where(Device.device_id == request.device_id)
    )
    device = device_result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")
    if device.platform != "android":
        raise HTTPException(status_code=400, detail="Drozer only supports Android devices")

    # Check for existing active session on this device
    existing = await db.execute(
        select(DrozerSession).where(
            DrozerSession.device_id == request.device_id,
            DrozerSession.status == "active",
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="Active Drozer session already exists for this device",
        )

    # Start the session
    service = DrozerService()
    session_info = await service.start_session(
        device_id=request.device_id,
        package_name=request.package_name,
    )

    if session_info.get("status") == "error":
        raise HTTPException(
            status_code=500,
            detail=session_info.get("error", "Failed to start Drozer session"),
        )

    # Get app_id if package exists in our database
    app_result = await db.execute(
        select(MobileApp).where(MobileApp.package_name == request.package_name)
    )
    app = app_result.scalar_one_or_none()

    # Create session record
    session = DrozerSession(
        device_id=request.device_id,
        app_id=app.app_id if app else None,
        package_name=request.package_name,
        status=session_info.get("status", "active"),
        drozer_port=session_info.get("drozer_port"),
    )

    db.add(session)
    await db.commit()
    await db.refresh(session)

    return DrozerSessionResponse.model_validate(session)


@router.get("/sessions", response_model=PaginatedResponse)
async def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    device_id: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List Drozer sessions with pagination."""
    query = select(DrozerSession)

    if device_id:
        query = query.where(DrozerSession.device_id == device_id)
    if status:
        query = query.where(DrozerSession.status == status)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(DrozerSession.started_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    sessions = result.scalars().all()

    return PaginatedResponse(
        items=[DrozerSessionResponse.model_validate(s) for s in sessions],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/sessions/{session_id}", response_model=DrozerSessionResponse)
async def get_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a Drozer session by ID."""
    result = await db.execute(
        select(DrozerSession).where(DrozerSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return DrozerSessionResponse.model_validate(session)


@router.post("/sessions/{session_id}/run", response_model=DrozerResultResponse)
async def run_module(
    session_id: UUID,
    request: DrozerModuleRun,
    db: AsyncSession = Depends(get_db),
):
    """Execute a Drozer module in a session."""
    # Get session
    result = await db.execute(
        select(DrozerSession).where(DrozerSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status != "active":
        raise HTTPException(status_code=400, detail="Session is not active")

    # Run module
    service = DrozerService()
    module_result = await service.run_module(
        session_id=session_id,
        device_id=session.device_id,
        module_name=request.module_name,
        args=request.args,
    )

    if module_result.get("result_type") == "error":
        raise HTTPException(
            status_code=500,
            detail=module_result.get("error", "Module execution failed"),
        )

    # Save result
    db_result = DrozerResult(
        session_id=session_id,
        module_name=request.module_name,
        module_args=request.args,
        result_type=module_result.get("result_type", "info"),
        result_data=module_result.get("data", {}),
        raw_output=module_result.get("raw_output"),
    )

    db.add(db_result)
    await db.commit()
    await db.refresh(db_result)

    return DrozerResultResponse.model_validate(db_result)


@router.get("/sessions/{session_id}/results", response_model=PaginatedResponse)
async def get_session_results(
    session_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Get results from a Drozer session."""
    # Verify session exists
    session_result = await db.execute(
        select(DrozerSession).where(DrozerSession.session_id == session_id)
    )
    if not session_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Session not found")

    query = select(DrozerResult).where(DrozerResult.session_id == session_id)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(DrozerResult.executed_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    results = result.scalars().all()

    return PaginatedResponse(
        items=[DrozerResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.delete("/sessions/{session_id}")
async def stop_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Stop a Drozer session."""
    result = await db.execute(
        select(DrozerSession).where(DrozerSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status == "active":
        # Stop the session
        service = DrozerService()
        await service.stop_session(session.device_id)

    session.status = "stopped"
    session.completed_at = datetime.utcnow()
    await db.commit()

    return {"message": "Session stopped"}


# Quick action endpoints
@router.post("/quick/attack-surface")
async def quick_attack_surface(
    device_id: str,
    package_name: str,
    db: AsyncSession = Depends(get_db),
):
    """Quick action: Get attack surface for a package."""
    # Verify device
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    service = DrozerService()
    result = await service.get_attack_surface(device_id, package_name)

    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    return result


@router.post("/quick/enumerate-providers")
async def quick_enumerate_providers(
    device_id: str,
    package_name: str,
    db: AsyncSession = Depends(get_db),
):
    """Quick action: Enumerate content providers for a package."""
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    service = DrozerService()
    result = await service.enumerate_providers(device_id, package_name)

    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    return result


@router.post("/quick/test-sqli")
async def quick_test_sql_injection(
    device_id: str,
    package_name: str,
    db: AsyncSession = Depends(get_db),
):
    """Quick action: Test for SQL injection in content providers."""
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    service = DrozerService()
    result = await service.test_sql_injection(device_id, package_name)

    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    return result


@router.post("/quick/test-traversal")
async def quick_test_path_traversal(
    device_id: str,
    package_name: str,
    db: AsyncSession = Depends(get_db),
):
    """Quick action: Test for path traversal in content providers."""
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    service = DrozerService()
    result = await service.test_path_traversal(device_id, package_name)

    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    return result
