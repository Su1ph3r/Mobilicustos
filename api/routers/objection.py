"""Objection router for runtime mobile app manipulation."""

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Device, MobileApp, ObjectionSession
from api.models.schemas import PaginatedResponse
from api.services.objection_service import ObjectionService

router = APIRouter()
logger = logging.getLogger(__name__)


# Request/Response Models
class ObjectionSessionCreate(BaseModel):
    """Request to start an Objection session."""
    device_id: str
    package_name: str


class ObjectionCommandRun(BaseModel):
    """Request to run an Objection command."""
    command: str
    args: list[str] = []


class ObjectionSessionResponse(BaseModel):
    """Objection session response."""
    session_id: UUID
    device_id: str
    package_name: str
    platform: str
    status: str
    frida_session_id: str | None = None
    started_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None

    class Config:
        from_attributes = True


@router.get("/commands")
async def list_commands(platform: str | None = None):
    """List available Objection commands grouped by category."""
    service = ObjectionService()
    commands = await service.list_commands(platform)
    return {"commands": commands}


@router.get("/status")
async def check_objection_status():
    """Check if Objection is installed and available."""
    service = ObjectionService()
    installed = await service.check_objection_installed()
    return {
        "installed": installed,
        "message": "Objection is available" if installed else "Objection is not installed",
    }


@router.post("/sessions", response_model=ObjectionSessionResponse)
async def start_session(
    request: ObjectionSessionCreate,
    db: AsyncSession = Depends(get_db),
):
    """Start a new Objection session on a device."""
    # Verify device exists and is connected
    device_result = await db.execute(
        select(Device).where(Device.device_id == request.device_id)
    )
    device = device_result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    platform = device.platform
    if platform not in ("android", "ios"):
        raise HTTPException(status_code=400, detail="Unsupported platform")

    # Check for existing active session on this device
    existing = await db.execute(
        select(ObjectionSession).where(
            ObjectionSession.device_id == request.device_id,
            ObjectionSession.status == "active",
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="Active Objection session already exists for this device",
        )

    # Start the session
    service = ObjectionService()
    session_info = await service.start_session(
        device_id=request.device_id,
        package_name=request.package_name,
        platform=platform,
    )

    if session_info.get("status") == "error":
        raise HTTPException(
            status_code=500,
            detail=session_info.get("error", "Failed to start Objection session"),
        )

    # Get app_id if package exists in our database
    app_result = await db.execute(
        select(MobileApp).where(MobileApp.package_name == request.package_name)
    )
    app = app_result.scalar_one_or_none()

    # Create session record
    session = ObjectionSession(
        device_id=request.device_id,
        app_id=app.app_id if app else None,
        package_name=request.package_name,
        platform=platform,
        status=session_info.get("status", "active"),
    )

    db.add(session)
    await db.commit()
    await db.refresh(session)

    return ObjectionSessionResponse.model_validate(session)


@router.get("/sessions", response_model=PaginatedResponse)
async def list_sessions(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    device_id: str | None = None,
    platform: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List Objection sessions with pagination."""
    query = select(ObjectionSession)

    if device_id:
        query = query.where(ObjectionSession.device_id == device_id)
    if platform:
        query = query.where(ObjectionSession.platform == platform)
    if status:
        query = query.where(ObjectionSession.status == status)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(ObjectionSession.started_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    sessions = result.scalars().all()

    return PaginatedResponse(
        items=[ObjectionSessionResponse.model_validate(s) for s in sessions],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/sessions/{session_id}", response_model=ObjectionSessionResponse)
async def get_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get an Objection session by ID."""
    result = await db.execute(
        select(ObjectionSession).where(ObjectionSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return ObjectionSessionResponse.model_validate(session)


@router.post("/sessions/{session_id}/execute")
async def execute_command(
    session_id: UUID,
    request: ObjectionCommandRun,
    db: AsyncSession = Depends(get_db),
):
    """Execute an Objection command in a session."""
    # Get session
    result = await db.execute(
        select(ObjectionSession).where(ObjectionSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status != "active":
        raise HTTPException(status_code=400, detail="Session is not active")

    # Execute command
    service = ObjectionService()
    cmd_result = await service.execute_command(
        device_id=session.device_id,
        package_name=session.package_name,
        platform=session.platform,
        command=request.command,
        args=request.args,
    )

    if cmd_result.get("result_type") == "error":
        raise HTTPException(
            status_code=500,
            detail=cmd_result.get("error", "Command execution failed"),
        )

    # Update session command history
    if session.command_history is None:
        session.command_history = []
    session.command_history = session.command_history + [{
        "command": request.command,
        "args": request.args,
        "executed_at": datetime.utcnow().isoformat(),
    }]
    await db.commit()

    return cmd_result


@router.delete("/sessions/{session_id}")
async def stop_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Stop an Objection session."""
    result = await db.execute(
        select(ObjectionSession).where(ObjectionSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status == "active":
        service = ObjectionService()
        await service.stop_session(str(session_id))

    session.status = "stopped"
    session.completed_at = datetime.utcnow()
    await db.commit()

    return {"message": "Session stopped"}


# Quick action endpoints
@router.post("/quick/disable-ssl-pinning")
async def quick_disable_ssl_pinning(
    device_id: str,
    package_name: str,
    db: AsyncSession = Depends(get_db),
):
    """Quick action: Disable SSL pinning."""
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    service = ObjectionService()
    result = await service.disable_ssl_pinning(device_id, package_name, device.platform)

    if result.get("result_type") == "error":
        raise HTTPException(status_code=500, detail=result.get("error"))

    return result


@router.post("/quick/disable-root-detection")
async def quick_disable_root_detection(
    device_id: str,
    package_name: str,
    db: AsyncSession = Depends(get_db),
):
    """Quick action: Disable root/jailbreak detection."""
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    service = ObjectionService()
    result = await service.disable_root_detection(device_id, package_name, device.platform)

    if result.get("result_type") == "error":
        raise HTTPException(status_code=500, detail=result.get("error"))

    return result


@router.post("/quick/dump-keychain")
async def quick_dump_keychain(
    device_id: str,
    package_name: str,
    db: AsyncSession = Depends(get_db),
):
    """Quick action: Dump keychain/keystore."""
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    service = ObjectionService()
    result = await service.dump_keychain(device_id, package_name, device.platform)

    if result.get("result_type") == "error":
        raise HTTPException(status_code=500, detail=result.get("error"))

    return result


@router.post("/quick/list-modules")
async def quick_list_modules(
    device_id: str,
    package_name: str,
    db: AsyncSession = Depends(get_db),
):
    """Quick action: List loaded modules."""
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    service = ObjectionService()
    result = await service.list_modules(device_id, package_name, device.platform)

    if result.get("result_type") == "error":
        raise HTTPException(status_code=500, detail=result.get("error"))

    return result


@router.get("/sessions/{session_id}/files")
async def list_files(
    session_id: UUID,
    path: str = Query("/data/data"),
    db: AsyncSession = Depends(get_db),
):
    """List files in a directory."""
    result = await db.execute(
        select(ObjectionSession).where(ObjectionSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status != "active":
        raise HTTPException(status_code=400, detail="Session is not active")

    service = ObjectionService()
    result_data = await service.list_directory(
        session.device_id, session.package_name, session.platform, path
    )

    if result_data.get("result_type") == "error":
        raise HTTPException(status_code=500, detail=result_data.get("error"))

    return result_data


@router.get("/sessions/{session_id}/file")
async def read_file(
    session_id: UUID,
    path: str,
    db: AsyncSession = Depends(get_db),
):
    """Read a file's contents."""
    result = await db.execute(
        select(ObjectionSession).where(ObjectionSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status != "active":
        raise HTTPException(status_code=400, detail="Session is not active")

    service = ObjectionService()
    result_data = await service.read_file(
        session.device_id, session.package_name, session.platform, path
    )

    if result_data.get("result_type") == "error":
        raise HTTPException(status_code=500, detail=result_data.get("error"))

    return result_data


@router.post("/sessions/{session_id}/sql")
async def execute_sql(
    session_id: UUID,
    db_path: str,
    query: str,
    db: AsyncSession = Depends(get_db),
):
    """Execute SQL query on a database."""
    result = await db.execute(
        select(ObjectionSession).where(ObjectionSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status != "active":
        raise HTTPException(status_code=400, detail="Session is not active")

    service = ObjectionService()
    result_data = await service.execute_sql(
        session.device_id, session.package_name, session.platform, db_path, query
    )

    if result_data.get("result_type") == "error":
        raise HTTPException(status_code=500, detail=result_data.get("error"))

    return result_data


@router.get("/sessions/{session_id}/plist")
async def read_plist(
    session_id: UUID,
    path: str,
    db: AsyncSession = Depends(get_db),
):
    """Read iOS plist file."""
    result = await db.execute(
        select(ObjectionSession).where(ObjectionSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.platform != "ios":
        raise HTTPException(status_code=400, detail="Plist reading is iOS only")
    if session.status != "active":
        raise HTTPException(status_code=400, detail="Session is not active")

    service = ObjectionService()
    result_data = await service.read_plist(
        session.device_id, session.package_name, path
    )

    if result_data.get("result_type") == "error":
        raise HTTPException(status_code=500, detail=result_data.get("error"))

    return result_data
