"""
Runtime Behavior Monitor Router

API endpoints for runtime behavior monitoring.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.runtime_monitor_service import RuntimeMonitorService

router = APIRouter(prefix="/runtime", tags=["Runtime Monitor"])


# Request Models

class CreateMonitorSessionRequest(BaseModel):
    """Request to create a runtime monitoring session."""
    app_id: str
    device_id: str
    monitor_types: list[str] = Field(
        default=["all"],
        description="Types: syscall, filesystem, network, permission, ipc, crypto, all"
    )
    duration_seconds: int = Field(default=300, ge=30, le=3600)


class RecordEventRequest(BaseModel):
    """Request to record a runtime event."""
    event_type: str
    process_name: str
    details: dict = Field(default_factory=dict)
    is_suspicious: bool = False


# Endpoints

@router.post("/sessions")
async def create_monitor_session(
    request: CreateMonitorSessionRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new runtime monitoring session."""
    service = RuntimeMonitorService(db)

    try:
        session = await service.create_monitor_session(
            app_id=request.app_id,
            device_id=request.device_id,
            monitor_types=request.monitor_types,
            duration_seconds=request.duration_seconds,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return session


@router.get("/sessions")
async def list_monitor_sessions(
    app_id: Optional[str] = None,
    status: Optional[str] = Query(None, pattern="^(active|stopped)$"),
    db: AsyncSession = Depends(get_db),
):
    """List runtime monitoring sessions."""
    service = RuntimeMonitorService(db)
    sessions = await service.list_sessions(app_id=app_id, status=status)
    return {"sessions": sessions, "count": len(sessions)}


@router.get("/sessions/{session_id}")
async def get_monitor_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get monitoring session details."""
    service = RuntimeMonitorService(db)
    session = await service.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return session


@router.post("/sessions/{session_id}/stop")
async def stop_monitor_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Stop a runtime monitoring session."""
    service = RuntimeMonitorService(db)

    stopped = await service.stop_monitor_session(session_id)
    if not stopped:
        raise HTTPException(status_code=404, detail="Session not found or already stopped")

    return {"message": "Session stopped", "session_id": session_id}


@router.post("/sessions/{session_id}/events")
async def record_event(
    session_id: str,
    request: RecordEventRequest,
    db: AsyncSession = Depends(get_db),
):
    """Record a runtime event."""
    service = RuntimeMonitorService(db)

    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.get("status") != "active":
        raise HTTPException(status_code=400, detail="Session is not active")

    event = await service.record_event(
        session_id=session_id,
        event_type=request.event_type,
        process_name=request.process_name,
        details=request.details,
        is_suspicious=request.is_suspicious,
    )

    return event


@router.get("/sessions/{session_id}/events")
async def get_events(
    session_id: str,
    event_type: Optional[str] = None,
    suspicious_only: bool = False,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Get events for a monitoring session."""
    service = RuntimeMonitorService(db)

    events = await service.get_events(
        session_id=session_id,
        event_type=event_type,
        suspicious_only=suspicious_only,
        limit=limit,
        offset=offset,
    )

    return {"events": events, "count": len(events)}


@router.get("/sessions/{session_id}/analyze")
async def analyze_monitor_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Analyze all events in a monitoring session."""
    service = RuntimeMonitorService(db)

    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    analysis = await service.analyze_session(session_id)
    return analysis


@router.post("/sessions/{session_id}/create-findings")
async def create_findings_from_session(
    session_id: str,
    scan_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Create findings from runtime analysis."""
    service = RuntimeMonitorService(db)

    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    app_id = session.get("app_id")
    if not app_id:
        raise HTTPException(status_code=400, detail="Session has no associated app")

    finding_ids = await service.create_findings_from_analysis(
        session_id=session_id,
        app_id=app_id,
        scan_id=scan_id,
    )

    return {
        "message": f"Created {len(finding_ids)} findings",
        "finding_ids": finding_ids,
    }


@router.get("/sessions/{session_id}/frida-script")
async def get_frida_monitor_script(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get Frida script for runtime monitoring."""
    service = RuntimeMonitorService(db)

    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    monitor_types = session.get("monitor_types", ["all"])
    script = service.get_frida_monitor_script(monitor_types)

    # Replace placeholders
    script = script.replace("%SESSION_ID%", session_id)
    script = script.replace("%WEBHOOK_URL%", f"/api/runtime/sessions/{session_id}/events")

    return {
        "session_id": session_id,
        "monitor_types": monitor_types,
        "script": script,
    }
