"""
Network Traffic Analysis Router

API endpoints for network traffic capture and analysis.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.network_traffic_service import NetworkTrafficService

router = APIRouter(prefix="/traffic", tags=["Network Traffic"])


# Request Models

class CreateCaptureSessionRequest(BaseModel):
    """Request to create a traffic capture session."""
    app_id: str
    device_id: str
    capture_method: str = Field(default="mitmproxy", pattern="^(mitmproxy|burp|charles|frida)$")
    proxy_port: int = Field(default=8080, ge=1024, le=65535)


class AddCapturedRequestRequest(BaseModel):
    """Request to add a captured HTTP request."""
    method: str = Field(default="GET")
    url: str
    headers: dict = Field(default_factory=dict)
    body: Optional[str] = None
    response: Optional[dict] = None


# Endpoints

@router.post("/sessions")
async def create_capture_session(
    request: CreateCaptureSessionRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new traffic capture session."""
    service = NetworkTrafficService(db)

    try:
        session = await service.create_capture_session(
            app_id=request.app_id,
            device_id=request.device_id,
            capture_method=request.capture_method,
            proxy_port=request.proxy_port,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return session


@router.get("/sessions")
async def list_capture_sessions(
    app_id: Optional[str] = None,
    status: Optional[str] = Query(None, pattern="^(active|stopped)$"),
    db: AsyncSession = Depends(get_db),
):
    """List traffic capture sessions."""
    service = NetworkTrafficService(db)
    sessions = await service.list_sessions(app_id=app_id, status=status)
    return {"sessions": sessions, "count": len(sessions)}


@router.get("/sessions/{session_id}")
async def get_capture_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get capture session details."""
    service = NetworkTrafficService(db)
    session = await service.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return session


@router.post("/sessions/{session_id}/stop")
async def stop_capture_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Stop a traffic capture session."""
    service = NetworkTrafficService(db)

    stopped = await service.stop_capture_session(session_id)
    if not stopped:
        raise HTTPException(status_code=404, detail="Session not found or already stopped")

    return {"message": "Session stopped", "session_id": session_id}


@router.post("/sessions/{session_id}/requests")
async def add_captured_request(
    session_id: str,
    request: AddCapturedRequestRequest,
    db: AsyncSession = Depends(get_db),
):
    """Add a captured HTTP request to a session."""
    service = NetworkTrafficService(db)

    # Verify session exists
    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.get("status") != "active":
        raise HTTPException(status_code=400, detail="Session is not active")

    request_data = {
        "method": request.method,
        "url": request.url,
        "headers": request.headers,
        "body": request.body,
        "response": request.response,
    }

    result = await service.add_captured_request(session_id, request_data)
    return result


@router.get("/sessions/{session_id}/requests")
async def get_captured_requests(
    session_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Get captured requests for a session."""
    service = NetworkTrafficService(db)

    requests = await service.get_captured_requests(session_id, limit=limit, offset=offset)
    return {"requests": requests, "count": len(requests)}


@router.get("/sessions/{session_id}/analyze")
async def analyze_capture_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Analyze all traffic in a capture session."""
    service = NetworkTrafficService(db)

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
    """Create findings from traffic analysis."""
    service = NetworkTrafficService(db)

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


@router.get("/sessions/{session_id}/config")
async def get_proxy_config(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get proxy configuration for a capture session."""
    service = NetworkTrafficService(db)

    try:
        config = await service.get_mitmproxy_config(session_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return config


@router.get("/sessions/{session_id}/export/har")
async def export_session_har(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Export captured traffic as HAR format."""
    service = NetworkTrafficService(db)

    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    har = await service.export_har(session_id)
    return har
