"""
Screenshot and Screen Recording Router

API endpoints for visual evidence capture.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.screenshot_service import ScreenCaptureService

router = APIRouter(prefix="/captures", tags=["Screen Capture"])


# Request Models

class CaptureScreenshotRequest(BaseModel):
    """Request to capture a screenshot."""
    device_id: str
    app_id: Optional[str] = None
    finding_id: Optional[str] = None
    description: Optional[str] = None


class StartRecordingRequest(BaseModel):
    """Request to start screen recording."""
    device_id: str
    app_id: Optional[str] = None
    max_duration: int = Field(default=180, ge=10, le=600)


class AttachCaptureRequest(BaseModel):
    """Request to attach a capture to a finding."""
    finding_id: str


# Endpoints

@router.post("/screenshot")
async def capture_screenshot(
    request: CaptureScreenshotRequest,
    db: AsyncSession = Depends(get_db),
):
    """Capture a screenshot from a device."""
    service = ScreenCaptureService(db)

    try:
        capture = await service.capture_screenshot(
            device_id=request.device_id,
            app_id=request.app_id,
            finding_id=request.finding_id,
            description=request.description,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return capture


@router.post("/screenshot/ios")
async def capture_screenshot_ios(
    request: CaptureScreenshotRequest,
    db: AsyncSession = Depends(get_db),
):
    """Capture a screenshot from an iOS device."""
    service = ScreenCaptureService(db)

    try:
        capture = await service.capture_screenshot_ios(
            device_id=request.device_id,
            app_id=request.app_id,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return capture


@router.post("/ui-dump")
async def capture_ui_dump(
    device_id: str,
    app_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Capture UI hierarchy dump from a device."""
    service = ScreenCaptureService(db)

    try:
        capture = await service.capture_ui_dump(
            device_id=device_id,
            app_id=app_id,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return capture


@router.post("/recordings/start")
async def start_recording(
    request: StartRecordingRequest,
    db: AsyncSession = Depends(get_db),
):
    """Start screen recording on a device."""
    service = ScreenCaptureService(db)

    try:
        recording = await service.start_recording(
            device_id=request.device_id,
            app_id=request.app_id,
            max_duration=request.max_duration,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return recording


@router.post("/recordings/{recording_id}/stop")
async def stop_recording(
    recording_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Stop a screen recording."""
    service = ScreenCaptureService(db)

    recording = await service.stop_recording(recording_id)
    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found or already stopped")

    return recording


@router.get("/recordings/{recording_id}")
async def get_recording(
    recording_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get recording details."""
    service = ScreenCaptureService(db)
    recording = await service.get_recording(recording_id)

    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found")

    return recording


@router.get("/recordings")
async def list_recordings(
    device_id: Optional[str] = None,
    app_id: Optional[str] = None,
    status: Optional[str] = Query(None, pattern="^(recording|completed)$"),
    db: AsyncSession = Depends(get_db),
):
    """List screen recordings."""
    service = ScreenCaptureService(db)
    recordings = await service.list_recordings(
        device_id=device_id,
        app_id=app_id,
        status=status,
    )
    return {"recordings": recordings, "count": len(recordings)}


@router.get("")
async def list_captures(
    device_id: Optional[str] = None,
    app_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    capture_type: Optional[str] = Query(None, pattern="^(screenshot|ui_dump)$"),
    db: AsyncSession = Depends(get_db),
):
    """List screen captures."""
    service = ScreenCaptureService(db)
    captures = await service.list_captures(
        device_id=device_id,
        app_id=app_id,
        finding_id=finding_id,
        capture_type=capture_type,
    )
    return {"captures": captures, "count": len(captures)}


@router.get("/{capture_id}")
async def get_capture(
    capture_id: str,
    include_data: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """Get capture details."""
    service = ScreenCaptureService(db)

    if include_data:
        capture = await service.get_capture_data(capture_id)
    else:
        captures = await service.list_captures()
        capture = next((c for c in captures if c.get("capture_id") == capture_id), None)

    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")

    return capture


@router.post("/{capture_id}/attach")
async def attach_capture_to_finding(
    capture_id: str,
    request: AttachCaptureRequest,
    db: AsyncSession = Depends(get_db),
):
    """Attach a capture to a finding."""
    service = ScreenCaptureService(db)

    attached = await service.attach_to_finding(
        capture_id=capture_id,
        finding_id=request.finding_id,
    )

    if not attached:
        raise HTTPException(status_code=404, detail="Capture not found")

    return {"message": "Capture attached to finding", "finding_id": request.finding_id}


@router.delete("/{capture_id}")
async def delete_capture(
    capture_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a capture."""
    service = ScreenCaptureService(db)

    deleted = await service.delete_capture(capture_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Capture not found")

    return {"message": "Capture deleted"}
