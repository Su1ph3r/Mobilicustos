"""Bypass router for anti-detection framework."""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import BypassResult, Device, FridaScript, MobileApp
from api.models.schemas import BypassResultCreate, BypassResultResponse, FridaScriptResponse, PaginatedResponse
from api.services.bypass_orchestrator import BypassOrchestrator

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/results", response_model=PaginatedResponse)
async def list_bypass_results(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    app_id: str | None = None,
    detection_type: str | None = None,
    bypass_status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all bypass results with pagination and filters."""
    query = select(BypassResult)

    if app_id:
        query = query.where(BypassResult.app_id == app_id)
    if detection_type:
        query = query.where(BypassResult.detection_type == detection_type)
    if bypass_status:
        query = query.where(BypassResult.bypass_status == bypass_status)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(BypassResult.attempted_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    results = result.scalars().all()

    return PaginatedResponse(
        items=[BypassResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.post("/analyze")
async def analyze_protections(
    app_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Analyze an app's protection mechanisms (static analysis)."""
    # Verify app
    result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    orchestrator = BypassOrchestrator()
    try:
        detections = await orchestrator.analyze_protections(app)
        return {
            "app_id": app_id,
            "detections": detections,
            "total": len(detections),
        }
    except Exception as e:
        logger.error(f"Failed to analyze protections: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze protections")


@router.post("/attempt")
async def attempt_bypass(
    app_id: str,
    device_id: str,
    detection_type: str,
    script_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Attempt to bypass a specific protection."""
    # Verify app
    app_result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Verify device
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    # Get bypass script if specified
    script = None
    if script_id:
        script_result = await db.execute(
            select(FridaScript).where(FridaScript.script_id == script_id)
        )
        script = script_result.scalar_one_or_none()
        if not script:
            raise HTTPException(status_code=404, detail="Script not found")

    orchestrator = BypassOrchestrator()
    try:
        result = await orchestrator.attempt_bypass(
            app=app,
            device=device,
            detection_type=detection_type,
            script=script,
        )

        # Save result
        bypass_result = BypassResult(
            app_id=app_id,
            device_id=device_id,
            detection_type=detection_type,
            detection_method=result.get("detection_method"),
            detection_library=result.get("detection_library"),
            bypass_script_id=script_id,
            bypass_status=result.get("status"),
            bypass_notes=result.get("notes"),
            poc_evidence=result.get("poc_evidence"),
        )
        db.add(bypass_result)
        await db.commit()

        return result
    except Exception as e:
        logger.error(f"Bypass attempt failed: {e}")
        raise HTTPException(status_code=500, detail="Bypass attempt failed")


@router.post("/auto-bypass")
async def auto_bypass(
    app_id: str,
    device_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Automatically detect and bypass all protections."""
    # Verify app
    app_result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Verify device
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    orchestrator = BypassOrchestrator()
    try:
        results = await orchestrator.auto_bypass(app, device, db)
        return {
            "app_id": app_id,
            "device_id": device_id,
            "results": results,
            "summary": {
                "total": len(results),
                "success": sum(1 for r in results if r["status"] == "success"),
                "partial": sum(1 for r in results if r["status"] == "partial"),
                "failed": sum(1 for r in results if r["status"] == "failed"),
            },
        }
    except Exception as e:
        logger.error(f"Auto-bypass failed: {e}")
        raise HTTPException(status_code=500, detail="Auto-bypass failed")


@router.get("/detection-types")
async def get_detection_types():
    """Get available detection types."""
    return {
        "detection_types": [
            {
                "type": "frida",
                "description": "Frida instrumentation detection",
                "methods": ["port_scan", "file_check", "memory_scan", "thread_check"],
            },
            {
                "type": "root",
                "description": "Root/superuser detection",
                "methods": ["file_check", "command_exec", "prop_check"],
            },
            {
                "type": "jailbreak",
                "description": "iOS jailbreak detection",
                "methods": ["file_check", "url_scheme", "fork_check", "sandbox_check"],
            },
            {
                "type": "emulator",
                "description": "Emulator/simulator detection",
                "methods": ["prop_check", "build_check", "sensor_check"],
            },
            {
                "type": "debugger",
                "description": "Debugger attachment detection",
                "methods": ["ptrace", "status_check", "timing_check"],
            },
            {
                "type": "ssl_pinning",
                "description": "SSL certificate pinning",
                "methods": ["trustmanager", "okhttp", "alamofire", "nsurlsession"],
            },
        ]
    }


@router.get("/scripts/recommended")
async def get_recommended_scripts(
    app_id: str,
    detection_type: str,
    db: AsyncSession = Depends(get_db),
):
    """Get recommended bypass scripts for a detection type."""
    # Get app for framework info
    app_result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Find matching scripts
    query = (
        select(FridaScript)
        .where(FridaScript.category == "bypass")
        .where(FridaScript.subcategory == detection_type)
        .where(FridaScript.platforms.contains([app.platform]))
    )

    # Prioritize framework-specific scripts
    if app.framework:
        query = query.order_by(
            FridaScript.target_frameworks.contains([app.framework]).desc(),
            FridaScript.is_builtin.desc(),
        )

    result = await db.execute(query)
    scripts = result.scalars().all()

    return {
        "app_id": app_id,
        "detection_type": detection_type,
        "platform": app.platform,
        "framework": app.framework,
        "recommended_scripts": [
            FridaScriptResponse.model_validate(s) for s in scripts
        ],
    }
