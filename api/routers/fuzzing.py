"""
Automated Fuzzing Router

API endpoints for automated fuzzing.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.fuzzing_service import FuzzingService

router = APIRouter(prefix="/fuzzing", tags=["Fuzzing"])


# Request Models

class CreateFuzzSessionRequest(BaseModel):
    """Request to create a fuzzing session."""
    app_id: str
    fuzz_type: str = Field(
        ...,
        pattern="^(input_field|intent|url_scheme|deep_link|api|file)$"
    )
    target: str = Field(..., description="Target to fuzz (field name, activity, URL, etc.)")
    payload_types: list[str] = Field(
        default=["sql_injection", "xss", "command_injection"],
        description="Types of payloads to use"
    )
    max_iterations: int = Field(default=100, ge=1, le=10000)


class RecordFuzzResultRequest(BaseModel):
    """Request to record a fuzz result."""
    payload_type: str
    payload: str
    response: Optional[str] = None
    is_crash: bool = False
    is_timeout: bool = False
    is_interesting: bool = False
    details: Optional[dict] = None


# Endpoints

@router.post("/sessions")
async def create_fuzz_session(
    request: CreateFuzzSessionRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new fuzzing session."""
    service = FuzzingService(db)

    try:
        session = await service.create_fuzz_session(
            app_id=request.app_id,
            fuzz_type=request.fuzz_type,
            target=request.target,
            payload_types=request.payload_types,
            max_iterations=request.max_iterations,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return session


@router.get("/sessions")
async def list_fuzz_sessions(
    app_id: Optional[str] = None,
    status: Optional[str] = Query(None, pattern="^(pending|running|completed|stopped)$"),
    db: AsyncSession = Depends(get_db),
):
    """List fuzzing sessions."""
    service = FuzzingService(db)
    sessions = await service.list_sessions(app_id=app_id, status=status)
    return {"sessions": sessions, "count": len(sessions)}


@router.get("/sessions/{session_id}")
async def get_fuzz_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get fuzzing session details."""
    service = FuzzingService(db)
    session = await service.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return session


@router.post("/sessions/{session_id}/start")
async def start_fuzz_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Start a fuzzing session."""
    service = FuzzingService(db)

    started = await service.start_fuzz_session(session_id)
    if not started:
        raise HTTPException(status_code=400, detail="Session not found or not pending")

    return {"message": "Session started", "session_id": session_id}


@router.post("/sessions/{session_id}/stop")
async def stop_fuzz_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Stop a fuzzing session."""
    service = FuzzingService(db)

    stopped = await service.stop_fuzz_session(session_id)
    if not stopped:
        raise HTTPException(status_code=404, detail="Session not found or not running")

    return {"message": "Session stopped", "session_id": session_id}


@router.post("/sessions/{session_id}/results")
async def record_fuzz_result(
    session_id: str,
    request: RecordFuzzResultRequest,
    db: AsyncSession = Depends(get_db),
):
    """Record a fuzzing result."""
    service = FuzzingService(db)

    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    result = await service.record_fuzz_result(
        session_id=session_id,
        payload_type=request.payload_type,
        payload=request.payload,
        response=request.response,
        is_crash=request.is_crash,
        is_timeout=request.is_timeout,
        is_interesting=request.is_interesting,
        details=request.details,
    )

    return result


@router.get("/sessions/{session_id}/results")
async def get_fuzz_results(
    session_id: str,
    crashes_only: bool = False,
    interesting_only: bool = False,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Get fuzzing results for a session."""
    service = FuzzingService(db)

    results = await service.get_fuzz_results(
        session_id=session_id,
        crashes_only=crashes_only,
        interesting_only=interesting_only,
        limit=limit,
        offset=offset,
    )

    return {"results": results, "count": len(results)}


@router.get("/sessions/{session_id}/summary")
async def get_fuzz_session_summary(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get summary of a fuzzing session."""
    service = FuzzingService(db)

    summary = await service.get_session_summary(session_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Session not found")

    return summary


@router.get("/sessions/{session_id}/payloads")
async def get_session_payloads(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get generated payloads for a fuzzing session."""
    service = FuzzingService(db)

    try:
        payloads = await service.generate_payloads_for_session(session_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {"payloads": payloads, "count": len(payloads)}


@router.post("/sessions/{session_id}/create-findings")
async def create_findings_from_session(
    session_id: str,
    scan_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Create findings from fuzzing results."""
    service = FuzzingService(db)

    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    app_id = session.get("app_id")
    if not app_id:
        raise HTTPException(status_code=400, detail="Session has no associated app")

    finding_ids = await service.create_findings_from_results(
        session_id=session_id,
        app_id=app_id,
        scan_id=scan_id,
    )

    return {
        "message": f"Created {len(finding_ids)} findings",
        "finding_ids": finding_ids,
    }


@router.get("/sessions/{session_id}/frida-script")
async def get_frida_fuzzer_script(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get Frida script for fuzzing."""
    service = FuzzingService(db)

    session = await service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    fuzz_type = session.get("fuzz_type", "input_field")
    target = session.get("target", "")

    script = service.get_frida_fuzzer_script(fuzz_type, target)

    return {
        "session_id": session_id,
        "fuzz_type": fuzz_type,
        "target": target,
        "script": script,
    }


@router.get("/payload-types")
async def get_payload_types():
    """Get available fuzzing payload types."""
    return {
        "types": [
            {"name": "sql_injection", "description": "SQL injection payloads"},
            {"name": "xss", "description": "Cross-site scripting payloads"},
            {"name": "command_injection", "description": "OS command injection payloads"},
            {"name": "path_traversal", "description": "Path/directory traversal payloads"},
            {"name": "format_string", "description": "Format string attack payloads"},
            {"name": "buffer_overflow", "description": "Buffer overflow payloads"},
            {"name": "integer_overflow", "description": "Integer overflow payloads"},
            {"name": "unicode", "description": "Unicode edge case payloads"},
            {"name": "special_chars", "description": "Special character payloads"},
            {"name": "null_byte", "description": "Null byte injection payloads"},
        ]
    }


@router.get("/fuzz-types")
async def get_fuzz_types():
    """Get available fuzzing target types."""
    return {
        "types": [
            {"name": "input_field", "description": "Text input fields"},
            {"name": "intent", "description": "Android Intents"},
            {"name": "url_scheme", "description": "URL schemes/deep links"},
            {"name": "deep_link", "description": "App deep links"},
            {"name": "api", "description": "API endpoints"},
            {"name": "file", "description": "File format parsing"},
        ]
    }
