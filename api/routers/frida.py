"""Frida router for script management and injection."""

import hashlib
import logging
import re
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Device, FridaScript, MobileApp
from api.models.schemas import FridaScriptCreate, FridaScriptResponse, PaginatedResponse
from api.services.frida_service import FridaService

router = APIRouter()
logger = logging.getLogger(__name__)

# Script sources for known repositories
KNOWN_SCRIPT_SOURCES = {
    "frida-codeshare": "https://codeshare.frida.re/api/project/",
    "github-raw": "https://raw.githubusercontent.com/",
}


@router.get("/scripts", response_model=PaginatedResponse)
async def list_scripts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    category: str | None = None,
    subcategory: str | None = None,
    platform: str | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all Frida scripts with pagination and filters."""
    query = select(FridaScript)

    if category:
        query = query.where(FridaScript.category == category)
    if subcategory:
        query = query.where(FridaScript.subcategory == subcategory)
    if platform:
        query = query.where(FridaScript.platforms.contains([platform]))
    if search:
        query = query.where(
            FridaScript.script_name.ilike(f"%{search}%")
            | FridaScript.description.ilike(f"%{search}%")
        )

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(FridaScript.is_builtin.desc(), FridaScript.script_name)
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    scripts = result.scalars().all()

    return PaginatedResponse(
        items=[FridaScriptResponse.model_validate(s) for s in scripts],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


# IMPORTANT: This static route must be defined BEFORE /scripts/{script_id}
# to prevent "categories" from being parsed as a UUID
@router.get("/scripts/categories")
async def get_script_categories(db: AsyncSession = Depends(get_db)):
    """Get available script categories."""
    categories = await db.execute(
        select(FridaScript.category, FridaScript.subcategory)
        .distinct()
        .order_by(FridaScript.category, FridaScript.subcategory)
    )

    result = {}
    for category, subcategory in categories.all():
        if category not in result:
            result[category] = []
        if subcategory and subcategory not in result[category]:
            result[category].append(subcategory)

    return result


@router.post("/scripts/import", response_model=FridaScriptResponse)
async def import_script(
    file: UploadFile | None = File(None, description="JavaScript file to import"),
    url: str | None = Form(None, description="URL to fetch script from"),
    script_name: str | None = Form(None, description="Name for the script"),
    category: str = Form("custom", description="Script category"),
    subcategory: str | None = Form(None, description="Script subcategory"),
    description: str | None = Form(None, description="Script description"),
    platforms: str = Form("android,ios", description="Comma-separated platforms"),
    db: AsyncSession = Depends(get_db),
):
    """
    Import a Frida script from a file upload or URL.

    Supports:
    - Direct file upload (.js files)
    - URLs to raw JavaScript files
    - Frida CodeShare project IDs (e.g., codeshare:project-name)
    - GitHub raw URLs
    """
    script_content = None
    source_url = None
    detected_name = None

    if file and url:
        raise HTTPException(
            status_code=400,
            detail="Provide either file or url, not both",
        )

    if not file and not url:
        raise HTTPException(
            status_code=400,
            detail="Either file or url is required",
        )

    # Handle file upload
    if file:
        if not file.filename or not file.filename.endswith(".js"):
            raise HTTPException(
                status_code=400,
                detail="File must be a JavaScript file (.js)",
            )

        try:
            content_bytes = await file.read()
            if len(content_bytes) > 5 * 1024 * 1024:  # 5MB limit
                raise HTTPException(
                    status_code=400,
                    detail="File too large (max 5MB)",
                )
            script_content = content_bytes.decode("utf-8")
            detected_name = file.filename.rsplit(".", 1)[0]
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=400,
                detail="File must be valid UTF-8 text",
            )

    # Handle URL import
    if url:
        source_url = url

        # Handle Frida CodeShare
        if url.startswith("codeshare:"):
            project_id = url.split(":", 1)[1].strip()
            url = f"{KNOWN_SCRIPT_SOURCES['frida-codeshare']}{project_id}"
            detected_name = project_id

        # Validate URL
        if not url.startswith(("http://", "https://")):
            raise HTTPException(
                status_code=400,
                detail="URL must start with http:// or https://",
            )

        # Fetch script
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, follow_redirects=True)
                response.raise_for_status()

                content_type = response.headers.get("content-type", "")

                # Handle Frida CodeShare API response (JSON)
                if "codeshare.frida.re" in url and "application/json" in content_type:
                    try:
                        data = response.json()
                        script_content = data.get("source") or data.get("script")
                        if not script_content:
                            raise HTTPException(
                                status_code=400,
                                detail="Could not extract script from CodeShare response",
                            )
                        detected_name = detected_name or data.get("projectName")
                        if not description:
                            description = data.get("description")
                    except Exception:
                        raise HTTPException(
                            status_code=400,
                            detail="Invalid CodeShare response format",
                        )
                else:
                    # Raw JavaScript content
                    script_content = response.text

                if len(script_content) > 5 * 1024 * 1024:  # 5MB limit
                    raise HTTPException(
                        status_code=400,
                        detail="Script too large (max 5MB)",
                    )

                # Try to extract name from URL if not provided
                if not detected_name:
                    # Extract filename from URL path
                    path = url.split("?")[0]
                    if path.endswith(".js"):
                        detected_name = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                    else:
                        detected_name = path.rsplit("/", 1)[-1] or "imported"

        except httpx.TimeoutException:
            raise HTTPException(
                status_code=408,
                detail="Timeout fetching script from URL",
            )
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to fetch script: HTTP {e.response.status_code}",
            )
        except Exception as e:
            logger.error(f"Failed to fetch script from URL: {e}")
            raise HTTPException(
                status_code=500,
                detail="Failed to fetch script from URL",
            )

    # Validate script content
    if not script_content or not script_content.strip():
        raise HTTPException(
            status_code=400,
            detail="Script content is empty",
        )

    # Basic JavaScript validation
    if not _validate_frida_script(script_content):
        raise HTTPException(
            status_code=400,
            detail="Content does not appear to be a valid Frida script",
        )

    # Use provided name or detected name
    final_name = script_name or detected_name or "Imported Script"

    # Check for duplicate by content hash
    content_hash = hashlib.sha256(script_content.encode()).hexdigest()[:16]
    existing = await db.execute(
        select(FridaScript).where(
            FridaScript.script_name == final_name,
            FridaScript.is_builtin == False,  # noqa: E712
        )
    )
    if existing.scalar_one_or_none():
        # Append hash to make unique
        final_name = f"{final_name} ({content_hash[:8]})"

    # Parse platforms
    platform_list = [p.strip().lower() for p in platforms.split(",") if p.strip()]
    valid_platforms = ["android", "ios"]
    platform_list = [p for p in platform_list if p in valid_platforms]
    if not platform_list:
        platform_list = ["android", "ios"]

    # Create script
    script = FridaScript(
        script_name=final_name,
        description=description or f"Imported from {source_url or 'file upload'}",
        category=category,
        subcategory=subcategory,
        platforms=platform_list,
        script_content=script_content,
        is_builtin=False,
    )

    db.add(script)
    await db.commit()
    await db.refresh(script)

    logger.info(f"Imported Frida script: {final_name}")

    return FridaScriptResponse.model_validate(script)


def _validate_frida_script(content: str) -> bool:
    """
    Basic validation that content looks like a Frida script.

    Checks for common Frida API patterns.
    """
    # Check for common Frida patterns
    frida_patterns = [
        r"Java\.perform",
        r"Interceptor\.(attach|replace)",
        r"ObjC\.classes",
        r"Module\.(find|enumerate)",
        r"Memory\.(read|write|alloc)",
        r"send\s*\(",
        r"recv\s*\(",
        r"rpc\.exports",
        r"NativeFunction",
        r"NativeCallback",
        r"Process\.(arch|platform|id)",
        r"Thread\.(sleep|backtrace)",
        r"console\.log",  # Common in scripts
        r"function\s+\w+\s*\(",  # JavaScript function
    ]

    for pattern in frida_patterns:
        if re.search(pattern, content):
            return True

    # If no Frida patterns found, check if it's at least valid JavaScript-like
    # (has function definitions or common JS structures)
    js_patterns = [
        r"^\s*(var|let|const)\s+\w+",
        r"=>\s*\{",
        r"function\s*\(",
        r"\(\s*\)\s*\{",
    ]

    js_matches = sum(1 for p in js_patterns if re.search(p, content, re.MULTILINE))
    return js_matches >= 2


@router.get("/scripts/{script_id}", response_model=FridaScriptResponse)
async def get_script(script_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get a Frida script by ID."""
    result = await db.execute(
        select(FridaScript).where(FridaScript.script_id == script_id)
    )
    script = result.scalar_one_or_none()

    if not script:
        raise HTTPException(status_code=404, detail="Script not found")

    return FridaScriptResponse.model_validate(script)


@router.post("/scripts", response_model=FridaScriptResponse)
async def create_script(
    script_data: FridaScriptCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new Frida script."""
    script = FridaScript(**script_data.model_dump())
    script.is_builtin = False

    db.add(script)
    await db.commit()
    await db.refresh(script)

    return FridaScriptResponse.model_validate(script)


@router.put("/scripts/{script_id}", response_model=FridaScriptResponse)
async def update_script(
    script_id: UUID,
    script_data: FridaScriptCreate,
    db: AsyncSession = Depends(get_db),
):
    """Update a Frida script."""
    result = await db.execute(
        select(FridaScript).where(FridaScript.script_id == script_id)
    )
    script = result.scalar_one_or_none()

    if not script:
        raise HTTPException(status_code=404, detail="Script not found")

    if script.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot modify built-in scripts")

    for key, value in script_data.model_dump().items():
        setattr(script, key, value)

    await db.commit()
    await db.refresh(script)

    return FridaScriptResponse.model_validate(script)


@router.delete("/scripts/{script_id}")
async def delete_script(script_id: UUID, db: AsyncSession = Depends(get_db)):
    """Delete a Frida script."""
    result = await db.execute(
        select(FridaScript).where(FridaScript.script_id == script_id)
    )
    script = result.scalar_one_or_none()

    if not script:
        raise HTTPException(status_code=404, detail="Script not found")

    if script.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot delete built-in scripts")

    await db.delete(script)
    await db.commit()

    return {"message": "Script deleted successfully"}


@router.post("/inject")
async def inject_script(
    device_id: str,
    app_id: str,
    script_id: UUID | None = None,
    script_content: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Inject a Frida script into a running app."""
    # Verify device
    device_result = await db.execute(
        select(Device).where(Device.device_id == device_id)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    # Verify app
    app_result = await db.execute(
        select(MobileApp).where(MobileApp.app_id == app_id)
    )
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Get script content
    if script_id:
        script_result = await db.execute(
            select(FridaScript).where(FridaScript.script_id == script_id)
        )
        script = script_result.scalar_one_or_none()
        if not script:
            raise HTTPException(status_code=404, detail="Script not found")
        if not script.script_content:
            raise HTTPException(status_code=400, detail="Script has no content")
        script_content = script.script_content
    elif not script_content:
        raise HTTPException(
            status_code=400,
            detail="Either script_id or script_content is required",
        )

    # Inject script
    frida_service = FridaService()
    try:
        session_id = await frida_service.inject(
            device_id=device.device_id,
            package_name=app.package_name,
            script_content=script_content,
        )
        return {
            "message": "Script injected successfully",
            "session_id": session_id,
        }
    except Exception as e:
        logger.error(f"Failed to inject script: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions")
async def list_sessions():
    """List active Frida sessions."""
    frida_service = FridaService()
    sessions = await frida_service.list_sessions()
    return {"sessions": sessions}


@router.delete("/sessions/{session_id}")
async def detach_session(session_id: str):
    """Detach from a Frida session."""
    frida_service = FridaService()
    try:
        await frida_service.detach(session_id)
        return {"message": "Session detached"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
