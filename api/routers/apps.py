"""Mobile apps router."""

import hashlib
import logging
from pathlib import Path
from uuid import uuid4

import aiofiles
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import get_settings
from api.database import get_db
from api.models.database import Finding, MobileApp, Scan
from api.models.schemas import MobileAppResponse, PaginatedResponse
from api.services.framework_detector import detect_framework
from api.services.app_parser import parse_android_app, parse_ios_app

router = APIRouter()
logger = logging.getLogger(__name__)
settings = get_settings()


@router.get("", response_model=PaginatedResponse)
async def list_apps(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    platform: str | None = None,
    framework: str | None = None,
    status: str | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all mobile apps with pagination and filters."""
    query = select(MobileApp)

    if platform:
        query = query.where(MobileApp.platform == platform)
    if framework:
        query = query.where(MobileApp.framework == framework)
    if status:
        query = query.where(MobileApp.status == status)
    if search:
        query = query.where(
            MobileApp.package_name.ilike(f"%{search}%")
            | MobileApp.app_name.ilike(f"%{search}%")
        )

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(MobileApp.upload_date.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    apps = result.scalars().all()

    return PaginatedResponse(
        items=[MobileAppResponse.model_validate(app) for app in apps],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{app_id}", response_model=MobileAppResponse)
async def get_app(app_id: str, db: AsyncSession = Depends(get_db)):
    """Get a mobile app by ID."""
    result = await db.execute(select(MobileApp).where(MobileApp.app_id == app_id))
    app = result.scalar_one_or_none()

    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    return MobileAppResponse.model_validate(app)


@router.post("", response_model=MobileAppResponse)
async def upload_app(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload a mobile app (APK or IPA)."""
    # Validate file type
    filename = file.filename or ""
    if not filename.endswith((".apk", ".ipa")):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only APK and IPA files are supported.",
        )

    platform = "android" if filename.endswith(".apk") else "ios"

    # Check file size
    max_size = (
        settings.max_apk_size_mb if platform == "android" else settings.max_ipa_size_mb
    )
    content = await file.read()
    if len(content) > max_size * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {max_size}MB.",
        )

    # Calculate hash
    file_hash = hashlib.sha256(content).hexdigest()

    # Check if already exists
    existing = await db.execute(
        select(MobileApp).where(MobileApp.file_hash_sha256 == file_hash)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail="App with this hash already exists.",
        )

    # Save file
    app_id = str(uuid4())
    file_path = settings.uploads_path / f"{app_id}{Path(filename).suffix}"
    file_path.parent.mkdir(parents=True, exist_ok=True)

    async with aiofiles.open(file_path, "wb") as f:
        await f.write(content)

    # Parse app metadata
    try:
        if platform == "android":
            metadata = await parse_android_app(file_path)
        else:
            metadata = await parse_ios_app(file_path)
    except Exception as e:
        logger.error(f"Failed to parse app: {e}")
        metadata = {}

    # Detect framework
    framework_info = await detect_framework(file_path, platform)

    # Create app record
    app = MobileApp(
        app_id=app_id,
        package_name=metadata.get("package_name", "unknown"),
        app_name=metadata.get("app_name"),
        version_name=metadata.get("version_name"),
        version_code=metadata.get("version_code"),
        platform=platform,
        file_path=str(file_path),
        file_hash_sha256=file_hash,
        file_size_bytes=len(content),
        framework=framework_info.get("framework"),
        framework_version=framework_info.get("version"),
        framework_details=framework_info.get("details", {}),
        min_sdk_version=metadata.get("min_sdk_version"),
        target_sdk_version=metadata.get("target_sdk_version"),
        min_ios_version=metadata.get("min_ios_version"),
        signing_info=metadata.get("signing_info", {}),
        status="pending",
    )

    db.add(app)
    await db.commit()
    await db.refresh(app)

    return MobileAppResponse.model_validate(app)


@router.delete("/{app_id}")
async def delete_app(app_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a mobile app and all associated data."""
    result = await db.execute(select(MobileApp).where(MobileApp.app_id == app_id))
    app = result.scalar_one_or_none()

    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Delete file
    if app.file_path:
        file_path = Path(app.file_path)
        if file_path.exists():
            file_path.unlink()

    await db.delete(app)
    await db.commit()

    return {"message": "App deleted successfully"}


@router.get("/{app_id}/stats")
async def get_app_stats(app_id: str, db: AsyncSession = Depends(get_db)):
    """Get statistics for a mobile app."""
    # Verify app exists
    result = await db.execute(select(MobileApp).where(MobileApp.app_id == app_id))
    app = result.scalar_one_or_none()

    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    # Get scan count
    scan_count = (
        await db.execute(
            select(func.count()).where(Scan.app_id == app_id)
        )
    ).scalar() or 0

    # Get findings by severity
    findings_query = (
        select(Finding.severity, func.count())
        .where(Finding.app_id == app_id)
        .group_by(Finding.severity)
    )
    findings_result = await db.execute(findings_query)
    findings_by_severity = dict(findings_result.all())

    # Get findings by category
    category_query = (
        select(Finding.category, func.count())
        .where(Finding.app_id == app_id)
        .where(Finding.category.isnot(None))
        .group_by(Finding.category)
    )
    category_result = await db.execute(category_query)
    findings_by_category = dict(category_result.all())

    return {
        "app_id": app_id,
        "scan_count": scan_count,
        "total_findings": sum(findings_by_severity.values()),
        "findings_by_severity": findings_by_severity,
        "findings_by_category": findings_by_category,
    }
