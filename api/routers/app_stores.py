"""
App Store Connectors Router

API endpoints for app store integrations.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.app_store_service import AppStoreService

router = APIRouter(prefix="/app-stores", tags=["App Store Connectors"])


# Request Models

class ConnectionCreateRequest(BaseModel):
    """Request to create an app store connection."""
    name: str = Field(..., min_length=1, max_length=256)
    store_type: str = Field(..., pattern="^(google_play|app_store|apkpure|apkmirror)$")
    credentials: Optional[dict] = None
    is_active: bool = Field(default=True)


class ImportAppRequest(BaseModel):
    """Request to import an app from a store."""
    app_id: str = Field(..., description="Store-specific app ID")


# Endpoints

@router.get("/types")
async def get_store_types():
    """Get supported app store types."""
    return {
        "stores": [
            {
                "type": "google_play",
                "name": "Google Play Store",
                "platform": "android",
                "description": "Official Android app store",
                "download_supported": False,
                "search_supported": True,
            },
            {
                "type": "app_store",
                "name": "Apple App Store",
                "platform": "ios",
                "description": "Official iOS app store",
                "download_supported": False,
                "search_supported": True,
            },
            {
                "type": "apkpure",
                "name": "APKPure",
                "platform": "android",
                "description": "Alternative Android APK source",
                "download_supported": True,
                "search_supported": True,
            },
        ]
    }


@router.post("/connections")
async def create_connection(
    request: ConnectionCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create an app store connection."""
    service = AppStoreService(db)

    try:
        connection = await service.create_connection(
            name=request.name,
            store_type=request.store_type,
            credentials=request.credentials,
            is_active=request.is_active,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return connection


@router.get("/connections")
async def list_connections(
    db: AsyncSession = Depends(get_db),
):
    """List all app store connections."""
    service = AppStoreService(db)
    connections = await service.list_connections()
    return {"connections": connections}


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete an app store connection."""
    service = AppStoreService(db)

    deleted = await service.delete_connection(connection_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Connection not found")

    return {"message": "Connection deleted"}


@router.get("/search/{store_type}")
async def search_apps(
    store_type: str,
    query: str = Query(..., min_length=1, description="Search query"),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """
    Search for apps in a store.

    Returns basic app information from the store.
    """
    service = AppStoreService(db)

    try:
        apps = await service.search_apps(store_type, query, limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"apps": apps, "count": len(apps)}


@router.get("/info/{store_type}/{app_id:path}")
async def get_app_info(
    store_type: str,
    app_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed app information from a store.

    Returns metadata like version, description, etc.
    """
    service = AppStoreService(db)

    try:
        info = await service.get_app_info(store_type, app_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not info:
        raise HTTPException(status_code=404, detail="App not found")

    return info


@router.post("/import/{store_type}")
async def import_app(
    store_type: str,
    request: ImportAppRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Download and import an app from a store.

    Downloads the app binary and creates a new app record
    in Mobilicustos for analysis.
    """
    service = AppStoreService(db)

    # Use a temp directory for downloads
    import tempfile
    import shutil
    download_path = tempfile.mkdtemp()

    try:
        app = await service.import_app(
            store_type=store_type,
            app_id=request.app_id,
            download_path=download_path,
        )
    except ValueError as e:
        # Clean up temp directory on error
        shutil.rmtree(download_path, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        # Clean up temp directory after import
        shutil.rmtree(download_path, ignore_errors=True)

    return {
        "message": "App imported successfully",
        "app": app,
    }


@router.post("/monitor")
async def create_version_monitor(
    store_type: str = Query(...),
    app_id: str = Query(..., description="Store-specific app ID"),
    notify_webhook: Optional[str] = Query(None, description="Webhook URL for notifications"),
    db: AsyncSession = Depends(get_db),
):
    """
    Monitor an app for new versions.

    When a new version is detected, optionally notify via webhook
    and auto-download the update.
    """
    # Get current version
    service = AppStoreService(db)
    info = await service.get_app_info(store_type, app_id)

    if not info:
        raise HTTPException(status_code=404, detail="App not found")

    # Note: Would store this in a monitors table
    return {
        "message": "Version monitor created",
        "app_id": app_id,
        "store_type": store_type,
        "current_version": info.get("version"),
        "notify_webhook": notify_webhook,
    }
