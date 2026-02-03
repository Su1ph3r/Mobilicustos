"""Devices router."""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.models.database import Device
from api.models.schemas import DeviceCreate, DeviceResponse, PaginatedResponse
from api.services.device_manager import DeviceManager

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("", response_model=PaginatedResponse)
async def list_devices(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    platform: str | None = None,
    device_type: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all devices with pagination and filters."""
    query = select(Device)

    if platform:
        query = query.where(Device.platform == platform)
    if device_type:
        query = query.where(Device.device_type == device_type)
    if status:
        query = query.where(Device.status == status)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(Device.last_seen.desc().nullslast())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    devices = result.scalars().all()

    return PaginatedResponse(
        items=[DeviceResponse.model_validate(d) for d in devices],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/discover")
async def discover_devices(db: AsyncSession = Depends(get_db)):
    """Discover connected devices (ADB and iOS)."""
    device_manager = DeviceManager()

    # Discover Android devices via ADB
    android_devices = await device_manager.discover_android_devices()

    # Discover iOS devices via libimobiledevice (if on Mac)
    ios_devices = await device_manager.discover_ios_devices()

    # Upsert devices to database - batch query to avoid N+1
    all_devices = android_devices + ios_devices
    device_ids = [d["device_id"] for d in all_devices]

    # Batch fetch all existing devices
    existing_result = await db.execute(
        select(Device).where(Device.device_id.in_(device_ids))
    )
    existing_devices = {d.device_id: d for d in existing_result.scalars().all()}

    for device_data in all_devices:
        device_id = device_data["device_id"]
        if device_id in existing_devices:
            existing = existing_devices[device_id]
            for key, value in device_data.items():
                setattr(existing, key, value)
            existing.last_seen = datetime.utcnow()
        else:
            device = Device(**device_data)
            device.last_seen = datetime.utcnow()
            db.add(device)

    await db.commit()

    return {
        "discovered": len(all_devices),
        "android": len(android_devices),
        "ios": len(ios_devices),
        "devices": all_devices,
    }


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(device_id: str, db: AsyncSession = Depends(get_db)):
    """Get a device by ID."""
    result = await db.execute(select(Device).where(Device.device_id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    return DeviceResponse.model_validate(device)


@router.post("", response_model=DeviceResponse)
async def register_device(
    device_data: DeviceCreate,
    db: AsyncSession = Depends(get_db),
):
    """Manually register a device."""
    # Check if exists
    result = await db.execute(
        select(Device).where(Device.device_id == device_data.device_id)
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Device already exists")

    device = Device(**device_data.model_dump())
    device.status = "disconnected"
    device.last_seen = datetime.utcnow()

    db.add(device)
    await db.commit()
    await db.refresh(device)

    return DeviceResponse.model_validate(device)


@router.post("/{device_id}/connect")
async def connect_device(device_id: str, db: AsyncSession = Depends(get_db)):
    """Connect to a device."""
    result = await db.execute(select(Device).where(Device.device_id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device_manager = DeviceManager()
    try:
        await device_manager.connect(device)
        device.status = "connected"
        device.last_seen = datetime.utcnow()
        await db.commit()
        return {"message": "Connected successfully"}
    except Exception as e:
        device.status = "error"
        await db.commit()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{device_id}/frida/install")
async def install_frida_server(device_id: str, db: AsyncSession = Depends(get_db)):
    """Install Frida server on a device."""
    result = await db.execute(select(Device).where(Device.device_id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if device.status != "connected":
        raise HTTPException(status_code=400, detail="Device not connected")

    device_manager = DeviceManager()
    try:
        version = await device_manager.install_frida_server(device)
        device.frida_server_version = version
        device.frida_server_status = "installed"
        await db.commit()
        return {"message": f"Frida server {version} installed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{device_id}/frida/start")
async def start_frida_server(device_id: str, db: AsyncSession = Depends(get_db)):
    """Start Frida server on a device."""
    result = await db.execute(select(Device).where(Device.device_id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device_manager = DeviceManager()
    try:
        await device_manager.start_frida_server(device)
        device.frida_server_status = "running"
        await db.commit()
        return {"message": "Frida server started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{device_id}")
async def delete_device(device_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a device from the registry."""
    result = await db.execute(select(Device).where(Device.device_id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    await db.delete(device)
    await db.commit()

    return {"message": "Device deleted successfully"}
