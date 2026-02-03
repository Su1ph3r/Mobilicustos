"""
Corellium Integration Router

API endpoints for Corellium virtual device management.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.corellium_service import CorelliumService

router = APIRouter(prefix="/corellium", tags=["Corellium"])


# Request Models

class CreateConnectionRequest(BaseModel):
    """Request to create a Corellium connection."""
    name: str = Field(..., min_length=1, max_length=256)
    api_url: str = Field(..., description="Corellium API URL")
    api_token: str = Field(..., min_length=1)


class CreateDeviceRequest(BaseModel):
    """Request to create a virtual device."""
    project_id: str
    flavor: str = Field(..., description="Device model (e.g., 'iphone12pro', 'pixel4')")
    os_version: str = Field(..., description="OS version (e.g., '15.0', '12')")
    name: str = Field(..., min_length=1, max_length=256)


class RunSecurityTestRequest(BaseModel):
    """Request to run security test."""
    app_id: str
    test_type: str = Field(
        default="all",
        pattern="^(ssl_pinning|root_detection|all)$"
    )


class RunFridaScriptRequest(BaseModel):
    """Request to run Frida script."""
    target: str = Field(..., description="Target package/bundle ID")
    script: str = Field(..., description="Frida script content")


# Endpoints - Connections

@router.post("/connections")
async def create_connection(
    request: CreateConnectionRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new Corellium connection."""
    service = CorelliumService(db)

    try:
        connection = await service.create_connection(
            name=request.name,
            api_url=request.api_url,
            api_token=request.api_token,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return connection


@router.get("/connections")
async def list_connections(
    db: AsyncSession = Depends(get_db),
):
    """List all Corellium connections."""
    service = CorelliumService(db)
    connections = await service.list_connections()
    return {"connections": connections, "count": len(connections)}


@router.get("/connections/{connection_id}")
async def get_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get Corellium connection details."""
    service = CorelliumService(db)
    connection = await service.get_connection(connection_id)

    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")

    # Don't expose API token
    connection.pop("api_token", None)
    return connection


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a Corellium connection."""
    service = CorelliumService(db)

    deleted = await service.delete_connection(connection_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Connection not found")

    return {"message": "Connection deleted"}


# Endpoints - Projects

@router.get("/connections/{connection_id}/projects")
async def get_projects(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get all projects in Corellium."""
    service = CorelliumService(db)

    try:
        projects = await service.get_projects(connection_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {"projects": projects, "count": len(projects)}


@router.get("/connections/{connection_id}/supported-devices")
async def get_supported_devices(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get supported device models."""
    service = CorelliumService(db)

    try:
        devices = await service.get_supported_devices(connection_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {"devices": devices, "count": len(devices)}


# Endpoints - Virtual Devices

@router.post("/connections/{connection_id}/devices")
async def create_virtual_device(
    connection_id: str,
    request: CreateDeviceRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new virtual device."""
    service = CorelliumService(db)

    try:
        device = await service.create_virtual_device(
            connection_id=connection_id,
            project_id=request.project_id,
            flavor=request.flavor,
            os_version=request.os_version,
            name=request.name,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return device


@router.get("/devices")
async def list_virtual_devices(
    connection_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List virtual devices."""
    service = CorelliumService(db)
    devices = await service.list_virtual_devices(connection_id=connection_id)
    return {"devices": devices, "count": len(devices)}


@router.get("/connections/{connection_id}/devices/{instance_id}")
async def get_device_status(
    connection_id: str,
    instance_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get virtual device status."""
    service = CorelliumService(db)

    try:
        status = await service.get_device_status(connection_id, instance_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return status


@router.post("/connections/{connection_id}/devices/{instance_id}/start")
async def start_virtual_device(
    connection_id: str,
    instance_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Start a virtual device."""
    service = CorelliumService(db)

    try:
        result = await service.start_virtual_device(connection_id, instance_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"message": "Device starting", "result": result}


@router.post("/connections/{connection_id}/devices/{instance_id}/stop")
async def stop_virtual_device(
    connection_id: str,
    instance_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Stop a virtual device."""
    service = CorelliumService(db)

    try:
        result = await service.stop_virtual_device(connection_id, instance_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"message": "Device stopping", "result": result}


@router.delete("/connections/{connection_id}/devices/{instance_id}")
async def delete_virtual_device(
    connection_id: str,
    instance_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a virtual device."""
    service = CorelliumService(db)

    try:
        deleted = await service.delete_virtual_device(connection_id, instance_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not deleted:
        raise HTTPException(status_code=404, detail="Device not found")

    return {"message": "Device deleted"}


# Endpoints - App Management

@router.post("/connections/{connection_id}/devices/{instance_id}/apps")
async def install_app(
    connection_id: str,
    instance_id: str,
    app_id: str = Query(..., description="Mobilicustos app ID"),
    db: AsyncSession = Depends(get_db),
):
    """Install an app on a virtual device."""
    service = CorelliumService(db)

    # Get app file path
    query = "SELECT file_path FROM mobile_apps WHERE app_id = :app_id"
    result = await db.execute(query, {"app_id": app_id})
    row = result.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="App not found")

    try:
        result = await service.install_app_on_device(
            connection_id=connection_id,
            instance_id=instance_id,
            app_path=row.file_path,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"message": "App installed", "result": result}


# Endpoints - Network Capture

@router.post("/connections/{connection_id}/devices/{instance_id}/network/start")
async def start_network_capture(
    connection_id: str,
    instance_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Start network capture on device."""
    service = CorelliumService(db)

    try:
        result = await service.start_network_capture(connection_id, instance_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"message": "Network capture started", "result": result}


@router.post("/connections/{connection_id}/devices/{instance_id}/network/stop")
async def stop_network_capture(
    connection_id: str,
    instance_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Stop network capture and get PCAP."""
    service = CorelliumService(db)

    import tempfile
    fd, output_path = tempfile.mkstemp(suffix=".pcap")
    import os
    os.close(fd)  # Close the file descriptor, we just need the path

    try:
        filepath = await service.stop_network_capture(
            connection_id=connection_id,
            instance_id=instance_id,
            output_path=output_path,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"message": "Network capture stopped", "file_path": filepath}


# Endpoints - Frida

@router.post("/connections/{connection_id}/devices/{instance_id}/frida")
async def run_frida_script(
    connection_id: str,
    instance_id: str,
    request: RunFridaScriptRequest,
    db: AsyncSession = Depends(get_db),
):
    """Run Frida script on device."""
    service = CorelliumService(db)

    try:
        result = await service.run_frida_script(
            connection_id=connection_id,
            instance_id=instance_id,
            target=request.target,
            script=request.script,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


# Endpoints - Security Testing

@router.post("/connections/{connection_id}/devices/{instance_id}/security-test")
async def run_security_test(
    connection_id: str,
    instance_id: str,
    request: RunSecurityTestRequest,
    db: AsyncSession = Depends(get_db),
):
    """Run automated security test on app."""
    service = CorelliumService(db)

    try:
        result = await service.run_security_test(
            connection_id=connection_id,
            instance_id=instance_id,
            app_id=request.app_id,
            test_type=request.test_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


# Endpoints - Snapshots

@router.post("/connections/{connection_id}/devices/{instance_id}/snapshots")
async def take_snapshot(
    connection_id: str,
    instance_id: str,
    name: str = Query(..., min_length=1, max_length=256),
    db: AsyncSession = Depends(get_db),
):
    """Take a device snapshot."""
    service = CorelliumService(db)

    try:
        result = await service.take_snapshot(
            connection_id=connection_id,
            instance_id=instance_id,
            name=name,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"message": "Snapshot created", "result": result}
