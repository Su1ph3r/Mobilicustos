"""
iOS-specific API Router

Provides endpoints for iOS analysis capabilities and Corellium integration.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Any, Optional
from ..services.ios_toolchain import get_ios_toolchain, CorelliumClient

router = APIRouter(prefix="/ios", tags=["iOS"])


class CorelliumConfig(BaseModel):
    """Corellium configuration"""

    api_token: str
    endpoint: str = "https://app.corellium.com"


class CreateInstanceRequest(BaseModel):
    """Request to create a Corellium instance"""

    project_id: str
    flavor: str = "iphone12pro"
    os_version: str = "17.0"
    name: str = "mobilicustos-instance"


class InstallAppRequest(BaseModel):
    """Request to install app on Corellium instance"""

    instance_id: str
    ipa_path: str


class FridaScriptRequest(BaseModel):
    """Request to run Frida script on Corellium"""

    instance_id: str
    bundle_id: str
    script: str


@router.get("/capabilities")
async def get_capabilities() -> dict[str, Any]:
    """Get iOS analysis capabilities for this installation"""
    toolchain = get_ios_toolchain()
    return {
        "tier": toolchain.get_tier(),
        "capabilities": toolchain.get_capabilities(),
        "tier_descriptions": {
            1: "Basic: IPA extraction, plist parsing, string analysis",
            2: "Mac Host: Binary analysis (otool, nm), class-dump, device connectivity",
            3: "Corellium: Full virtual iOS with root, dynamic analysis, Frida",
        },
    }


@router.get("/devices")
async def list_ios_devices() -> list[dict[str, Any]]:
    """List connected iOS devices via libimobiledevice"""
    toolchain = get_ios_toolchain()
    if not toolchain.capabilities.get("libimobiledevice"):
        raise HTTPException(
            status_code=400,
            detail="libimobiledevice not available. Install it or use Corellium.",
        )
    return toolchain.list_connected_devices()


# =========================================================================
# Corellium Integration
# =========================================================================


@router.post("/corellium/configure")
async def configure_corellium(config: CorelliumConfig) -> dict[str, str]:
    """Configure Corellium API credentials"""
    toolchain = get_ios_toolchain()
    toolchain.init_corellium(config.api_token, config.endpoint)
    return {"status": "configured"}


@router.get("/corellium/projects")
async def list_corellium_projects() -> list[dict[str, Any]]:
    """List Corellium projects"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        return await client.list_projects()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/corellium/projects/{project_id}/instances")
async def list_corellium_instances(project_id: str) -> list[dict[str, Any]]:
    """List instances in a Corellium project"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        return await client.list_instances(project_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/corellium/instances")
async def create_corellium_instance(request: CreateInstanceRequest) -> dict[str, Any]:
    """Create a new Corellium iOS instance"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        return await client.create_instance(
            project_id=request.project_id,
            flavor=request.flavor,
            os_version=request.os_version,
            name=request.name,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/corellium/instances/{instance_id}")
async def get_corellium_instance(instance_id: str) -> dict[str, Any]:
    """Get Corellium instance details"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        return await client.get_instance(instance_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/corellium/instances/{instance_id}/start")
async def start_corellium_instance(instance_id: str) -> dict[str, Any]:
    """Start a Corellium instance"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        return await client.start_instance(instance_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/corellium/instances/{instance_id}/stop")
async def stop_corellium_instance(instance_id: str) -> dict[str, Any]:
    """Stop a Corellium instance"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        return await client.stop_instance(instance_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/corellium/instances/{instance_id}")
async def delete_corellium_instance(instance_id: str) -> dict[str, str]:
    """Delete a Corellium instance"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        success = await client.delete_instance(instance_id)
        if success:
            return {"status": "deleted"}
        raise HTTPException(status_code=500, detail="Failed to delete instance")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/corellium/instances/{instance_id}/apps")
async def install_app_on_corellium(
    instance_id: str, request: InstallAppRequest
) -> dict[str, Any]:
    """Install an app on a Corellium instance"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        return await client.install_app(instance_id, request.ipa_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/corellium/instances/{instance_id}/apps")
async def list_corellium_apps(instance_id: str) -> list[dict[str, Any]]:
    """List apps installed on a Corellium instance"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        return await client.list_apps(instance_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/corellium/instances/{instance_id}/console")
async def get_corellium_console(instance_id: str) -> dict[str, str]:
    """Get console log from a Corellium instance"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        log = await client.get_console_log(instance_id)
        return {"console_log": log}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/corellium/frida/run")
async def run_frida_on_corellium(request: FridaScriptRequest) -> dict[str, Any]:
    """Run a Frida script on a Corellium instance"""
    toolchain = get_ios_toolchain()
    client = toolchain.get_corellium_client()
    if not client:
        raise HTTPException(status_code=400, detail="Corellium not configured")
    try:
        return await client.run_frida_script(
            instance_id=request.instance_id,
            bundle_id=request.bundle_id,
            script=request.script,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
