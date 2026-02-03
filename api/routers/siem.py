"""
SIEM/SOAR Integration Router

API endpoints for SIEM integrations.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.siem_service import SIEMService

router = APIRouter(prefix="/siem", tags=["SIEM/SOAR Integration"])


# Request Models

class SIEMConfigCreateRequest(BaseModel):
    """Request to create a SIEM configuration."""
    name: str = Field(..., min_length=1, max_length=256)
    siem_type: str = Field(..., pattern="^(splunk|elastic|sentinel|qradar|sumo_logic)$")
    config: dict = Field(..., description="SIEM-specific configuration")
    is_active: bool = Field(default=True)
    auto_export: bool = Field(default=False, description="Auto-export new findings")
    export_severity: list[str] = Field(default=["critical", "high"])


class ExportFindingsRequest(BaseModel):
    """Request to export findings."""
    finding_ids: Optional[list[str]] = None
    severity: Optional[list[str]] = None
    app_id: Optional[str] = None


# Endpoints

@router.get("/types")
async def get_siem_types():
    """Get supported SIEM types with configuration fields."""
    return {
        "types": [
            {
                "type": "splunk",
                "name": "Splunk",
                "description": "Splunk Enterprise/Cloud via HEC",
                "config_fields": [
                    {"name": "hec_url", "label": "HEC URL", "type": "url", "required": True},
                    {"name": "token", "label": "HEC Token", "type": "password", "required": True},
                    {"name": "index", "label": "Index", "type": "text", "required": False, "default": "main"},
                    {"name": "source", "label": "Source", "type": "text", "required": False, "default": "mobilicustos"},
                ],
            },
            {
                "type": "elastic",
                "name": "Elastic SIEM",
                "description": "Elasticsearch/Elastic Security",
                "config_fields": [
                    {"name": "url", "label": "Elasticsearch URL", "type": "url", "required": True},
                    {"name": "api_key", "label": "API Key", "type": "password", "required": True},
                    {"name": "index_prefix", "label": "Index Prefix", "type": "text", "required": False, "default": "mobilicustos"},
                ],
            },
            {
                "type": "sentinel",
                "name": "Microsoft Sentinel",
                "description": "Azure Log Analytics / Microsoft Sentinel",
                "config_fields": [
                    {"name": "workspace_id", "label": "Workspace ID", "type": "text", "required": True},
                    {"name": "shared_key", "label": "Shared Key", "type": "password", "required": True},
                    {"name": "log_type", "label": "Log Type", "type": "text", "required": False, "default": "MobilicustosFindings"},
                ],
            },
        ]
    }


@router.post("/configs")
async def create_config(
    request: SIEMConfigCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new SIEM configuration."""
    service = SIEMService(db)

    try:
        config = await service.create_config(
            name=request.name,
            siem_type=request.siem_type,
            config=request.config,
            is_active=request.is_active,
            auto_export=request.auto_export,
            export_severity=request.export_severity,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return config


@router.get("/configs")
async def list_configs(
    db: AsyncSession = Depends(get_db),
):
    """List all SIEM configurations."""
    service = SIEMService(db)
    configs = await service.list_configs()
    return {"configs": configs}


@router.get("/configs/{config_id}")
async def get_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a SIEM configuration."""
    service = SIEMService(db)
    config = await service.get_config(config_id)

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    # Mask sensitive config
    config.pop("config", None)
    return config


@router.delete("/configs/{config_id}")
async def delete_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a SIEM configuration."""
    service = SIEMService(db)

    deleted = await service.delete_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Configuration not found")

    return {"message": "Configuration deleted"}


@router.post("/configs/{config_id}/test")
async def test_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Test a SIEM configuration."""
    service = SIEMService(db)
    config = await service.get_config(config_id)

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    client = service._get_client(config["siem_type"], config["config"])
    result = await client.test_connection()

    return {
        "config_id": config_id,
        "success": result.get("success", False),
        "message": "Connected" if result.get("success") else result.get("error"),
    }


@router.post("/configs/{config_id}/export/finding/{finding_id}")
async def export_finding(
    config_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Export a single finding to SIEM."""
    service = SIEMService(db)

    try:
        result = await service.export_finding(config_id, finding_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


@router.post("/configs/{config_id}/export/batch")
async def export_findings_batch(
    config_id: str,
    request: ExportFindingsRequest,
    db: AsyncSession = Depends(get_db),
):
    """Export multiple findings to SIEM."""
    service = SIEMService(db)

    try:
        result = await service.export_findings_batch(
            config_id=config_id,
            finding_ids=request.finding_ids,
            severity=request.severity,
            app_id=request.app_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


@router.post("/configs/{config_id}/export/scan/{scan_id}")
async def export_scan_event(
    config_id: str,
    scan_id: str,
    event_type: str = Query(..., pattern="^(started|completed|failed)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export a scan event to SIEM."""
    service = SIEMService(db)

    try:
        result = await service.export_scan_event(config_id, scan_id, event_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result
