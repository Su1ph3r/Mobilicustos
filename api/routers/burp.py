"""
Burp Suite Pro Integration Router

API endpoints for Burp Suite Professional integration:
- Connection management
- Scan management
- Issue import
- Proxy history
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.burp_service import BurpService

router = APIRouter(prefix="/burp", tags=["Burp Suite Integration"])


# Request/Response Models

class ConnectionCreateRequest(BaseModel):
    """Request to create a Burp connection."""
    name: str = Field(..., min_length=1, max_length=256, description="Name for this connection")
    api_url: str = Field(..., description="Burp REST API URL (e.g., http://localhost:1337)")
    api_key: str = Field(..., description="Burp API key")
    is_active: bool = Field(default=True, description="Whether the connection is active")


class ConnectionResponse(BaseModel):
    """Response for a Burp connection."""
    connection_id: str
    name: str
    api_url: str
    is_active: bool
    burp_version: Optional[str] = None
    status: Optional[str] = None
    last_connected_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class ScanStartRequest(BaseModel):
    """Request to start a Burp scan."""
    target_urls: list[str] = Field(..., min_items=1, description="URLs to scan")
    app_id: Optional[str] = Field(None, description="Associated Mobilicustos app ID")
    scan_config: Optional[str] = Field(None, description="Named scan configuration")
    resource_pool: Optional[str] = Field(None, description="Named resource pool")


class ScanResponse(BaseModel):
    """Response for a Burp scan."""
    task_id: str
    burp_task_id: Optional[str] = None
    status: str
    target_urls: Optional[list[str]] = None
    issues_count: Optional[int] = None
    requests_made: Optional[int] = None
    percent_complete: Optional[int] = None


class ImportResponse(BaseModel):
    """Response for issue import."""
    task_id: str
    imported: int
    skipped: int
    total: int


# Endpoints

@router.post("/connections", response_model=ConnectionResponse)
async def create_connection(
    request: ConnectionCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new Burp Suite connection.

    The connection will be tested before being saved.
    Ensure Burp Suite Pro is running with the REST API enabled.

    To enable Burp REST API:
    1. Open Burp Suite Pro
    2. Go to User options > Misc
    3. Enable "Allow APIs to access private data"
    4. Note the API key
    """
    service = BurpService(db)

    try:
        connection = await service.create_connection(
            name=request.name,
            api_url=request.api_url.rstrip('/'),
            api_key=request.api_key,
            is_active=request.is_active,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return connection


@router.get("/connections", response_model=dict)
async def list_connections(
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List all Burp Suite connections."""
    service = BurpService(db)

    return await service.list_connections(
        is_active=is_active,
        page=page,
        page_size=page_size,
    )


@router.get("/connections/{connection_id}", response_model=ConnectionResponse)
async def get_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a Burp connection by ID."""
    service = BurpService(db)

    connection = await service.get_connection(connection_id)
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")

    # Don't expose the API key
    connection.pop("api_key", None)

    return connection


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a Burp connection."""
    service = BurpService(db)

    deleted = await service.delete_connection(connection_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Connection not found")

    return {"message": "Connection deleted successfully"}


@router.post("/connections/{connection_id}/test")
async def test_connection(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Test a Burp Suite connection."""
    service = BurpService(db)

    connection = await service.get_connection(connection_id)
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")

    result = await service._test_connection(
        connection["api_url"],
        connection["api_key"],
    )

    if result["success"]:
        # Update last_connected_at
        await db.execute(
            """
            UPDATE burp_connections
            SET last_connected_at = :now
            WHERE connection_id = :connection_id
            """,
            {"connection_id": connection_id, "now": datetime.utcnow()}
        )
        await db.commit()

    return {
        "connection_id": connection_id,
        "success": result["success"],
        "message": "Connected" if result["success"] else result.get("error"),
        "burp_version": result.get("version"),
    }


@router.post("/connections/{connection_id}/scans", response_model=ScanResponse)
async def start_scan(
    connection_id: str,
    request: ScanStartRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Start a new Burp scan.

    The scan will run in Burp Suite and can be monitored
    through this API. Issues can be imported once complete.
    """
    service = BurpService(db)

    try:
        scan = await service.start_scan(
            connection_id=connection_id,
            target_urls=request.target_urls,
            app_id=request.app_id,
            scan_config=request.scan_config,
            resource_pool=request.resource_pool,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return scan


@router.get("/scans/{task_id}", response_model=ScanResponse)
async def get_scan_status(
    task_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get the status of a Burp scan."""
    service = BurpService(db)

    try:
        status = await service.get_scan_status(task_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return status


@router.post("/scans/{task_id}/stop")
async def stop_scan(
    task_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Stop a running Burp scan."""
    service = BurpService(db)

    try:
        result = await service.stop_scan(task_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


@router.post("/scans/{task_id}/import", response_model=ImportResponse)
async def import_issues(
    task_id: str,
    app_id: Optional[str] = Query(None, description="App ID to associate findings with"),
    db: AsyncSession = Depends(get_db),
):
    """
    Import issues from a Burp scan into Mobilicustos findings.

    If an app_id is provided, findings will be created and linked
    to the app. Otherwise, issues are stored in the Burp issues table
    for later review.
    """
    service = BurpService(db)

    try:
        result = await service.import_issues(task_id, app_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


@router.get("/connections/{connection_id}/proxy-history")
async def get_proxy_history(
    connection_id: str,
    limit: int = Query(100, ge=1, le=1000, description="Max items to return"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get proxy history from Burp Suite.

    Returns recent HTTP requests captured by the Burp proxy.
    """
    service = BurpService(db)

    try:
        history = await service.get_proxy_history(connection_id, limit)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"items": history, "count": len(history)}


@router.post("/connections/{connection_id}/proxy-history/import")
async def import_proxy_history(
    connection_id: str,
    app_id: str = Query(..., description="App ID to associate requests with"),
    item_ids: Optional[list[int]] = Query(None, description="Specific items to import"),
    db: AsyncSession = Depends(get_db),
):
    """
    Import proxy history items into Mobilicustos.

    Imports HTTP traffic data for network analysis.
    """
    service = BurpService(db)

    try:
        result = await service.import_proxy_history(
            connection_id=connection_id,
            app_id=app_id,
            item_ids=item_ids,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


@router.get("/connections/{connection_id}/configurations")
async def get_scan_configurations(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Get available scan configurations from Burp.

    Returns named scan configurations that can be used
    when starting scans.
    """
    service = BurpService(db)

    try:
        configs = await service.get_scan_configurations(connection_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"configurations": configs}


@router.get("/issues")
async def list_burp_issues(
    task_id: Optional[str] = Query(None, description="Filter by scan task"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """List imported Burp issues."""
    conditions = []
    params = {}

    if task_id:
        conditions.append("task_id = :task_id")
        params["task_id"] = task_id

    if severity:
        conditions.append("severity = :severity")
        params["severity"] = severity

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # Count
    count_query = f"SELECT COUNT(*) FROM burp_issues WHERE {where_clause}"
    count_result = await db.execute(count_query, params)
    total = count_result.scalar()

    # Data
    offset = (page - 1) * page_size
    data_query = f"""
        SELECT issue_id, task_id, finding_id, name, severity,
               confidence, url, path, issue_type, created_at
        FROM burp_issues
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
    """
    params["limit"] = page_size
    params["offset"] = offset

    result = await db.execute(data_query, params)
    issues = [dict(row._mapping) for row in result.fetchall()]

    return {
        "items": issues,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/issues/{issue_id}")
async def get_burp_issue(
    issue_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get details of a specific Burp issue."""
    query = "SELECT * FROM burp_issues WHERE issue_id = :issue_id"
    result = await db.execute(query, {"issue_id": issue_id})
    issue = result.fetchone()

    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")

    return dict(issue._mapping)
