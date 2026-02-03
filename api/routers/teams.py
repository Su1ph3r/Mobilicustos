"""
Teams and Workspaces Router

API endpoints for managing teams, workspaces, and permissions.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.team_service import TeamService

router = APIRouter(prefix="/workspaces", tags=["Teams & Workspaces"])


# Request/Response Models

class WorkspaceCreateRequest(BaseModel):
    """Request to create a workspace."""
    name: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = Field(None, max_length=1000)


class WorkspaceUpdateRequest(BaseModel):
    """Request to update a workspace."""
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = Field(None, max_length=1000)


class MemberAddRequest(BaseModel):
    """Request to add a team member."""
    user_id: str
    user_name: str
    user_email: str
    role: str = Field(default="viewer", pattern="^(owner|admin|analyst|developer|viewer)$")


class MemberRoleUpdateRequest(BaseModel):
    """Request to update a member's role."""
    role: str = Field(..., pattern="^(owner|admin|analyst|developer|viewer)$")


# Mock current user (in production, get from auth)
def get_current_user():
    return {"id": "system", "name": "System User"}


# ==================== Workspaces ====================

@router.post("")
async def create_workspace(
    request: WorkspaceCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new workspace."""
    user = get_current_user()
    service = TeamService(db)

    workspace = await service.create_workspace(
        name=request.name,
        description=request.description,
        owner_id=user["id"],
        owner_name=user["name"],
    )

    return workspace


@router.get("")
async def list_workspaces(
    my_workspaces: bool = Query(False, description="Only show workspaces I'm a member of"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List all workspaces."""
    user = get_current_user()
    service = TeamService(db)

    return await service.list_workspaces(
        user_id=user["id"] if my_workspaces else None,
        page=page,
        page_size=page_size,
    )


@router.get("/roles")
async def get_available_roles():
    """Get available roles and their descriptions."""
    return {
        "roles": [
            {
                "id": role_id,
                "name": role_id.title(),
                "level": info["level"],
                "description": info["description"],
            }
            for role_id, info in TeamService.ROLES.items()
        ]
    }


@router.get("/{workspace_id}")
async def get_workspace(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get workspace details."""
    service = TeamService(db)
    workspace = await service.get_workspace(workspace_id)

    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")

    return workspace


@router.put("/{workspace_id}")
async def update_workspace(
    workspace_id: str,
    request: WorkspaceUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update workspace details."""
    service = TeamService(db)

    workspace = await service.update_workspace(
        workspace_id=workspace_id,
        name=request.name,
        description=request.description,
    )

    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")

    return workspace


@router.delete("/{workspace_id}")
async def delete_workspace(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a workspace."""
    service = TeamService(db)

    deleted = await service.delete_workspace(workspace_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Workspace not found")

    return {"message": "Workspace deleted"}


@router.get("/{workspace_id}/stats")
async def get_workspace_stats(
    workspace_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get workspace statistics."""
    service = TeamService(db)
    return await service.get_workspace_stats(workspace_id)


# ==================== Team Members ====================

@router.post("/{workspace_id}/members")
async def add_team_member(
    workspace_id: str,
    request: MemberAddRequest,
    db: AsyncSession = Depends(get_db),
):
    """Add a member to the workspace team."""
    user = get_current_user()
    service = TeamService(db)

    try:
        member = await service.add_team_member(
            workspace_id=workspace_id,
            user_id=request.user_id,
            user_name=request.user_name,
            user_email=request.user_email,
            role=request.role,
            invited_by_id=user["id"],
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return member


@router.get("/{workspace_id}/members")
async def get_team_members(
    workspace_id: str,
    role: Optional[str] = Query(None, description="Filter by role"),
    db: AsyncSession = Depends(get_db),
):
    """Get all team members for a workspace."""
    service = TeamService(db)
    members = await service.get_team_members(workspace_id, role)
    return {"members": members}


@router.put("/{workspace_id}/members/{user_id}")
async def update_member_role(
    workspace_id: str,
    user_id: str,
    request: MemberRoleUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update a team member's role."""
    user = get_current_user()
    service = TeamService(db)

    try:
        member = await service.update_member_role(
            workspace_id=workspace_id,
            user_id=user_id,
            new_role=request.role,
            updated_by_id=user["id"],
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not member:
        raise HTTPException(status_code=404, detail="Member not found")

    return member


@router.delete("/{workspace_id}/members/{user_id}")
async def remove_team_member(
    workspace_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Remove a member from the workspace team."""
    user = get_current_user()
    service = TeamService(db)

    try:
        removed = await service.remove_team_member(
            workspace_id=workspace_id,
            user_id=user_id,
            removed_by_id=user["id"],
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not removed:
        raise HTTPException(status_code=404, detail="Member not found")

    return {"message": "Member removed"}


# ==================== Activity Log ====================

@router.get("/{workspace_id}/activity")
async def get_activity_log(
    workspace_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Get activity log for a workspace."""
    service = TeamService(db)
    activities = await service.get_activity_log(workspace_id, limit)
    return {"activities": activities}
