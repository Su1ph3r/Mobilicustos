"""
Finding Workflow Router

API endpoints for finding workflows including comments, assignments, and history.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.finding_workflow_service import FindingWorkflowService

router = APIRouter(prefix="/findings-workflow", tags=["Finding Workflow"])


# Request/Response Models

class CommentCreateRequest(BaseModel):
    """Request to add a comment."""
    content: str = Field(..., min_length=1, max_length=10000)
    is_internal: bool = Field(default=False, description="Internal notes not visible to external users")


class CommentUpdateRequest(BaseModel):
    """Request to update a comment."""
    content: str = Field(..., min_length=1, max_length=10000)


class AssignmentRequest(BaseModel):
    """Request to assign a finding."""
    assignee_id: str
    assignee_name: str
    notes: Optional[str] = None


class StatusChangeRequest(BaseModel):
    """Request to change finding status."""
    new_status: str = Field(..., description="New status value")
    reason: Optional[str] = Field(None, description="Reason for status change")


class BulkAssignRequest(BaseModel):
    """Request for bulk assignment."""
    finding_ids: list[str] = Field(..., min_items=1, max_items=100)
    assignee_id: str
    assignee_name: str


class BulkStatusRequest(BaseModel):
    """Request for bulk status change."""
    finding_ids: list[str] = Field(..., min_items=1, max_items=100)
    new_status: str
    reason: Optional[str] = None


# Mock user context (in production, get from auth)
def get_current_user():
    return {"id": "system", "name": "System User"}


# ==================== Comments ====================

@router.post("/{finding_id}/comments")
async def add_comment(
    finding_id: str,
    request: CommentCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Add a comment to a finding."""
    user = get_current_user()
    service = FindingWorkflowService(db)

    comment = await service.add_comment(
        finding_id=finding_id,
        content=request.content,
        author_id=user["id"],
        author_name=user["name"],
        is_internal=request.is_internal,
    )

    return comment


@router.get("/{finding_id}/comments")
async def get_comments(
    finding_id: str,
    include_internal: bool = Query(True, description="Include internal comments"),
    db: AsyncSession = Depends(get_db),
):
    """Get all comments for a finding."""
    service = FindingWorkflowService(db)
    comments = await service.get_comments(finding_id, include_internal)
    return {"comments": comments}


@router.put("/comments/{comment_id}")
async def update_comment(
    comment_id: str,
    request: CommentUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update a comment."""
    service = FindingWorkflowService(db)
    comment = await service.update_comment(comment_id, request.content)

    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    return comment


@router.delete("/comments/{comment_id}")
async def delete_comment(
    comment_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a comment."""
    service = FindingWorkflowService(db)
    deleted = await service.delete_comment(comment_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Comment not found")

    return {"message": "Comment deleted"}


# ==================== Assignments ====================

@router.post("/{finding_id}/assign")
async def assign_finding(
    finding_id: str,
    request: AssignmentRequest,
    db: AsyncSession = Depends(get_db),
):
    """Assign a finding to a user."""
    user = get_current_user()
    service = FindingWorkflowService(db)

    assignment = await service.assign_finding(
        finding_id=finding_id,
        assignee_id=request.assignee_id,
        assignee_name=request.assignee_name,
        assigned_by_id=user["id"],
        assigned_by_name=user["name"],
        notes=request.notes,
    )

    return assignment


@router.post("/{finding_id}/unassign")
async def unassign_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Remove assignment from a finding."""
    user = get_current_user()
    service = FindingWorkflowService(db)

    unassigned = await service.unassign_finding(
        finding_id=finding_id,
        unassigned_by_id=user["id"],
        unassigned_by_name=user["name"],
    )

    if not unassigned:
        raise HTTPException(status_code=404, detail="No active assignment found")

    return {"message": "Finding unassigned"}


@router.get("/{finding_id}/assignments")
async def get_finding_assignments(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get assignment history for a finding."""
    service = FindingWorkflowService(db)
    assignments = await service.get_assignments(finding_id=finding_id)
    return {"assignments": assignments}


@router.get("/assignments/my")
async def get_my_assignments(
    status: Optional[str] = Query(None, description="Filter by status"),
    db: AsyncSession = Depends(get_db),
):
    """Get findings assigned to current user."""
    user = get_current_user()
    service = FindingWorkflowService(db)

    assignments = await service.get_assignments(
        assignee_id=user["id"],
        status=status,
    )

    return {"assignments": assignments}


# ==================== Status ====================

@router.post("/{finding_id}/status")
async def change_status(
    finding_id: str,
    request: StatusChangeRequest,
    db: AsyncSession = Depends(get_db),
):
    """Change the status of a finding."""
    user = get_current_user()
    service = FindingWorkflowService(db)

    try:
        result = await service.change_status(
            finding_id=finding_id,
            new_status=request.new_status,
            changed_by_id=user["id"],
            changed_by_name=user["name"],
            reason=request.reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


@router.get("/{finding_id}/status/transitions")
async def get_allowed_transitions(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get allowed status transitions for a finding."""
    # Get current status
    result = await db.execute(
        "SELECT status FROM findings WHERE finding_id = :finding_id",
        {"finding_id": finding_id}
    )
    row = result.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    service = FindingWorkflowService(db)
    transitions = service.get_allowed_transitions(row[0])

    return {
        "current_status": row[0],
        "allowed_transitions": transitions,
    }


@router.get("/workflow/statuses")
async def get_workflow_statuses():
    """Get all status values and their allowed transitions."""
    return {
        "statuses": [
            {"value": "new", "label": "New", "color": "blue"},
            {"value": "confirmed", "label": "Confirmed", "color": "orange"},
            {"value": "in_progress", "label": "In Progress", "color": "purple"},
            {"value": "fixed", "label": "Fixed", "color": "teal"},
            {"value": "verified", "label": "Verified", "color": "green"},
            {"value": "closed", "label": "Closed", "color": "gray"},
            {"value": "false_positive", "label": "False Positive", "color": "yellow"},
            {"value": "ignored", "label": "Ignored", "color": "gray"},
            {"value": "wont_fix", "label": "Won't Fix", "color": "red"},
        ],
        "workflow": FindingWorkflowService.STATUS_WORKFLOW,
    }


# ==================== History ====================

@router.get("/{finding_id}/history")
async def get_history(
    finding_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Get activity history for a finding."""
    service = FindingWorkflowService(db)
    history = await service.get_history(finding_id, limit)
    return {"history": history}


# ==================== Bulk Operations ====================

@router.post("/bulk/assign")
async def bulk_assign(
    request: BulkAssignRequest,
    db: AsyncSession = Depends(get_db),
):
    """Bulk assign findings to a user."""
    user = get_current_user()
    service = FindingWorkflowService(db)

    result = await service.bulk_assign(
        finding_ids=request.finding_ids,
        assignee_id=request.assignee_id,
        assignee_name=request.assignee_name,
        assigned_by_id=user["id"],
        assigned_by_name=user["name"],
    )

    return result


@router.post("/bulk/status")
async def bulk_status_change(
    request: BulkStatusRequest,
    db: AsyncSession = Depends(get_db),
):
    """Bulk change status of findings."""
    user = get_current_user()
    service = FindingWorkflowService(db)

    result = await service.bulk_status_change(
        finding_ids=request.finding_ids,
        new_status=request.new_status,
        changed_by_id=user["id"],
        changed_by_name=user["name"],
        reason=request.reason,
    )

    return result
