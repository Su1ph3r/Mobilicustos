"""
Issue Tracker Integration Router

API endpoints for managing issue tracker integrations.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.issue_tracker_service import IssueTrackerService

router = APIRouter(prefix="/issue-tracker", tags=["Issue Tracker Integration"])


# Request/Response Models

class JiraConfig(BaseModel):
    """Jira configuration."""
    base_url: str = Field(..., description="Jira instance URL (e.g., https://company.atlassian.net)")
    email: str = Field(..., description="Jira account email")
    api_token: str = Field(..., description="Jira API token")
    project_key: str = Field(..., description="Project key (e.g., SEC)")


class GitHubConfig(BaseModel):
    """GitHub configuration."""
    token: str = Field(..., description="GitHub personal access token")
    owner: str = Field(..., description="Repository owner")
    repo: str = Field(..., description="Repository name")


class GitLabConfig(BaseModel):
    """GitLab configuration."""
    base_url: str = Field(default="https://gitlab.com", description="GitLab instance URL")
    token: str = Field(..., description="GitLab personal access token")
    project_id: str = Field(..., description="Project ID or path")


class ConfigCreateRequest(BaseModel):
    """Request to create an issue tracker configuration."""
    name: str = Field(..., min_length=1, max_length=256)
    tracker_type: str = Field(..., pattern="^(jira|github|gitlab|azure_devops)$")
    config: dict = Field(..., description="Tracker-specific configuration")
    is_active: bool = Field(default=True)


class ConfigResponse(BaseModel):
    """Response for an issue tracker configuration."""
    config_id: str
    name: str
    tracker_type: str
    is_active: bool
    connection_status: Optional[str] = None


class CreateIssueRequest(BaseModel):
    """Request to create an issue from a finding."""
    finding_id: str = Field(..., description="Finding ID to create issue from")
    additional_labels: Optional[list[str]] = Field(None, description="Additional labels")


class IssueResponse(BaseModel):
    """Response for issue creation."""
    success: bool
    issue_id: Optional[str] = None
    issue_url: Optional[str] = None
    error: Optional[str] = None


# Endpoints

@router.get("/types")
async def get_tracker_types():
    """
    Get supported issue tracker types with their required configuration fields.
    """
    return {
        "types": [
            {
                "type": "jira",
                "name": "Jira",
                "description": "Atlassian Jira issue tracking",
                "config_fields": [
                    {"name": "base_url", "label": "Jira URL", "type": "url", "required": True},
                    {"name": "email", "label": "Email", "type": "email", "required": True},
                    {"name": "api_token", "label": "API Token", "type": "password", "required": True},
                    {"name": "project_key", "label": "Project Key", "type": "text", "required": True},
                ],
            },
            {
                "type": "github",
                "name": "GitHub Issues",
                "description": "GitHub repository issues",
                "config_fields": [
                    {"name": "token", "label": "Personal Access Token", "type": "password", "required": True},
                    {"name": "owner", "label": "Repository Owner", "type": "text", "required": True},
                    {"name": "repo", "label": "Repository Name", "type": "text", "required": True},
                ],
            },
            {
                "type": "gitlab",
                "name": "GitLab Issues",
                "description": "GitLab project issues",
                "config_fields": [
                    {"name": "base_url", "label": "GitLab URL", "type": "url", "required": False, "default": "https://gitlab.com"},
                    {"name": "token", "label": "Personal Access Token", "type": "password", "required": True},
                    {"name": "project_id", "label": "Project ID", "type": "text", "required": True},
                ],
            },
        ]
    }


@router.post("/configs", response_model=ConfigResponse)
async def create_config(
    request: ConfigCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new issue tracker configuration.

    The configuration will be tested before saving.
    """
    service = IssueTrackerService(db)

    try:
        config = await service.create_config(
            name=request.name,
            tracker_type=request.tracker_type,
            config=request.config,
            is_active=request.is_active,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return config


@router.get("/configs")
async def list_configs(
    tracker_type: Optional[str] = Query(None, description="Filter by tracker type"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    db: AsyncSession = Depends(get_db),
):
    """List all issue tracker configurations."""
    service = IssueTrackerService(db)
    configs = await service.list_configs(tracker_type, is_active)
    return {"configs": configs}


@router.get("/configs/{config_id}", response_model=ConfigResponse)
async def get_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get an issue tracker configuration."""
    service = IssueTrackerService(db)
    config = await service.get_config(config_id)

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    # Don't expose sensitive config
    return {
        "config_id": config["config_id"],
        "name": config["name"],
        "tracker_type": config["tracker_type"],
        "is_active": config["is_active"],
    }


@router.delete("/configs/{config_id}")
async def delete_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete an issue tracker configuration."""
    service = IssueTrackerService(db)
    deleted = await service.delete_config(config_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Configuration not found")

    return {"message": "Configuration deleted successfully"}


@router.post("/configs/{config_id}/test")
async def test_config(
    config_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Test an issue tracker configuration."""
    service = IssueTrackerService(db)
    config = await service.get_config(config_id)

    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    client = service._get_client(config["tracker_type"], config["config"])
    result = await client.test_connection()

    return {
        "config_id": config_id,
        "success": result.get("success", False),
        "message": "Connected" if result.get("success") else result.get("error"),
        "details": {k: v for k, v in result.items() if k not in ("success", "error")},
    }


@router.post("/issues", response_model=IssueResponse)
async def create_issue(
    request: CreateIssueRequest,
    config_id: str = Query(..., description="Issue tracker configuration to use"),
    db: AsyncSession = Depends(get_db),
):
    """
    Create an issue from a finding.

    The issue will be created in the configured issue tracker
    and linked to the finding.
    """
    service = IssueTrackerService(db)

    try:
        result = await service.create_issue_from_finding(
            config_id=config_id,
            finding_id=request.finding_id,
            additional_labels=request.additional_labels,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result


@router.post("/issues/bulk")
async def create_issues_bulk(
    finding_ids: list[str],
    config_id: str = Query(..., description="Issue tracker configuration to use"),
    additional_labels: Optional[list[str]] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Create issues for multiple findings.

    Returns a summary of created issues and any failures.
    """
    service = IssueTrackerService(db)

    results = {
        "created": [],
        "failed": [],
    }

    for finding_id in finding_ids:
        try:
            result = await service.create_issue_from_finding(
                config_id=config_id,
                finding_id=finding_id,
                additional_labels=additional_labels,
            )

            if result.get("success"):
                results["created"].append({
                    "finding_id": finding_id,
                    "issue_id": result["issue_id"],
                    "issue_url": result.get("issue_url"),
                })
            else:
                results["failed"].append({
                    "finding_id": finding_id,
                    "error": result.get("error"),
                })
        except Exception as e:
            results["failed"].append({
                "finding_id": finding_id,
                "error": str(e),
            })

    return {
        "total": len(finding_ids),
        "created_count": len(results["created"]),
        "failed_count": len(results["failed"]),
        **results,
    }


@router.post("/findings/{finding_id}/sync")
async def sync_finding_status(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Sync finding status from linked external issue.

    Updates the finding status based on the external issue status.
    """
    service = IssueTrackerService(db)

    try:
        result = await service.sync_issue_status(finding_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Sync failed"))

    return {
        "finding_id": finding_id,
        "external_status": result.get("status"),
        "synced": True,
    }
