"""
Webhooks Router

API endpoints for managing webhook configurations and testing.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services.webhook_service import WebhookService

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


# Request/Response Models

class WebhookCreateRequest(BaseModel):
    """Request to create a webhook."""
    name: str = Field(..., min_length=1, max_length=256, description="Name for the webhook")
    url: str = Field(..., description="URL to send events to")
    events: list[str] = Field(..., min_items=1, description="Event types to subscribe to")
    is_active: bool = Field(default=True, description="Whether the webhook is active")
    headers: Optional[dict] = Field(None, description="Custom headers to include")


class WebhookUpdateRequest(BaseModel):
    """Request to update a webhook."""
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    url: Optional[str] = None
    events: Optional[list[str]] = None
    is_active: Optional[bool] = None
    headers: Optional[dict] = None


class WebhookResponse(BaseModel):
    """Response for a webhook."""
    webhook_id: str
    name: str
    url: str
    events: list[str]
    is_active: bool
    secret: Optional[str] = None  # Masked in list, full in create
    headers: Optional[dict] = None
    last_triggered_at: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None


class WebhookTestResponse(BaseModel):
    """Response for webhook test."""
    webhook_id: str
    delivery_id: str
    success: bool
    status_code: int
    duration_ms: int
    retry_count: int


class EventTypesResponse(BaseModel):
    """Response listing available event types."""
    events: list[dict]


# Endpoints

@router.get("/events", response_model=EventTypesResponse)
async def list_event_types():
    """
    List all available webhook event types.

    Use these event types when creating or updating webhooks
    to specify which events should trigger notifications.
    """
    events = [
        {
            "type": WebhookService.EVENT_SCAN_STARTED,
            "description": "Triggered when a scan starts",
            "payload_example": {
                "scan_id": "uuid",
                "app_id": "uuid",
                "scan_type": "full",
            },
        },
        {
            "type": WebhookService.EVENT_SCAN_COMPLETED,
            "description": "Triggered when a scan completes successfully",
            "payload_example": {
                "scan_id": "uuid",
                "app_id": "uuid",
                "findings_count": 15,
                "duration_seconds": 120,
            },
        },
        {
            "type": WebhookService.EVENT_SCAN_FAILED,
            "description": "Triggered when a scan fails",
            "payload_example": {
                "scan_id": "uuid",
                "app_id": "uuid",
                "error": "Error message",
            },
        },
        {
            "type": WebhookService.EVENT_FINDING_NEW,
            "description": "Triggered when a new finding is discovered",
            "payload_example": {
                "finding_id": "uuid",
                "app_id": "uuid",
                "title": "Finding title",
                "severity": "high",
            },
        },
        {
            "type": WebhookService.EVENT_FINDING_STATUS_CHANGED,
            "description": "Triggered when a finding's status changes",
            "payload_example": {
                "finding_id": "uuid",
                "old_status": "new",
                "new_status": "confirmed",
            },
        },
        {
            "type": WebhookService.EVENT_APP_UPLOADED,
            "description": "Triggered when a new app is uploaded",
            "payload_example": {
                "app_id": "uuid",
                "app_name": "App Name",
                "platform": "android",
            },
        },
        {
            "type": WebhookService.EVENT_SCHEDULE_TRIGGERED,
            "description": "Triggered when a scheduled scan starts",
            "payload_example": {
                "schedule_id": "uuid",
                "scan_id": "uuid",
                "app_id": "uuid",
            },
        },
    ]

    return {"events": events}


@router.post("", response_model=WebhookResponse)
async def create_webhook(
    request: WebhookCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new webhook configuration.

    The webhook will receive POST requests for subscribed events with:
    - `X-Webhook-Signature`: HMAC SHA256 signature using the secret
    - `X-Webhook-ID`: The webhook ID
    - `X-Delivery-ID`: Unique delivery ID
    - `X-Event-Type`: The event type

    Verify the signature to ensure authenticity:
    ```python
    import hmac
    import hashlib

    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    signature = request.headers['X-Webhook-Signature']
    if signature == f"sha256={expected}":
        # Valid signature
    ```
    """
    service = WebhookService(db)

    try:
        webhook = await service.create_webhook(
            name=request.name,
            url=request.url,
            events=request.events,
            is_active=request.is_active,
            headers=request.headers,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return webhook


@router.get("", response_model=dict)
async def list_webhooks(
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    event_type: Optional[str] = Query(None, description="Filter by subscribed event"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List all webhooks with optional filters."""
    service = WebhookService(db)

    return await service.list_webhooks(
        is_active=is_active,
        event_type=event_type,
        page=page,
        page_size=page_size,
    )


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a webhook by ID."""
    service = WebhookService(db)

    webhook = await service.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    # Mask the secret
    if webhook.get("secret"):
        webhook["secret"] = webhook["secret"][:8] + "..." + webhook["secret"][-4:]

    return webhook


@router.put("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: str,
    request: WebhookUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update a webhook configuration."""
    service = WebhookService(db)

    try:
        webhook = await service.update_webhook(
            webhook_id=webhook_id,
            name=request.name,
            url=request.url,
            events=request.events,
            is_active=request.is_active,
            headers=request.headers,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return webhook


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a webhook."""
    service = WebhookService(db)

    deleted = await service.delete_webhook(webhook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return {"message": "Webhook deleted successfully"}


@router.post("/{webhook_id}/test", response_model=WebhookTestResponse)
async def test_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Send a test event to a webhook.

    This sends a `webhook.test` event to verify the webhook
    configuration is working correctly.
    """
    service = WebhookService(db)

    try:
        result = await service.test_webhook(webhook_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return result


@router.post("/{webhook_id}/regenerate-secret")
async def regenerate_secret(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Regenerate the secret for a webhook.

    The old secret will be invalidated immediately.
    Update your webhook handler with the new secret.
    """
    service = WebhookService(db)

    new_secret = await service.regenerate_secret(webhook_id)
    if not new_secret:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return {
        "message": "Secret regenerated successfully",
        "secret": new_secret,
    }


@router.post("/{webhook_id}/pause")
async def pause_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Pause a webhook (stop sending events)."""
    service = WebhookService(db)

    webhook = await service.update_webhook(webhook_id, is_active=False)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return {"message": "Webhook paused", "webhook_id": webhook_id}


@router.post("/{webhook_id}/resume")
async def resume_webhook(
    webhook_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Resume a paused webhook."""
    service = WebhookService(db)

    webhook = await service.update_webhook(webhook_id, is_active=True)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return {"message": "Webhook resumed", "webhook_id": webhook_id}


@router.get("/{webhook_id}/deliveries")
async def get_delivery_history(
    webhook_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Get delivery history for a webhook."""
    service = WebhookService(db)

    webhook = await service.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    deliveries = await service.get_delivery_history(webhook_id, limit)

    return {
        "webhook_id": webhook_id,
        "deliveries": deliveries,
    }
