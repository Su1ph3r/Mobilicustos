"""
Webhook Service

Manages webhook configurations and deliveries for event notifications.
Supports:
- Scan completion notifications
- Finding notifications
- Custom event hooks
- Retry logic with exponential backoff
"""

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class WebhookService:
    """Service for managing webhooks and event notifications."""

    # Event types
    EVENT_SCAN_STARTED = "scan.started"
    EVENT_SCAN_COMPLETED = "scan.completed"
    EVENT_SCAN_FAILED = "scan.failed"
    EVENT_FINDING_NEW = "finding.new"
    EVENT_FINDING_STATUS_CHANGED = "finding.status_changed"
    EVENT_APP_UPLOADED = "app.uploaded"
    EVENT_SCHEDULE_TRIGGERED = "schedule.triggered"

    ALL_EVENTS = [
        EVENT_SCAN_STARTED,
        EVENT_SCAN_COMPLETED,
        EVENT_SCAN_FAILED,
        EVENT_FINDING_NEW,
        EVENT_FINDING_STATUS_CHANGED,
        EVENT_APP_UPLOADED,
        EVENT_SCHEDULE_TRIGGERED,
    ]

    def __init__(self, db: AsyncSession):
        self.db = db
        self.http_client = httpx.AsyncClient(timeout=30.0)

    async def create_webhook(
        self,
        name: str,
        url: str,
        events: list[str],
        secret: Optional[str] = None,
        is_active: bool = True,
        headers: Optional[dict] = None,
        created_by: Optional[str] = None,
    ) -> dict:
        """
        Create a new webhook configuration.

        Args:
            name: Name for the webhook
            url: URL to send events to
            events: List of event types to subscribe to
            secret: Optional secret for HMAC signature
            is_active: Whether the webhook is active
            headers: Optional custom headers
            created_by: User who created the webhook

        Returns:
            Created webhook configuration
        """
        webhook_id = str(uuid4())

        # Generate secret if not provided
        if not secret:
            secret = hashlib.sha256(str(uuid4()).encode()).hexdigest()[:32]

        # Validate events
        invalid_events = set(events) - set(self.ALL_EVENTS)
        if invalid_events:
            raise ValueError(f"Invalid events: {invalid_events}")

        query = """
            INSERT INTO webhooks (
                webhook_id, name, url, events, secret,
                is_active, headers, created_by, created_at
            ) VALUES (
                :webhook_id, :name, :url, :events, :secret,
                :is_active, :headers, :created_by, :created_at
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "webhook_id": webhook_id,
            "name": name,
            "url": url,
            "events": events,
            "secret": secret,
            "is_active": is_active,
            "headers": json.dumps(headers) if headers else None,
            "created_by": created_by,
            "created_at": datetime.utcnow(),
        })

        await self.db.commit()

        return {
            "webhook_id": webhook_id,
            "name": name,
            "url": url,
            "events": events,
            "secret": secret,
            "is_active": is_active,
            "headers": headers,
        }

    async def get_webhook(self, webhook_id: str) -> Optional[dict]:
        """Get a webhook by ID."""
        query = """
            SELECT * FROM webhooks WHERE webhook_id = :webhook_id
        """
        result = await self.db.execute(query, {"webhook_id": webhook_id})
        row = result.fetchone()

        if not row:
            return None

        webhook = dict(row._mapping)
        if webhook.get("headers"):
            webhook["headers"] = json.loads(webhook["headers"])
        return webhook

    async def list_webhooks(
        self,
        is_active: Optional[bool] = None,
        event_type: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List webhooks with optional filters."""
        conditions = []
        params = {}

        if is_active is not None:
            conditions.append("is_active = :is_active")
            params["is_active"] = is_active

        if event_type:
            conditions.append(":event_type = ANY(events)")
            params["event_type"] = event_type

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # Count
        count_query = text(f"SELECT COUNT(*) FROM webhooks WHERE {where_clause}")
        count_result = await self.db.execute(count_query, params)
        total = count_result.scalar()

        # Data
        offset = (page - 1) * page_size
        data_query = text(f"""
            SELECT * FROM webhooks
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """)
        params["limit"] = page_size
        params["offset"] = offset

        result = await self.db.execute(data_query, params)
        webhooks = []
        for row in result.fetchall():
            webhook = dict(row._mapping)
            if webhook.get("headers"):
                webhook["headers"] = json.loads(webhook["headers"])
            # Mask secret
            if webhook.get("secret"):
                webhook["secret"] = webhook["secret"][:8] + "..." + webhook["secret"][-4:]
            webhooks.append(webhook)

        return {
            "items": webhooks,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    async def update_webhook(
        self,
        webhook_id: str,
        name: Optional[str] = None,
        url: Optional[str] = None,
        events: Optional[list[str]] = None,
        is_active: Optional[bool] = None,
        headers: Optional[dict] = None,
    ) -> Optional[dict]:
        """Update a webhook configuration."""
        updates = []
        params = {"webhook_id": webhook_id}

        if name is not None:
            updates.append("name = :name")
            params["name"] = name

        if url is not None:
            updates.append("url = :url")
            params["url"] = url

        if events is not None:
            invalid_events = set(events) - set(self.ALL_EVENTS)
            if invalid_events:
                raise ValueError(f"Invalid events: {invalid_events}")
            updates.append("events = :events")
            params["events"] = events

        if is_active is not None:
            updates.append("is_active = :is_active")
            params["is_active"] = is_active

        if headers is not None:
            updates.append("headers = :headers")
            params["headers"] = json.dumps(headers)

        if not updates:
            return await self.get_webhook(webhook_id)

        updates.append("updated_at = :updated_at")
        params["updated_at"] = datetime.utcnow()

        query = f"""
            UPDATE webhooks
            SET {", ".join(updates)}
            WHERE webhook_id = :webhook_id
            RETURNING *
        """

        result = await self.db.execute(query, params)
        await self.db.commit()

        row = result.fetchone()
        if not row:
            return None

        webhook = dict(row._mapping)
        if webhook.get("headers"):
            webhook["headers"] = json.loads(webhook["headers"])
        return webhook

    async def delete_webhook(self, webhook_id: str) -> bool:
        """Delete a webhook."""
        query = "DELETE FROM webhooks WHERE webhook_id = :webhook_id"
        result = await self.db.execute(query, {"webhook_id": webhook_id})
        await self.db.commit()
        return result.rowcount > 0

    async def regenerate_secret(self, webhook_id: str) -> Optional[str]:
        """Regenerate the secret for a webhook."""
        new_secret = hashlib.sha256(str(uuid4()).encode()).hexdigest()[:32]

        query = """
            UPDATE webhooks
            SET secret = :secret, updated_at = :updated_at
            WHERE webhook_id = :webhook_id
            RETURNING secret
        """

        result = await self.db.execute(query, {
            "webhook_id": webhook_id,
            "secret": new_secret,
            "updated_at": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return row[0] if row else None

    async def trigger_event(
        self,
        event_type: str,
        payload: dict,
    ) -> list[dict]:
        """
        Trigger an event and send to all subscribed webhooks.

        Args:
            event_type: The event type (e.g., scan.completed)
            payload: Event payload data

        Returns:
            List of delivery results
        """
        # Get all active webhooks subscribed to this event
        query = """
            SELECT * FROM webhooks
            WHERE is_active = true
              AND :event_type = ANY(events)
        """
        result = await self.db.execute(query, {"event_type": event_type})
        webhooks = [dict(row._mapping) for row in result.fetchall()]

        if not webhooks:
            return []

        # Prepare event data
        event_data = {
            "event_id": str(uuid4()),
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": payload,
        }

        # Send to all webhooks
        results = []
        for webhook in webhooks:
            delivery_result = await self._deliver_webhook(webhook, event_data)
            results.append(delivery_result)

        return results

    async def _deliver_webhook(
        self,
        webhook: dict,
        event_data: dict,
        retry_count: int = 0,
        max_retries: int = 3,
    ) -> dict:
        """Deliver a webhook with retry logic."""
        delivery_id = str(uuid4())
        started_at = datetime.utcnow()

        # Prepare headers
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-ID": webhook["webhook_id"],
            "X-Delivery-ID": delivery_id,
            "X-Event-Type": event_data["event_type"],
        }

        # Add custom headers
        if webhook.get("headers"):
            custom_headers = webhook["headers"]
            if isinstance(custom_headers, str):
                custom_headers = json.loads(custom_headers)
            headers.update(custom_headers)

        # Add HMAC signature
        payload_json = json.dumps(event_data, default=str)
        if webhook.get("secret"):
            signature = hmac.new(
                webhook["secret"].encode(),
                payload_json.encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-Webhook-Signature"] = f"sha256={signature}"

        # Attempt delivery
        try:
            response = await self.http_client.post(
                webhook["url"],
                content=payload_json,
                headers=headers,
            )

            success = 200 <= response.status_code < 300
            status_code = response.status_code
            response_body = response.text[:1000]  # Limit response body

        except Exception as e:
            success = False
            status_code = 0
            response_body = str(e)

        completed_at = datetime.utcnow()
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        # Log delivery
        await self._log_delivery(
            webhook_id=webhook["webhook_id"],
            delivery_id=delivery_id,
            event_type=event_data["event_type"],
            event_data=event_data,
            success=success,
            status_code=status_code,
            response_body=response_body,
            duration_ms=duration_ms,
            retry_count=retry_count,
        )

        # Retry on failure
        if not success and retry_count < max_retries:
            delay = 2 ** retry_count  # Exponential backoff
            await asyncio.sleep(delay)
            return await self._deliver_webhook(
                webhook, event_data, retry_count + 1, max_retries
            )

        # Update webhook stats
        await self._update_webhook_stats(
            webhook["webhook_id"],
            success=success,
        )

        return {
            "webhook_id": webhook["webhook_id"],
            "delivery_id": delivery_id,
            "success": success,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "retry_count": retry_count,
        }

    async def _log_delivery(
        self,
        webhook_id: str,
        delivery_id: str,
        event_type: str,
        event_data: dict,
        success: bool,
        status_code: int,
        response_body: str,
        duration_ms: int,
        retry_count: int,
    ) -> None:
        """Log a webhook delivery attempt."""
        # Note: This would insert into a webhook_deliveries table
        # For now, just log
        logger.info(
            f"Webhook delivery: webhook_id={webhook_id}, "
            f"event={event_type}, success={success}, "
            f"status={status_code}, duration={duration_ms}ms"
        )

    async def _update_webhook_stats(
        self,
        webhook_id: str,
        success: bool,
    ) -> None:
        """Update webhook delivery statistics."""
        if success:
            query = """
                UPDATE webhooks
                SET last_triggered_at = :now,
                    success_count = COALESCE(success_count, 0) + 1
                WHERE webhook_id = :webhook_id
            """
        else:
            query = """
                UPDATE webhooks
                SET last_triggered_at = :now,
                    failure_count = COALESCE(failure_count, 0) + 1
                WHERE webhook_id = :webhook_id
            """

        await self.db.execute(query, {
            "webhook_id": webhook_id,
            "now": datetime.utcnow(),
        })
        await self.db.commit()

    async def test_webhook(self, webhook_id: str) -> dict:
        """Send a test event to a webhook."""
        webhook = await self.get_webhook(webhook_id)
        if not webhook:
            raise ValueError("Webhook not found")

        test_payload = {
            "message": "This is a test webhook delivery",
            "timestamp": datetime.utcnow().isoformat(),
            "webhook_id": webhook_id,
        }

        event_data = {
            "event_id": str(uuid4()),
            "event_type": "webhook.test",
            "timestamp": datetime.utcnow().isoformat(),
            "data": test_payload,
        }

        return await self._deliver_webhook(webhook, event_data)

    async def get_delivery_history(
        self,
        webhook_id: str,
        limit: int = 50,
    ) -> list[dict]:
        """Get delivery history for a webhook."""
        # Note: This would query webhook_deliveries table
        # For now, return empty list
        return []

    def generate_signature(self, payload: str, secret: str) -> str:
        """Generate HMAC signature for a payload."""
        return hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

    def verify_signature(
        self,
        payload: str,
        signature: str,
        secret: str,
    ) -> bool:
        """Verify HMAC signature of a payload."""
        expected = self.generate_signature(payload, secret)
        return hmac.compare_digest(f"sha256={expected}", signature)
