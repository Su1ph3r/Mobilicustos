"""
Scheduled Scan Service

Manages scheduled/recurring scans with cron-like scheduling capabilities.
Supports:
- One-time scheduled scans
- Recurring scans (daily, weekly, monthly, custom cron)
- Scan configuration persistence
- Notification on completion
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4, UUID
from croniter import croniter

from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class ScheduledScanService:
    """Service for managing scheduled scans."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._scheduler_task: Optional[asyncio.Task] = None

    async def create_schedule(
        self,
        app_id: str,
        name: str,
        cron_expression: str,
        analyzers: list[str],
        is_active: bool = True,
        webhook_url: Optional[str] = None,
        notify_email: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> dict:
        """
        Create a new scheduled scan.

        Args:
            app_id: The app to scan
            name: Name for this schedule
            cron_expression: Cron expression (e.g., "0 2 * * *" for daily at 2 AM)
            analyzers: List of analyzers to run
            is_active: Whether the schedule is active
            webhook_url: Optional webhook to call on completion
            notify_email: Optional email for notifications
            created_by: User who created the schedule

        Returns:
            Created schedule details
        """
        schedule_id = str(uuid4())

        # Calculate next run time
        cron = croniter(cron_expression, datetime.utcnow())
        next_run = cron.get_next(datetime)

        query = """
            INSERT INTO scheduled_scans (
                schedule_id, app_id, name, cron_expression, analyzers,
                is_active, next_run_at, webhook_url, notify_email,
                created_by, created_at
            ) VALUES (
                :schedule_id, :app_id, :name, :cron_expression, :analyzers,
                :is_active, :next_run_at, :webhook_url, :notify_email,
                :created_by, :created_at
            )
            RETURNING *
        """

        result = await self.db.execute(
            query,
            {
                "schedule_id": schedule_id,
                "app_id": app_id,
                "name": name,
                "cron_expression": cron_expression,
                "analyzers": analyzers,
                "is_active": is_active,
                "next_run_at": next_run,
                "webhook_url": webhook_url,
                "notify_email": notify_email,
                "created_by": created_by,
                "created_at": datetime.utcnow(),
            }
        )

        await self.db.commit()

        return {
            "schedule_id": schedule_id,
            "app_id": app_id,
            "name": name,
            "cron_expression": cron_expression,
            "analyzers": analyzers,
            "is_active": is_active,
            "next_run_at": next_run.isoformat(),
            "webhook_url": webhook_url,
            "notify_email": notify_email,
            "created_by": created_by,
        }

    async def get_schedule(self, schedule_id: str) -> Optional[dict]:
        """Get a scheduled scan by ID."""
        query = """
            SELECT s.*, a.app_name, a.package_name
            FROM scheduled_scans s
            JOIN mobile_apps a ON s.app_id = a.app_id
            WHERE s.schedule_id = :schedule_id
        """

        result = await self.db.execute(query, {"schedule_id": schedule_id})
        row = result.fetchone()

        if not row:
            return None

        return dict(row._mapping)

    async def list_schedules(
        self,
        app_id: Optional[str] = None,
        is_active: Optional[bool] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List scheduled scans with optional filters."""
        conditions = []
        params = {}

        if app_id:
            conditions.append("s.app_id = :app_id")
            params["app_id"] = app_id

        if is_active is not None:
            conditions.append("s.is_active = :is_active")
            params["is_active"] = is_active

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # Count query
        count_query = f"""
            SELECT COUNT(*) FROM scheduled_scans s WHERE {where_clause}
        """
        count_result = await self.db.execute(count_query, params)
        total = count_result.scalar()

        # Data query
        offset = (page - 1) * page_size
        data_query = f"""
            SELECT s.*, a.app_name, a.package_name
            FROM scheduled_scans s
            JOIN mobile_apps a ON s.app_id = a.app_id
            WHERE {where_clause}
            ORDER BY s.next_run_at ASC NULLS LAST
            LIMIT :limit OFFSET :offset
        """
        params["limit"] = page_size
        params["offset"] = offset

        result = await self.db.execute(data_query, params)
        schedules = [dict(row._mapping) for row in result.fetchall()]

        return {
            "items": schedules,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        }

    async def update_schedule(
        self,
        schedule_id: str,
        name: Optional[str] = None,
        cron_expression: Optional[str] = None,
        analyzers: Optional[list[str]] = None,
        is_active: Optional[bool] = None,
        webhook_url: Optional[str] = None,
        notify_email: Optional[str] = None,
    ) -> Optional[dict]:
        """Update an existing scheduled scan."""
        updates = []
        params = {"schedule_id": schedule_id}

        if name is not None:
            updates.append("name = :name")
            params["name"] = name

        if cron_expression is not None:
            updates.append("cron_expression = :cron_expression")
            params["cron_expression"] = cron_expression
            # Recalculate next run
            cron = croniter(cron_expression, datetime.utcnow())
            next_run = cron.get_next(datetime)
            updates.append("next_run_at = :next_run_at")
            params["next_run_at"] = next_run

        if analyzers is not None:
            updates.append("analyzers = :analyzers")
            params["analyzers"] = analyzers

        if is_active is not None:
            updates.append("is_active = :is_active")
            params["is_active"] = is_active

        if webhook_url is not None:
            updates.append("webhook_url = :webhook_url")
            params["webhook_url"] = webhook_url

        if notify_email is not None:
            updates.append("notify_email = :notify_email")
            params["notify_email"] = notify_email

        if not updates:
            return await self.get_schedule(schedule_id)

        updates.append("updated_at = :updated_at")
        params["updated_at"] = datetime.utcnow()

        query = f"""
            UPDATE scheduled_scans
            SET {", ".join(updates)}
            WHERE schedule_id = :schedule_id
            RETURNING *
        """

        result = await self.db.execute(query, params)
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else None

    async def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a scheduled scan."""
        query = """
            DELETE FROM scheduled_scans WHERE schedule_id = :schedule_id
        """
        result = await self.db.execute(query, {"schedule_id": schedule_id})
        await self.db.commit()
        return result.rowcount > 0

    async def get_due_schedules(self) -> list[dict]:
        """Get all schedules that are due to run."""
        query = """
            SELECT s.*, a.app_name, a.package_name, a.file_path
            FROM scheduled_scans s
            JOIN mobile_apps a ON s.app_id = a.app_id
            WHERE s.is_active = true
              AND s.next_run_at <= :now
            ORDER BY s.next_run_at ASC
        """

        result = await self.db.execute(query, {"now": datetime.utcnow()})
        return [dict(row._mapping) for row in result.fetchall()]

    async def mark_schedule_run(self, schedule_id: str, scan_id: str) -> None:
        """Mark a schedule as having been run and calculate next run time."""
        # Get current schedule
        schedule = await self.get_schedule(schedule_id)
        if not schedule:
            return

        # Calculate next run time
        cron = croniter(schedule["cron_expression"], datetime.utcnow())
        next_run = cron.get_next(datetime)

        query = """
            UPDATE scheduled_scans
            SET last_run_at = :last_run_at,
                last_scan_id = :last_scan_id,
                next_run_at = :next_run_at,
                run_count = COALESCE(run_count, 0) + 1
            WHERE schedule_id = :schedule_id
        """

        await self.db.execute(query, {
            "schedule_id": schedule_id,
            "last_run_at": datetime.utcnow(),
            "last_scan_id": scan_id,
            "next_run_at": next_run,
        })
        await self.db.commit()

    async def get_schedule_history(
        self,
        schedule_id: str,
        limit: int = 10,
    ) -> list[dict]:
        """Get scan history for a scheduled scan."""
        query = """
            SELECT sc.*
            FROM scans sc
            JOIN scheduled_scans ss ON sc.scan_id = ss.last_scan_id
            WHERE ss.schedule_id = :schedule_id
            ORDER BY sc.created_at DESC
            LIMIT :limit
        """

        result = await self.db.execute(query, {
            "schedule_id": schedule_id,
            "limit": limit,
        })

        return [dict(row._mapping) for row in result.fetchall()]

    @staticmethod
    def validate_cron_expression(expression: str) -> tuple[bool, str]:
        """Validate a cron expression."""
        try:
            croniter(expression)
            return True, "Valid cron expression"
        except (ValueError, KeyError) as e:
            return False, f"Invalid cron expression: {str(e)}"

    @staticmethod
    def get_next_runs(cron_expression: str, count: int = 5) -> list[str]:
        """Get the next N run times for a cron expression."""
        try:
            cron = croniter(cron_expression, datetime.utcnow())
            runs = []
            for _ in range(count):
                next_run = cron.get_next(datetime)
                runs.append(next_run.isoformat())
            return runs
        except Exception:
            return []

    @staticmethod
    def describe_cron(expression: str) -> str:
        """Generate a human-readable description of a cron expression."""
        # Common patterns
        descriptions = {
            "0 * * * *": "Every hour",
            "0 0 * * *": "Daily at midnight",
            "0 2 * * *": "Daily at 2:00 AM",
            "0 0 * * 0": "Weekly on Sunday",
            "0 0 * * 1": "Weekly on Monday",
            "0 0 1 * *": "Monthly on the 1st",
            "0 0 1 1 *": "Yearly on January 1st",
        }

        if expression in descriptions:
            return descriptions[expression]

        parts = expression.split()
        if len(parts) != 5:
            return "Custom schedule"

        minute, hour, day, month, weekday = parts

        desc_parts = []

        if minute == "0" and hour != "*":
            desc_parts.append(f"at {hour}:00")
        elif minute != "*" and hour != "*":
            desc_parts.append(f"at {hour}:{minute.zfill(2)}")
        elif minute == "*/15":
            desc_parts.append("every 15 minutes")
        elif minute == "*/30":
            desc_parts.append("every 30 minutes")

        if day == "*" and weekday == "*":
            desc_parts.append("daily")
        elif weekday != "*":
            days = {
                "0": "Sunday", "1": "Monday", "2": "Tuesday",
                "3": "Wednesday", "4": "Thursday", "5": "Friday", "6": "Saturday",
            }
            desc_parts.append(f"on {days.get(weekday, weekday)}")
        elif day != "*":
            desc_parts.append(f"on day {day}")

        return " ".join(desc_parts) if desc_parts else "Custom schedule"
