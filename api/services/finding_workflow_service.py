"""
Finding Workflow Service

Manages finding workflows including:
- Comments and discussions
- Assignments
- Status history/audit trail
- Custom statuses and transitions
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class FindingWorkflowService:
    """Service for managing finding workflows."""

    # Default status workflow
    STATUS_WORKFLOW = {
        "new": ["confirmed", "false_positive", "ignored"],
        "confirmed": ["in_progress", "false_positive", "ignored"],
        "in_progress": ["fixed", "wont_fix", "confirmed"],
        "fixed": ["verified", "confirmed"],  # Can reopen if verification fails
        "verified": ["closed"],
        "closed": ["confirmed"],  # Can reopen
        "false_positive": ["confirmed"],  # Can reopen
        "ignored": ["confirmed"],  # Can reopen
        "wont_fix": ["confirmed"],  # Can reopen
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    # ==================== Comments ====================

    async def add_comment(
        self,
        finding_id: str,
        content: str,
        author_id: str,
        author_name: str,
        is_internal: bool = False,
    ) -> dict:
        """Add a comment to a finding."""
        comment_id = str(uuid4())

        query = """
            INSERT INTO finding_comments (
                comment_id, finding_id, content, author_id, author_name,
                is_internal, created_at
            ) VALUES (
                :comment_id, :finding_id, :content, :author_id, :author_name,
                :is_internal, :created_at
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "comment_id": comment_id,
            "finding_id": finding_id,
            "content": content,
            "author_id": author_id,
            "author_name": author_name,
            "is_internal": is_internal,
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping)

    async def get_comments(
        self,
        finding_id: str,
        include_internal: bool = True,
    ) -> list[dict]:
        """Get all comments for a finding."""
        conditions = ["finding_id = :finding_id"]
        params = {"finding_id": finding_id}

        if not include_internal:
            conditions.append("is_internal = false")

        query = f"""
            SELECT * FROM finding_comments
            WHERE {" AND ".join(conditions)}
            ORDER BY created_at ASC
        """

        result = await self.db.execute(query, params)
        return [dict(row._mapping) for row in result.fetchall()]

    async def update_comment(
        self,
        comment_id: str,
        content: str,
    ) -> Optional[dict]:
        """Update a comment."""
        query = """
            UPDATE finding_comments
            SET content = :content, updated_at = :updated_at
            WHERE comment_id = :comment_id
            RETURNING *
        """

        result = await self.db.execute(query, {
            "comment_id": comment_id,
            "content": content,
            "updated_at": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else None

    async def delete_comment(self, comment_id: str) -> bool:
        """Delete a comment."""
        query = "DELETE FROM finding_comments WHERE comment_id = :comment_id"
        result = await self.db.execute(query, {"comment_id": comment_id})
        await self.db.commit()
        return result.rowcount > 0

    # ==================== Assignments ====================

    async def assign_finding(
        self,
        finding_id: str,
        assignee_id: str,
        assignee_name: str,
        assigned_by_id: str,
        assigned_by_name: str,
        notes: Optional[str] = None,
    ) -> dict:
        """Assign a finding to a user."""
        assignment_id = str(uuid4())

        # Close any existing active assignments
        await self.db.execute(
            """
            UPDATE finding_assignments
            SET status = 'reassigned', completed_at = :now
            WHERE finding_id = :finding_id AND status = 'active'
            """,
            {"finding_id": finding_id, "now": datetime.utcnow()}
        )

        # Create new assignment
        query = """
            INSERT INTO finding_assignments (
                assignment_id, finding_id, assignee_id, assignee_name,
                assigned_by_id, assigned_by_name, notes, status, created_at
            ) VALUES (
                :assignment_id, :finding_id, :assignee_id, :assignee_name,
                :assigned_by_id, :assigned_by_name, :notes, 'active', :created_at
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "assignment_id": assignment_id,
            "finding_id": finding_id,
            "assignee_id": assignee_id,
            "assignee_name": assignee_name,
            "assigned_by_id": assigned_by_id,
            "assigned_by_name": assigned_by_name,
            "notes": notes,
            "created_at": datetime.utcnow(),
        })

        # Update finding with current assignee
        await self.db.execute(
            """
            UPDATE findings
            SET assignee_id = :assignee_id, assignee_name = :assignee_name
            WHERE finding_id = :finding_id
            """,
            {
                "finding_id": finding_id,
                "assignee_id": assignee_id,
                "assignee_name": assignee_name,
            }
        )

        await self.db.commit()

        # Record in history
        await self._record_history(
            finding_id=finding_id,
            action="assigned",
            actor_id=assigned_by_id,
            actor_name=assigned_by_name,
            details={"assignee": assignee_name},
        )

        row = result.fetchone()
        return dict(row._mapping)

    async def unassign_finding(
        self,
        finding_id: str,
        unassigned_by_id: str,
        unassigned_by_name: str,
    ) -> bool:
        """Remove assignment from a finding."""
        # Close active assignments
        result = await self.db.execute(
            """
            UPDATE finding_assignments
            SET status = 'unassigned', completed_at = :now
            WHERE finding_id = :finding_id AND status = 'active'
            """,
            {"finding_id": finding_id, "now": datetime.utcnow()}
        )

        # Clear assignee from finding
        await self.db.execute(
            """
            UPDATE findings
            SET assignee_id = NULL, assignee_name = NULL
            WHERE finding_id = :finding_id
            """,
            {"finding_id": finding_id}
        )

        await self.db.commit()

        if result.rowcount > 0:
            await self._record_history(
                finding_id=finding_id,
                action="unassigned",
                actor_id=unassigned_by_id,
                actor_name=unassigned_by_name,
            )

        return result.rowcount > 0

    async def get_assignments(
        self,
        finding_id: Optional[str] = None,
        assignee_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict]:
        """Get assignments with optional filters."""
        conditions = []
        params = {}

        if finding_id:
            conditions.append("fa.finding_id = :finding_id")
            params["finding_id"] = finding_id

        if assignee_id:
            conditions.append("fa.assignee_id = :assignee_id")
            params["assignee_id"] = assignee_id

        if status:
            conditions.append("fa.status = :status")
            params["status"] = status

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT fa.*, f.title as finding_title, f.severity
            FROM finding_assignments fa
            JOIN findings f ON fa.finding_id = f.finding_id
            WHERE {where_clause}
            ORDER BY fa.created_at DESC
        """

        result = await self.db.execute(query, params)
        return [dict(row._mapping) for row in result.fetchall()]

    # ==================== Status Changes ====================

    async def change_status(
        self,
        finding_id: str,
        new_status: str,
        changed_by_id: str,
        changed_by_name: str,
        reason: Optional[str] = None,
    ) -> dict:
        """Change the status of a finding."""
        # Get current status
        result = await self.db.execute(
            "SELECT status FROM findings WHERE finding_id = :finding_id",
            {"finding_id": finding_id}
        )
        row = result.fetchone()

        if not row:
            raise ValueError("Finding not found")

        old_status = row[0]

        # Validate transition
        allowed_transitions = self.STATUS_WORKFLOW.get(old_status, [])
        if new_status not in allowed_transitions:
            raise ValueError(
                f"Cannot transition from '{old_status}' to '{new_status}'. "
                f"Allowed: {allowed_transitions}"
            )

        # Update status
        await self.db.execute(
            """
            UPDATE findings
            SET status = :new_status, updated_at = :now
            WHERE finding_id = :finding_id
            """,
            {
                "finding_id": finding_id,
                "new_status": new_status,
                "now": datetime.utcnow(),
            }
        )

        await self.db.commit()

        # Record in history
        await self._record_history(
            finding_id=finding_id,
            action="status_changed",
            actor_id=changed_by_id,
            actor_name=changed_by_name,
            old_value=old_status,
            new_value=new_status,
            details={"reason": reason} if reason else None,
        )

        return {
            "finding_id": finding_id,
            "old_status": old_status,
            "new_status": new_status,
        }

    def get_allowed_transitions(self, current_status: str) -> list[str]:
        """Get allowed status transitions from current status."""
        return self.STATUS_WORKFLOW.get(current_status, [])

    # ==================== History ====================

    async def _record_history(
        self,
        finding_id: str,
        action: str,
        actor_id: str,
        actor_name: str,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        """Record an action in finding history."""
        import json

        query = """
            INSERT INTO finding_history (
                history_id, finding_id, action, actor_id, actor_name,
                old_value, new_value, details, created_at
            ) VALUES (
                :history_id, :finding_id, :action, :actor_id, :actor_name,
                :old_value, :new_value, :details, :created_at
            )
        """

        await self.db.execute(query, {
            "history_id": str(uuid4()),
            "finding_id": finding_id,
            "action": action,
            "actor_id": actor_id,
            "actor_name": actor_name,
            "old_value": old_value,
            "new_value": new_value,
            "details": json.dumps(details) if details else None,
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

    async def get_history(
        self,
        finding_id: str,
        limit: int = 50,
    ) -> list[dict]:
        """Get history for a finding."""
        query = """
            SELECT * FROM finding_history
            WHERE finding_id = :finding_id
            ORDER BY created_at DESC
            LIMIT :limit
        """

        result = await self.db.execute(query, {
            "finding_id": finding_id,
            "limit": limit,
        })

        import json
        history = []
        for row in result.fetchall():
            item = dict(row._mapping)
            if item.get("details"):
                item["details"] = json.loads(item["details"])
            history.append(item)

        return history

    # ==================== Bulk Operations ====================

    async def bulk_assign(
        self,
        finding_ids: list[str],
        assignee_id: str,
        assignee_name: str,
        assigned_by_id: str,
        assigned_by_name: str,
    ) -> dict:
        """Bulk assign findings to a user."""
        assigned = 0
        failed = 0

        for finding_id in finding_ids:
            try:
                await self.assign_finding(
                    finding_id=finding_id,
                    assignee_id=assignee_id,
                    assignee_name=assignee_name,
                    assigned_by_id=assigned_by_id,
                    assigned_by_name=assigned_by_name,
                )
                assigned += 1
            except Exception as e:
                logger.warning(f"Failed to assign {finding_id}: {e}")
                failed += 1

        return {"assigned": assigned, "failed": failed}

    async def bulk_status_change(
        self,
        finding_ids: list[str],
        new_status: str,
        changed_by_id: str,
        changed_by_name: str,
        reason: Optional[str] = None,
    ) -> dict:
        """Bulk change status of findings."""
        changed = 0
        failed = 0
        errors = []

        for finding_id in finding_ids:
            try:
                await self.change_status(
                    finding_id=finding_id,
                    new_status=new_status,
                    changed_by_id=changed_by_id,
                    changed_by_name=changed_by_name,
                    reason=reason,
                )
                changed += 1
            except ValueError as e:
                failed += 1
                errors.append({"finding_id": finding_id, "error": str(e)})
            except Exception as e:
                logger.warning(f"Failed to change status for {finding_id}: {e}")
                failed += 1
                errors.append({"finding_id": finding_id, "error": str(e)})

        return {"changed": changed, "failed": failed, "errors": errors}
