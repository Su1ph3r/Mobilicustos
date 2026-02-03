"""
Team and Workspace Service

Manages teams, workspaces, and role-based access:
- Team management
- Workspace isolation
- Role assignments
- Activity logging
"""

import logging
from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class TeamService:
    """Service for managing teams and workspaces."""

    # Available roles
    ROLES = {
        "owner": {"level": 100, "description": "Full control over workspace"},
        "admin": {"level": 80, "description": "Manage team and settings"},
        "analyst": {"level": 60, "description": "Full access to scans and findings"},
        "developer": {"level": 40, "description": "View findings and update status"},
        "viewer": {"level": 20, "description": "Read-only access"},
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    # ==================== Workspaces ====================

    async def create_workspace(
        self,
        name: str,
        description: Optional[str] = None,
        owner_id: str = None,
        owner_name: str = None,
    ) -> dict:
        """Create a new workspace."""
        workspace_id = str(uuid4())

        query = """
            INSERT INTO workspaces (
                workspace_id, name, description, created_by, created_at
            ) VALUES (
                :workspace_id, :name, :description, :created_by, :created_at
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "workspace_id": workspace_id,
            "name": name,
            "description": description,
            "created_by": owner_id,
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        # Add owner as team member
        if owner_id:
            await self.add_team_member(
                workspace_id=workspace_id,
                user_id=owner_id,
                user_name=owner_name or "Owner",
                user_email="",
                role="owner",
            )

        row = result.fetchone()
        return dict(row._mapping)

    async def get_workspace(self, workspace_id: str) -> Optional[dict]:
        """Get workspace by ID."""
        query = """
            SELECT w.*, COUNT(tm.member_id) as member_count
            FROM workspaces w
            LEFT JOIN team_members tm ON w.workspace_id = tm.workspace_id
            WHERE w.workspace_id = :workspace_id
            GROUP BY w.workspace_id
        """
        result = await self.db.execute(query, {"workspace_id": workspace_id})
        row = result.fetchone()
        return dict(row._mapping) if row else None

    async def list_workspaces(
        self,
        user_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List workspaces, optionally filtered by user membership."""
        params = {}

        if user_id:
            query = """
                SELECT w.*, tm.role as user_role, COUNT(tm2.member_id) as member_count
                FROM workspaces w
                JOIN team_members tm ON w.workspace_id = tm.workspace_id AND tm.user_id = :user_id
                LEFT JOIN team_members tm2 ON w.workspace_id = tm2.workspace_id
                GROUP BY w.workspace_id, tm.role
                ORDER BY w.name
                LIMIT :limit OFFSET :offset
            """
            params["user_id"] = user_id
        else:
            query = """
                SELECT w.*, COUNT(tm.member_id) as member_count
                FROM workspaces w
                LEFT JOIN team_members tm ON w.workspace_id = tm.workspace_id
                GROUP BY w.workspace_id
                ORDER BY w.name
                LIMIT :limit OFFSET :offset
            """

        params["limit"] = page_size
        params["offset"] = (page - 1) * page_size

        result = await self.db.execute(query, params)
        workspaces = [dict(row._mapping) for row in result.fetchall()]

        return {"workspaces": workspaces}

    async def update_workspace(
        self,
        workspace_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Optional[dict]:
        """Update workspace details."""
        updates = []
        params = {"workspace_id": workspace_id}

        if name:
            updates.append("name = :name")
            params["name"] = name

        if description is not None:
            updates.append("description = :description")
            params["description"] = description

        if not updates:
            return await self.get_workspace(workspace_id)

        updates.append("updated_at = :updated_at")
        params["updated_at"] = datetime.utcnow()

        query = f"""
            UPDATE workspaces
            SET {", ".join(updates)}
            WHERE workspace_id = :workspace_id
            RETURNING *
        """

        result = await self.db.execute(query, params)
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else None

    async def delete_workspace(self, workspace_id: str) -> bool:
        """Delete a workspace and all associated data."""
        # First remove all team members
        await self.db.execute(
            "DELETE FROM team_members WHERE workspace_id = :workspace_id",
            {"workspace_id": workspace_id}
        )

        # Delete workspace
        result = await self.db.execute(
            "DELETE FROM workspaces WHERE workspace_id = :workspace_id",
            {"workspace_id": workspace_id}
        )
        await self.db.commit()

        return result.rowcount > 0

    # ==================== Team Members ====================

    async def add_team_member(
        self,
        workspace_id: str,
        user_id: str,
        user_name: str,
        user_email: str,
        role: str = "viewer",
        invited_by_id: Optional[str] = None,
    ) -> dict:
        """Add a member to a workspace team."""
        if role not in self.ROLES:
            raise ValueError(f"Invalid role: {role}")

        member_id = str(uuid4())

        query = """
            INSERT INTO team_members (
                member_id, workspace_id, user_id, user_name, user_email,
                role, invited_by, joined_at
            ) VALUES (
                :member_id, :workspace_id, :user_id, :user_name, :user_email,
                :role, :invited_by, :joined_at
            )
            ON CONFLICT (workspace_id, user_id) DO UPDATE
            SET role = EXCLUDED.role, updated_at = :joined_at
            RETURNING *
        """

        result = await self.db.execute(query, {
            "member_id": member_id,
            "workspace_id": workspace_id,
            "user_id": user_id,
            "user_name": user_name,
            "user_email": user_email,
            "role": role,
            "invited_by": invited_by_id,
            "joined_at": datetime.utcnow(),
        })
        await self.db.commit()

        # Log activity
        await self._log_activity(
            workspace_id=workspace_id,
            user_id=invited_by_id or user_id,
            action="member_added",
            details={"new_member": user_name, "role": role},
        )

        row = result.fetchone()
        return dict(row._mapping)

    async def get_team_members(
        self,
        workspace_id: str,
        role: Optional[str] = None,
    ) -> list[dict]:
        """Get all team members for a workspace."""
        conditions = ["workspace_id = :workspace_id"]
        params = {"workspace_id": workspace_id}

        if role:
            conditions.append("role = :role")
            params["role"] = role

        query = f"""
            SELECT * FROM team_members
            WHERE {" AND ".join(conditions)}
            ORDER BY
                CASE role
                    WHEN 'owner' THEN 1
                    WHEN 'admin' THEN 2
                    WHEN 'analyst' THEN 3
                    WHEN 'developer' THEN 4
                    ELSE 5
                END,
                joined_at
        """

        result = await self.db.execute(query, params)
        return [dict(row._mapping) for row in result.fetchall()]

    async def update_member_role(
        self,
        workspace_id: str,
        user_id: str,
        new_role: str,
        updated_by_id: str,
    ) -> Optional[dict]:
        """Update a team member's role."""
        if new_role not in self.ROLES:
            raise ValueError(f"Invalid role: {new_role}")

        # Get current role
        current = await self.db.execute(
            """
            SELECT role FROM team_members
            WHERE workspace_id = :workspace_id AND user_id = :user_id
            """,
            {"workspace_id": workspace_id, "user_id": user_id}
        )
        current_row = current.fetchone()
        old_role = current_row[0] if current_row else None

        query = """
            UPDATE team_members
            SET role = :role, updated_at = :updated_at
            WHERE workspace_id = :workspace_id AND user_id = :user_id
            RETURNING *
        """

        result = await self.db.execute(query, {
            "workspace_id": workspace_id,
            "user_id": user_id,
            "role": new_role,
            "updated_at": datetime.utcnow(),
        })
        await self.db.commit()

        if old_role:
            await self._log_activity(
                workspace_id=workspace_id,
                user_id=updated_by_id,
                action="role_changed",
                details={"user_id": user_id, "old_role": old_role, "new_role": new_role},
            )

        row = result.fetchone()
        return dict(row._mapping) if row else None

    async def remove_team_member(
        self,
        workspace_id: str,
        user_id: str,
        removed_by_id: str,
    ) -> bool:
        """Remove a member from a workspace team."""
        # Check if trying to remove owner
        member = await self.db.execute(
            """
            SELECT role FROM team_members
            WHERE workspace_id = :workspace_id AND user_id = :user_id
            """,
            {"workspace_id": workspace_id, "user_id": user_id}
        )
        member_row = member.fetchone()

        if member_row and member_row[0] == "owner":
            # Count other owners
            owner_count = await self.db.execute(
                """
                SELECT COUNT(*) FROM team_members
                WHERE workspace_id = :workspace_id AND role = 'owner'
                """,
                {"workspace_id": workspace_id}
            )
            if owner_count.scalar() <= 1:
                raise ValueError("Cannot remove the only owner")

        result = await self.db.execute(
            """
            DELETE FROM team_members
            WHERE workspace_id = :workspace_id AND user_id = :user_id
            """,
            {"workspace_id": workspace_id, "user_id": user_id}
        )
        await self.db.commit()

        if result.rowcount > 0:
            await self._log_activity(
                workspace_id=workspace_id,
                user_id=removed_by_id,
                action="member_removed",
                details={"removed_user_id": user_id},
            )

        return result.rowcount > 0

    async def get_user_role(
        self,
        workspace_id: str,
        user_id: str,
    ) -> Optional[str]:
        """Get a user's role in a workspace."""
        result = await self.db.execute(
            """
            SELECT role FROM team_members
            WHERE workspace_id = :workspace_id AND user_id = :user_id
            """,
            {"workspace_id": workspace_id, "user_id": user_id}
        )
        row = result.fetchone()
        return row[0] if row else None

    async def check_permission(
        self,
        workspace_id: str,
        user_id: str,
        required_level: int,
    ) -> bool:
        """Check if user has required permission level."""
        role = await self.get_user_role(workspace_id, user_id)
        if not role:
            return False

        role_info = self.ROLES.get(role, {"level": 0})
        return role_info["level"] >= required_level

    # ==================== Activity Logging ====================

    async def _log_activity(
        self,
        workspace_id: str,
        user_id: str,
        action: str,
        details: Optional[dict] = None,
    ) -> None:
        """Log an activity in the audit log."""
        import json

        query = """
            INSERT INTO audit_log (
                log_id, workspace_id, user_id, action, details, created_at
            ) VALUES (
                :log_id, :workspace_id, :user_id, :action, :details, :created_at
            )
        """

        await self.db.execute(query, {
            "log_id": str(uuid4()),
            "workspace_id": workspace_id,
            "user_id": user_id,
            "action": action,
            "details": json.dumps(details) if details else None,
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

    async def get_activity_log(
        self,
        workspace_id: str,
        limit: int = 50,
    ) -> list[dict]:
        """Get activity log for a workspace."""
        query = """
            SELECT * FROM audit_log
            WHERE workspace_id = :workspace_id
            ORDER BY created_at DESC
            LIMIT :limit
        """

        result = await self.db.execute(query, {
            "workspace_id": workspace_id,
            "limit": limit,
        })

        import json
        activities = []
        for row in result.fetchall():
            item = dict(row._mapping)
            if item.get("details"):
                item["details"] = json.loads(item["details"])
            activities.append(item)

        return activities

    # ==================== Workspace Stats ====================

    async def get_workspace_stats(self, workspace_id: str) -> dict:
        """Get statistics for a workspace."""
        # This would need workspace_id on apps/findings tables
        # For now, return placeholder stats
        members_result = await self.db.execute(
            "SELECT COUNT(*) FROM team_members WHERE workspace_id = :workspace_id",
            {"workspace_id": workspace_id}
        )

        return {
            "workspace_id": workspace_id,
            "members_count": members_result.scalar() or 0,
            "apps_count": 0,  # Would query apps table
            "findings_count": 0,  # Would query findings table
            "scans_count": 0,  # Would query scans table
        }
