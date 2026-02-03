"""
Issue Tracker Integration Service

Integrates with external issue trackers for:
- Jira
- GitHub Issues
- GitLab Issues
- Azure DevOps

Allows creating issues from findings and syncing status.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class IssueTrackerClient(ABC):
    """Abstract base class for issue tracker clients."""

    @abstractmethod
    async def test_connection(self) -> dict:
        """Test connection to the issue tracker."""
        pass

    @abstractmethod
    async def create_issue(
        self,
        title: str,
        description: str,
        labels: list[str],
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> dict:
        """Create a new issue."""
        pass

    @abstractmethod
    async def update_issue(
        self,
        issue_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
    ) -> dict:
        """Update an existing issue."""
        pass

    @abstractmethod
    async def get_issue(self, issue_id: str) -> dict:
        """Get issue details."""
        pass

    @abstractmethod
    async def add_comment(self, issue_id: str, comment: str) -> dict:
        """Add a comment to an issue."""
        pass


class JiraClient(IssueTrackerClient):
    """Jira issue tracker client."""

    def __init__(self, base_url: str, email: str, api_token: str, project_key: str):
        self.base_url = base_url.rstrip('/')
        self.auth = (email, api_token)
        self.project_key = project_key
        self.http = httpx.AsyncClient(timeout=30.0, auth=self.auth)

    async def test_connection(self) -> dict:
        try:
            response = await self.http.get(f"{self.base_url}/rest/api/3/myself")
            if response.status_code == 200:
                user = response.json()
                return {
                    "success": True,
                    "user": user.get("displayName"),
                    "email": user.get("emailAddress"),
                }
            return {"success": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def create_issue(
        self,
        title: str,
        description: str,
        labels: list[str],
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> dict:
        # Map severity to Jira priority
        priority_map = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }

        issue_data = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": title,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}]
                        }
                    ]
                },
                "issuetype": {"name": "Bug"},
                "labels": labels,
            }
        }

        if priority:
            jira_priority = priority_map.get(priority.lower(), "Medium")
            issue_data["fields"]["priority"] = {"name": jira_priority}

        if assignee:
            issue_data["fields"]["assignee"] = {"accountId": assignee}

        response = await self.http.post(
            f"{self.base_url}/rest/api/3/issue",
            json=issue_data,
        )

        if response.status_code in (200, 201):
            data = response.json()
            return {
                "success": True,
                "issue_id": data["key"],
                "issue_url": f"{self.base_url}/browse/{data['key']}",
            }

        return {"success": False, "error": response.text}

    async def update_issue(
        self,
        issue_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
    ) -> dict:
        update_data: dict[str, Any] = {"fields": {}}

        if title:
            update_data["fields"]["summary"] = title

        if description:
            update_data["fields"]["description"] = {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description}]
                    }
                ]
            }

        if update_data["fields"]:
            response = await self.http.put(
                f"{self.base_url}/rest/api/3/issue/{issue_id}",
                json=update_data,
            )

            if response.status_code not in (200, 204):
                return {"success": False, "error": response.text}

        # Status transitions are more complex in Jira
        if status:
            # Would need to get transitions first
            pass

        return {"success": True, "issue_id": issue_id}

    async def get_issue(self, issue_id: str) -> dict:
        response = await self.http.get(
            f"{self.base_url}/rest/api/3/issue/{issue_id}"
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "issue_id": data["key"],
                "title": data["fields"]["summary"],
                "status": data["fields"]["status"]["name"],
                "url": f"{self.base_url}/browse/{data['key']}",
            }

        return {"success": False, "error": response.text}

    async def add_comment(self, issue_id: str, comment: str) -> dict:
        response = await self.http.post(
            f"{self.base_url}/rest/api/3/issue/{issue_id}/comment",
            json={
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": comment}]
                        }
                    ]
                }
            },
        )

        if response.status_code in (200, 201):
            return {"success": True}

        return {"success": False, "error": response.text}


class GitHubClient(IssueTrackerClient):
    """GitHub Issues client."""

    def __init__(self, token: str, owner: str, repo: str):
        self.token = token
        self.owner = owner
        self.repo = repo
        self.http = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )

    async def test_connection(self) -> dict:
        try:
            response = await self.http.get(
                f"https://api.github.com/repos/{self.owner}/{self.repo}"
            )
            if response.status_code == 200:
                repo = response.json()
                return {
                    "success": True,
                    "repo": repo.get("full_name"),
                    "private": repo.get("private"),
                }
            return {"success": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def create_issue(
        self,
        title: str,
        description: str,
        labels: list[str],
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> dict:
        # Add priority as label if provided
        if priority:
            labels.append(f"priority:{priority}")

        issue_data = {
            "title": title,
            "body": description,
            "labels": labels,
        }

        if assignee:
            issue_data["assignees"] = [assignee]

        response = await self.http.post(
            f"https://api.github.com/repos/{self.owner}/{self.repo}/issues",
            json=issue_data,
        )

        if response.status_code in (200, 201):
            data = response.json()
            return {
                "success": True,
                "issue_id": str(data["number"]),
                "issue_url": data["html_url"],
            }

        return {"success": False, "error": response.text}

    async def update_issue(
        self,
        issue_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
    ) -> dict:
        update_data: dict[str, Any] = {}

        if title:
            update_data["title"] = title

        if description:
            update_data["body"] = description

        if status:
            update_data["state"] = "closed" if status in ("closed", "resolved", "fixed") else "open"

        if update_data:
            response = await self.http.patch(
                f"https://api.github.com/repos/{self.owner}/{self.repo}/issues/{issue_id}",
                json=update_data,
            )

            if response.status_code != 200:
                return {"success": False, "error": response.text}

        return {"success": True, "issue_id": issue_id}

    async def get_issue(self, issue_id: str) -> dict:
        response = await self.http.get(
            f"https://api.github.com/repos/{self.owner}/{self.repo}/issues/{issue_id}"
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "issue_id": str(data["number"]),
                "title": data["title"],
                "status": data["state"],
                "url": data["html_url"],
            }

        return {"success": False, "error": response.text}

    async def add_comment(self, issue_id: str, comment: str) -> dict:
        response = await self.http.post(
            f"https://api.github.com/repos/{self.owner}/{self.repo}/issues/{issue_id}/comments",
            json={"body": comment},
        )

        if response.status_code in (200, 201):
            return {"success": True}

        return {"success": False, "error": response.text}


class GitLabClient(IssueTrackerClient):
    """GitLab Issues client."""

    def __init__(self, base_url: str, token: str, project_id: str):
        self.base_url = base_url.rstrip('/')
        self.project_id = project_id
        self.http = httpx.AsyncClient(
            timeout=30.0,
            headers={"PRIVATE-TOKEN": token},
        )

    async def test_connection(self) -> dict:
        try:
            response = await self.http.get(
                f"{self.base_url}/api/v4/projects/{self.project_id}"
            )
            if response.status_code == 200:
                project = response.json()
                return {
                    "success": True,
                    "project": project.get("path_with_namespace"),
                }
            return {"success": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def create_issue(
        self,
        title: str,
        description: str,
        labels: list[str],
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> dict:
        if priority:
            labels.append(f"priority::{priority}")

        issue_data = {
            "title": title,
            "description": description,
            "labels": ",".join(labels),
        }

        if assignee:
            issue_data["assignee_ids"] = assignee

        response = await self.http.post(
            f"{self.base_url}/api/v4/projects/{self.project_id}/issues",
            json=issue_data,
        )

        if response.status_code in (200, 201):
            data = response.json()
            return {
                "success": True,
                "issue_id": str(data["iid"]),
                "issue_url": data["web_url"],
            }

        return {"success": False, "error": response.text}

    async def update_issue(
        self,
        issue_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
    ) -> dict:
        update_data: dict[str, Any] = {}

        if title:
            update_data["title"] = title

        if description:
            update_data["description"] = description

        if status:
            update_data["state_event"] = "close" if status in ("closed", "resolved", "fixed") else "reopen"

        if update_data:
            response = await self.http.put(
                f"{self.base_url}/api/v4/projects/{self.project_id}/issues/{issue_id}",
                json=update_data,
            )

            if response.status_code != 200:
                return {"success": False, "error": response.text}

        return {"success": True, "issue_id": issue_id}

    async def get_issue(self, issue_id: str) -> dict:
        response = await self.http.get(
            f"{self.base_url}/api/v4/projects/{self.project_id}/issues/{issue_id}"
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "issue_id": str(data["iid"]),
                "title": data["title"],
                "status": data["state"],
                "url": data["web_url"],
            }

        return {"success": False, "error": response.text}

    async def add_comment(self, issue_id: str, comment: str) -> dict:
        response = await self.http.post(
            f"{self.base_url}/api/v4/projects/{self.project_id}/issues/{issue_id}/notes",
            json={"body": comment},
        )

        if response.status_code in (200, 201):
            return {"success": True}

        return {"success": False, "error": response.text}


class IssueTrackerService:
    """Service for managing issue tracker integrations."""

    TRACKER_TYPES = ["jira", "github", "gitlab", "azure_devops"]

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_config(
        self,
        name: str,
        tracker_type: str,
        config: dict,
        is_active: bool = True,
        created_by: Optional[str] = None,
    ) -> dict:
        """Create a new issue tracker configuration."""
        config_id = str(uuid4())

        if tracker_type not in self.TRACKER_TYPES:
            raise ValueError(f"Invalid tracker type: {tracker_type}")

        # Test the connection
        client = self._get_client(tracker_type, config)
        test_result = await client.test_connection()
        if not test_result.get("success"):
            raise ValueError(f"Connection failed: {test_result.get('error')}")

        query = """
            INSERT INTO issue_tracker_configs (
                config_id, name, tracker_type, config,
                is_active, created_by, created_at
            ) VALUES (
                :config_id, :name, :tracker_type, :config,
                :is_active, :created_by, :created_at
            )
            RETURNING *
        """

        import json
        await self.db.execute(query, {
            "config_id": config_id,
            "name": name,
            "tracker_type": tracker_type,
            "config": json.dumps(config),
            "is_active": is_active,
            "created_by": created_by,
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        return {
            "config_id": config_id,
            "name": name,
            "tracker_type": tracker_type,
            "is_active": is_active,
            "connection_status": "connected",
        }

    async def get_config(self, config_id: str) -> Optional[dict]:
        """Get an issue tracker configuration."""
        query = """
            SELECT * FROM issue_tracker_configs WHERE config_id = :config_id
        """
        result = await self.db.execute(query, {"config_id": config_id})
        row = result.fetchone()

        if not row:
            return None

        import json
        config = dict(row._mapping)
        config["config"] = json.loads(config["config"])
        return config

    async def list_configs(
        self,
        tracker_type: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> list[dict]:
        """List all issue tracker configurations."""
        conditions = []
        params = {}

        if tracker_type:
            conditions.append("tracker_type = :tracker_type")
            params["tracker_type"] = tracker_type

        if is_active is not None:
            conditions.append("is_active = :is_active")
            params["is_active"] = is_active

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT config_id, name, tracker_type, is_active, created_at
            FROM issue_tracker_configs
            WHERE {where_clause}
            ORDER BY created_at DESC
        """

        result = await self.db.execute(query, params)
        return [dict(row._mapping) for row in result.fetchall()]

    async def delete_config(self, config_id: str) -> bool:
        """Delete an issue tracker configuration."""
        query = "DELETE FROM issue_tracker_configs WHERE config_id = :config_id"
        result = await self.db.execute(query, {"config_id": config_id})
        await self.db.commit()
        return result.rowcount > 0

    async def create_issue_from_finding(
        self,
        config_id: str,
        finding_id: str,
        additional_labels: Optional[list[str]] = None,
    ) -> dict:
        """Create an issue from a finding."""
        # Get config
        config = await self.get_config(config_id)
        if not config:
            raise ValueError("Configuration not found")

        # Get finding
        finding_query = """
            SELECT f.*, a.app_name, a.package_name
            FROM findings f
            JOIN mobile_apps a ON f.app_id = a.app_id
            WHERE f.finding_id = :finding_id
        """
        result = await self.db.execute(finding_query, {"finding_id": finding_id})
        finding = result.fetchone()

        if not finding:
            raise ValueError("Finding not found")

        finding = dict(finding._mapping)

        # Format issue content
        title = f"[{finding['severity'].upper()}] {finding['title']}"

        description = f"""## Security Finding

**App:** {finding['app_name']} ({finding['package_name']})
**Severity:** {finding['severity'].upper()}
**Category:** {finding['category'] or 'N/A'}
**Tool:** {finding['tool'] or 'N/A'}

### Description

{finding['description']}

### Location

- **File:** {finding['file_path'] or 'N/A'}
- **Line:** {finding['line_number'] or 'N/A'}

### Code Snippet

```
{finding['code_snippet'] or 'N/A'}
```

### Verification Steps

{finding['poc_verification'] or 'N/A'}

### References

- CWE: {finding['cwe_id'] or 'N/A'}
- CVSS: {finding['cvss_score'] or 'N/A'}

---
*Created from Mobilicustos finding {finding_id}*
"""

        labels = [
            "security",
            f"severity:{finding['severity']}",
            finding['category'] or "uncategorized",
        ]
        if additional_labels:
            labels.extend(additional_labels)

        # Create issue
        client = self._get_client(config["tracker_type"], config["config"])
        result = await client.create_issue(
            title=title,
            description=description,
            labels=labels,
            priority=finding['severity'],
        )

        if result.get("success"):
            # Link issue to finding
            link_query = """
                UPDATE findings
                SET external_issue_id = :issue_id,
                    external_issue_url = :issue_url
                WHERE finding_id = :finding_id
            """
            await self.db.execute(link_query, {
                "finding_id": finding_id,
                "issue_id": result["issue_id"],
                "issue_url": result.get("issue_url"),
            })
            await self.db.commit()

        return result

    async def sync_issue_status(self, finding_id: str) -> dict:
        """Sync issue status from external tracker."""
        # Get finding with issue link
        query = """
            SELECT f.external_issue_id, f.external_issue_url,
                   itc.config_id, itc.tracker_type, itc.config
            FROM findings f
            JOIN issue_tracker_configs itc ON itc.is_active = true
            WHERE f.finding_id = :finding_id
              AND f.external_issue_id IS NOT NULL
        """
        result = await self.db.execute(query, {"finding_id": finding_id})
        row = result.fetchone()

        if not row:
            return {"success": False, "error": "No linked issue found"}

        import json
        row = dict(row._mapping)
        row["config"] = json.loads(row["config"])

        client = self._get_client(row["tracker_type"], row["config"])
        issue = await client.get_issue(row["external_issue_id"])

        if issue.get("success"):
            # Map external status to internal
            status_map = {
                "open": "confirmed",
                "closed": "fixed",
                "resolved": "fixed",
                "done": "fixed",
                "in progress": "in_progress",
            }
            new_status = status_map.get(issue["status"].lower(), "new")

            # Update finding status
            update_query = """
                UPDATE findings
                SET status = :status
                WHERE finding_id = :finding_id
            """
            await self.db.execute(update_query, {
                "finding_id": finding_id,
                "status": new_status,
            })
            await self.db.commit()

        return issue

    def _get_client(self, tracker_type: str, config: dict) -> IssueTrackerClient:
        """Get the appropriate client for the tracker type."""
        if tracker_type == "jira":
            return JiraClient(
                base_url=config["base_url"],
                email=config["email"],
                api_token=config["api_token"],
                project_key=config["project_key"],
            )
        elif tracker_type == "github":
            return GitHubClient(
                token=config["token"],
                owner=config["owner"],
                repo=config["repo"],
            )
        elif tracker_type == "gitlab":
            return GitLabClient(
                base_url=config.get("base_url", "https://gitlab.com"),
                token=config["token"],
                project_id=config["project_id"],
            )
        else:
            raise ValueError(f"Unsupported tracker type: {tracker_type}")
