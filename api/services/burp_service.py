"""
Burp Suite Pro Integration Service

Integrates with Burp Suite Professional's REST API for:
- Connection management
- Scan management (active/passive)
- Issue synchronization
- Proxy history import
- Configuration management
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class BurpService:
    """Service for Burp Suite Pro integration."""

    # Burp issue severity mapping
    SEVERITY_MAP = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "information": "info",
        "info": "info",
    }

    # Burp confidence mapping
    CONFIDENCE_MAP = {
        "certain": "confirmed",
        "firm": "likely",
        "tentative": "possible",
    }

    def __init__(self, db: AsyncSession):
        self.db = db
        self.http_client = httpx.AsyncClient(timeout=60.0, verify=False)

    async def create_connection(
        self,
        name: str,
        api_url: str,
        api_key: str,
        is_active: bool = True,
        created_by: Optional[str] = None,
    ) -> dict:
        """
        Create a new Burp Suite connection.

        Args:
            name: Name for this connection
            api_url: Burp REST API URL (e.g., http://localhost:1337)
            api_key: Burp API key
            is_active: Whether the connection is active
            created_by: User who created the connection

        Returns:
            Created connection details
        """
        connection_id = str(uuid4())

        # Test the connection
        test_result = await self._test_connection(api_url, api_key)
        if not test_result["success"]:
            raise ValueError(f"Connection failed: {test_result['error']}")

        query = text("""
            INSERT INTO burp_connections (
                connection_id, name, api_url, api_key, is_active,
                burp_version, created_by, created_at, last_connected_at
            ) VALUES (
                :connection_id, :name, :api_url, :api_key, :is_active,
                :burp_version, :created_by, :created_at, :last_connected_at
            )
            RETURNING *
        """)

        result = await self.db.execute(query, {
            "connection_id": connection_id,
            "name": name,
            "api_url": api_url,
            "api_key": api_key,
            "is_active": is_active,
            "burp_version": test_result.get("version"),
            "created_by": created_by,
            "created_at": datetime.utcnow(),
            "last_connected_at": datetime.utcnow(),
        })

        await self.db.commit()

        return {
            "connection_id": connection_id,
            "name": name,
            "api_url": api_url,
            "is_active": is_active,
            "burp_version": test_result.get("version"),
            "status": "connected",
        }

    async def _test_connection(self, api_url: str, api_key: str) -> dict:
        """Test connection to Burp Suite."""
        try:
            headers = {"Authorization": api_key}

            # Try to get Burp version info
            response = await self.http_client.get(
                f"{api_url}/burp/versions",
                headers=headers,
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "version": data.get("burpVersion", "Unknown"),
                }
            else:
                return {
                    "success": False,
                    "error": f"API returned status {response.status_code}",
                }

        except httpx.ConnectError:
            return {"success": False, "error": "Connection refused"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_connection(self, connection_id: str) -> Optional[dict]:
        """Get a Burp connection by ID."""
        query = text("""
            SELECT * FROM burp_connections WHERE connection_id = :connection_id
        """)
        result = await self.db.execute(query, {"connection_id": connection_id})
        row = result.fetchone()
        return dict(row._mapping) if row else None

    async def list_connections(
        self,
        is_active: Optional[bool] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List all Burp connections."""
        conditions = []
        params = {}

        if is_active is not None:
            conditions.append("is_active = :is_active")
            params["is_active"] = is_active

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # Count
        count_query = text(f"SELECT COUNT(*) FROM burp_connections WHERE {where_clause}")
        count_result = await self.db.execute(count_query, params)
        total = count_result.scalar()

        # Data
        offset = (page - 1) * page_size
        data_query = text(f"""
            SELECT connection_id, name, api_url, is_active, burp_version,
                   last_connected_at, created_at
            FROM burp_connections
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """)
        params["limit"] = page_size
        params["offset"] = offset

        result = await self.db.execute(data_query, params)
        connections = [dict(row._mapping) for row in result.fetchall()]

        return {
            "items": connections,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    async def delete_connection(self, connection_id: str) -> bool:
        """Delete a Burp connection."""
        query = text("DELETE FROM burp_connections WHERE connection_id = :connection_id")
        result = await self.db.execute(query, {"connection_id": connection_id})
        await self.db.commit()
        return result.rowcount > 0

    async def start_scan(
        self,
        connection_id: str,
        target_urls: list[str],
        app_id: Optional[str] = None,
        scan_config: Optional[str] = None,
        resource_pool: Optional[str] = None,
    ) -> dict:
        """
        Start a Burp scan.

        Args:
            connection_id: Burp connection to use
            target_urls: URLs to scan
            app_id: Associated Mobilicustos app ID
            scan_config: Named scan configuration to use
            resource_pool: Named resource pool to use

        Returns:
            Scan task details
        """
        connection = await self.get_connection(connection_id)
        if not connection:
            raise ValueError("Connection not found")

        headers = {"Authorization": connection["api_key"]}

        # Prepare scan request
        scan_request = {
            "urls": target_urls,
        }

        if scan_config:
            scan_request["scan_configurations"] = [{"name": scan_config}]

        if resource_pool:
            scan_request["resource_pool"] = resource_pool

        # Start the scan
        try:
            response = await self.http_client.post(
                f"{connection['api_url']}/burp/scanner/scans",
                json=scan_request,
                headers=headers,
            )

            if response.status_code not in (200, 201):
                raise ValueError(f"Failed to start scan: {response.text}")

            data = response.json()
            burp_task_id = data.get("task_id")

        except httpx.ConnectError:
            raise ValueError("Connection to Burp Suite failed")

        # Save scan task
        task_id = str(uuid4())

        query = text("""
            INSERT INTO burp_scan_tasks (
                task_id, connection_id, burp_task_id, app_id,
                target_urls, status, created_at
            ) VALUES (
                :task_id, :connection_id, :burp_task_id, :app_id,
                :target_urls, :status, :created_at
            )
            RETURNING *
        """)

        await self.db.execute(query, {
            "task_id": task_id,
            "connection_id": connection_id,
            "burp_task_id": str(burp_task_id),
            "app_id": app_id,
            "target_urls": target_urls,
            "status": "running",
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        return {
            "task_id": task_id,
            "burp_task_id": burp_task_id,
            "target_urls": target_urls,
            "status": "running",
        }

    async def get_scan_status(self, task_id: str) -> dict:
        """Get status of a Burp scan."""
        # Get task from database
        task_query = text("""
            SELECT t.*, c.api_url, c.api_key
            FROM burp_scan_tasks t
            JOIN burp_connections c ON t.connection_id = c.connection_id
            WHERE t.task_id = :task_id
        """)
        result = await self.db.execute(task_query, {"task_id": task_id})
        task = result.fetchone()

        if not task:
            raise ValueError("Scan task not found")

        task = dict(task._mapping)

        # Query Burp for status
        headers = {"Authorization": task["api_key"]}

        try:
            response = await self.http_client.get(
                f"{task['api_url']}/burp/scanner/scans/{task['burp_task_id']}",
                headers=headers,
            )

            if response.status_code == 200:
                data = response.json()
                burp_status = data.get("scan_status", "unknown")

                # Map Burp status to our status
                status_map = {
                    "succeeded": "completed",
                    "failed": "failed",
                    "paused": "paused",
                    "running": "running",
                    "queued": "queued",
                }
                status = status_map.get(burp_status, burp_status)

                # Update status in database
                await self.db.execute(
                    text("UPDATE burp_scan_tasks SET status = :status WHERE task_id = :task_id"),
                    {"task_id": task_id, "status": status}
                )
                await self.db.commit()

                return {
                    "task_id": task_id,
                    "burp_task_id": task["burp_task_id"],
                    "status": status,
                    "issues_count": data.get("issue_events", 0),
                    "requests_made": data.get("request_count", 0),
                    "percent_complete": data.get("scan_metrics", {}).get("crawl_and_audit_progress", 0),
                }

        except Exception as e:
            logger.error(f"Error getting scan status: {e}")

        return {
            "task_id": task_id,
            "status": task.get("status", "unknown"),
            "error": "Failed to get status from Burp",
        }

    async def stop_scan(self, task_id: str) -> dict:
        """Stop a running Burp scan."""
        task_query = text("""
            SELECT t.*, c.api_url, c.api_key
            FROM burp_scan_tasks t
            JOIN burp_connections c ON t.connection_id = c.connection_id
            WHERE t.task_id = :task_id
        """)
        result = await self.db.execute(task_query, {"task_id": task_id})
        task = result.fetchone()

        if not task:
            raise ValueError("Scan task not found")

        task = dict(task._mapping)
        headers = {"Authorization": task["api_key"]}

        try:
            response = await self.http_client.delete(
                f"{task['api_url']}/burp/scanner/scans/{task['burp_task_id']}",
                headers=headers,
            )

            # Update status
            await self.db.execute(
                text("UPDATE burp_scan_tasks SET status = 'stopped' WHERE task_id = :task_id"),
                {"task_id": task_id}
            )
            await self.db.commit()

            return {"task_id": task_id, "status": "stopped"}

        except Exception as e:
            raise ValueError(f"Failed to stop scan: {e}")

    async def import_issues(
        self,
        task_id: str,
        app_id: Optional[str] = None,
    ) -> dict:
        """
        Import issues from a Burp scan into Mobilicustos findings.

        Args:
            task_id: Burp scan task ID
            app_id: Optional app ID to associate findings with

        Returns:
            Import statistics
        """
        task_query = text("""
            SELECT t.*, c.api_url, c.api_key
            FROM burp_scan_tasks t
            JOIN burp_connections c ON t.connection_id = c.connection_id
            WHERE t.task_id = :task_id
        """)
        result = await self.db.execute(task_query, {"task_id": task_id})
        task = result.fetchone()

        if not task:
            raise ValueError("Scan task not found")

        task = dict(task._mapping)
        app_id = app_id or task.get("app_id")
        headers = {"Authorization": task["api_key"]}

        # Get issues from Burp
        try:
            response = await self.http_client.get(
                f"{task['api_url']}/burp/scanner/scans/{task['burp_task_id']}/issues",
                headers=headers,
            )

            if response.status_code != 200:
                raise ValueError(f"Failed to get issues: {response.text}")

            issues = response.json().get("issue_events", [])

        except Exception as e:
            raise ValueError(f"Failed to get issues from Burp: {e}")

        # Import each issue
        imported = 0
        skipped = 0

        for issue in issues:
            issue_data = issue.get("issue", {})

            # Check if already imported
            check_query = text("""
                SELECT 1 FROM burp_issues WHERE burp_issue_id = :burp_issue_id
            """)
            existing = await self.db.execute(check_query, {
                "burp_issue_id": str(issue_data.get("serial_number", "")),
            })

            if existing.fetchone():
                skipped += 1
                continue

            # Map severity
            severity = self.SEVERITY_MAP.get(
                issue_data.get("severity", "").lower(),
                "info"
            )

            # Map confidence
            confidence = self.CONFIDENCE_MAP.get(
                issue_data.get("confidence", "").lower(),
                "possible"
            )

            # Create finding
            finding_id = str(uuid4())
            burp_issue_id = str(uuid4())

            # Insert into findings
            if app_id:
                finding_query = text("""
                    INSERT INTO findings (
                        finding_id, app_id, title, description, severity,
                        category, file_path, tool, status, cwe_id,
                        poc_evidence, poc_verification, created_at
                    ) VALUES (
                        :finding_id, :app_id, :title, :description, :severity,
                        :category, :file_path, :tool, :status, :cwe_id,
                        :poc_evidence, :poc_verification, :created_at
                    )
                """)

                await self.db.execute(finding_query, {
                    "finding_id": finding_id,
                    "app_id": app_id,
                    "title": issue_data.get("name", "Burp Issue"),
                    "description": self._clean_html(issue_data.get("issue_detail", "")),
                    "severity": severity,
                    "category": "MASVS-NETWORK",
                    "file_path": issue_data.get("origin", ""),
                    "tool": "burp_suite",
                    "status": "new",
                    "cwe_id": self._extract_cwe(issue_data.get("type_index", 0)),
                    "poc_evidence": issue_data.get("evidence", []),
                    "poc_verification": self._clean_html(issue_data.get("remediation_detail", "")),
                    "created_at": datetime.utcnow(),
                })

            # Insert into burp_issues for tracking
            burp_issue_query = text("""
                INSERT INTO burp_issues (
                    issue_id, task_id, finding_id, burp_issue_id,
                    name, severity, confidence, url, path,
                    issue_type, issue_detail, remediation,
                    created_at
                ) VALUES (
                    :issue_id, :task_id, :finding_id, :burp_issue_id,
                    :name, :severity, :confidence, :url, :path,
                    :issue_type, :issue_detail, :remediation,
                    :created_at
                )
            """)

            await self.db.execute(burp_issue_query, {
                "issue_id": burp_issue_id,
                "task_id": task_id,
                "finding_id": finding_id if app_id else None,
                "burp_issue_id": str(issue_data.get("serial_number", "")),
                "name": issue_data.get("name", ""),
                "severity": severity,
                "confidence": confidence,
                "url": issue_data.get("origin", ""),
                "path": issue_data.get("path", ""),
                "issue_type": issue_data.get("type_index", 0),
                "issue_detail": issue_data.get("issue_detail", "")[:5000],
                "remediation": issue_data.get("remediation_detail", "")[:5000],
                "created_at": datetime.utcnow(),
            })

            imported += 1

        await self.db.commit()

        return {
            "task_id": task_id,
            "imported": imported,
            "skipped": skipped,
            "total": len(issues),
        }

    async def get_proxy_history(
        self,
        connection_id: str,
        limit: int = 100,
    ) -> list[dict]:
        """Get proxy history from Burp."""
        connection = await self.get_connection(connection_id)
        if not connection:
            raise ValueError("Connection not found")

        headers = {"Authorization": connection["api_key"]}

        try:
            response = await self.http_client.get(
                f"{connection['api_url']}/burp/proxy/history",
                headers=headers,
            )

            if response.status_code != 200:
                raise ValueError(f"Failed to get proxy history: {response.text}")

            items = response.json()[:limit]

            return [
                {
                    "id": item.get("id"),
                    "method": item.get("method"),
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "mime_type": item.get("mime_type"),
                    "comment": item.get("comment"),
                }
                for item in items
            ]

        except Exception as e:
            raise ValueError(f"Failed to get proxy history: {e}")

    async def import_proxy_history(
        self,
        connection_id: str,
        app_id: str,
        item_ids: Optional[list[int]] = None,
    ) -> dict:
        """
        Import proxy history items into Mobilicustos.

        Args:
            connection_id: Burp connection ID
            app_id: App ID to associate requests with
            item_ids: Specific items to import (None = all)

        Returns:
            Import statistics
        """
        connection = await self.get_connection(connection_id)
        if not connection:
            raise ValueError("Connection not found")

        headers = {"Authorization": connection["api_key"]}

        try:
            response = await self.http_client.get(
                f"{connection['api_url']}/burp/proxy/history",
                headers=headers,
            )

            if response.status_code != 200:
                raise ValueError("Failed to get proxy history")

            items = response.json()

            if item_ids:
                items = [i for i in items if i.get("id") in item_ids]

        except Exception as e:
            raise ValueError(f"Failed to get proxy history: {e}")

        imported = 0

        for item in items:
            # Get full request/response
            try:
                item_response = await self.http_client.get(
                    f"{connection['api_url']}/burp/proxy/history/{item['id']}",
                    headers=headers,
                )

                if item_response.status_code == 200:
                    item_detail = item_response.json()

                    # Insert into burp_proxy_history
                    query = text("""
                        INSERT INTO burp_proxy_history (
                            history_id, connection_id, app_id, burp_item_id,
                            method, url, status_code, content_length,
                            mime_type, request_headers, response_headers,
                            created_at
                        ) VALUES (
                            :history_id, :connection_id, :app_id, :burp_item_id,
                            :method, :url, :status_code, :content_length,
                            :mime_type, :request_headers, :response_headers,
                            :created_at
                        )
                    """)

                    await self.db.execute(query, {
                        "history_id": str(uuid4()),
                        "connection_id": connection_id,
                        "app_id": app_id,
                        "burp_item_id": item.get("id"),
                        "method": item.get("method"),
                        "url": item.get("url"),
                        "status_code": item.get("status"),
                        "content_length": item.get("length"),
                        "mime_type": item.get("mime_type"),
                        "request_headers": item_detail.get("request", {}).get("headers"),
                        "response_headers": item_detail.get("response", {}).get("headers"),
                        "created_at": datetime.utcnow(),
                    })

                    imported += 1

            except Exception as e:
                logger.warning(f"Failed to import proxy item {item.get('id')}: {e}")

        await self.db.commit()

        return {
            "imported": imported,
            "total": len(items),
        }

    async def get_scan_configurations(self, connection_id: str) -> list[dict]:
        """Get available scan configurations from Burp."""
        connection = await self.get_connection(connection_id)
        if not connection:
            raise ValueError("Connection not found")

        headers = {"Authorization": connection["api_key"]}

        try:
            response = await self.http_client.get(
                f"{connection['api_url']}/burp/scanner/configurations",
                headers=headers,
            )

            if response.status_code == 200:
                return response.json()

        except Exception as e:
            logger.error(f"Failed to get scan configurations: {e}")

        return []

    def _clean_html(self, html: str) -> str:
        """Remove HTML tags from string."""
        import re
        clean = re.sub(r'<[^>]+>', '', html)
        return clean.strip()

    def _extract_cwe(self, type_index: int) -> Optional[str]:
        """Map Burp issue type to CWE."""
        # Common Burp issue types to CWE mapping
        cwe_map = {
            1048832: "CWE-89",   # SQL injection
            1049088: "CWE-79",   # XSS
            1049344: "CWE-611",  # XXE
            1049600: "CWE-22",   # Path traversal
            1049856: "CWE-918",  # SSRF
            1050112: "CWE-94",   # Code injection
            1050368: "CWE-78",   # OS command injection
            2097408: "CWE-200",  # Information disclosure
            2097920: "CWE-614",  # Cookie without Secure flag
            2098176: "CWE-1004", # Cookie without HttpOnly
        }
        return cwe_map.get(type_index)
