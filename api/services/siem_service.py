"""
SIEM/SOAR Integration Service

Integrates with Security Information and Event Management systems:
- Splunk
- Elastic SIEM
- Microsoft Sentinel
- IBM QRadar
- Sumo Logic

Exports findings and events for security correlation.
"""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class SIEMClient(ABC):
    """Abstract base class for SIEM clients."""

    @abstractmethod
    async def test_connection(self) -> dict:
        """Test connection to SIEM."""
        pass

    @abstractmethod
    async def send_event(self, event: dict) -> dict:
        """Send an event to SIEM."""
        pass

    @abstractmethod
    async def send_batch(self, events: list[dict]) -> dict:
        """Send batch of events to SIEM."""
        pass


class SplunkClient(SIEMClient):
    """Splunk HEC (HTTP Event Collector) client."""

    def __init__(self, hec_url: str, token: str, index: str = "main", source: str = "mobilicustos", verify_ssl: bool = False):
        self.hec_url = hec_url.rstrip('/')
        self.token = token
        self.index = index
        self.source = source
        self.http = httpx.AsyncClient(
            timeout=30.0,
            headers={"Authorization": f"Splunk {token}"},
            verify=verify_ssl,  # Configurable SSL verification (default False for self-signed certs)
        )

    async def test_connection(self) -> dict:
        try:
            # Send a test event
            response = await self.http.post(
                f"{self.hec_url}/services/collector/event",
                json={
                    "event": {"test": True, "source": "mobilicustos"},
                    "index": self.index,
                    "source": self.source,
                },
            )

            if response.status_code == 200:
                return {"success": True, "message": "Connected to Splunk"}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def send_event(self, event: dict) -> dict:
        payload = {
            "event": event,
            "index": self.index,
            "source": self.source,
            "sourcetype": "_json",
            "time": datetime.utcnow().timestamp(),
        }

        try:
            response = await self.http.post(
                f"{self.hec_url}/services/collector/event",
                json=payload,
            )

            if response.status_code == 200:
                return {"success": True}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def send_batch(self, events: list[dict]) -> dict:
        # Splunk HEC accepts newline-delimited JSON
        payload = "\n".join([
            json.dumps({
                "event": event,
                "index": self.index,
                "source": self.source,
                "sourcetype": "_json",
                "time": datetime.utcnow().timestamp(),
            })
            for event in events
        ])

        try:
            response = await self.http.post(
                f"{self.hec_url}/services/collector/event",
                content=payload,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                return {"success": True, "count": len(events)}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}


class ElasticClient(SIEMClient):
    """Elasticsearch/Elastic SIEM client."""

    def __init__(self, url: str, api_key: str, index_prefix: str = "mobilicustos"):
        self.url = url.rstrip('/')
        self.index_prefix = index_prefix
        self.http = httpx.AsyncClient(
            timeout=30.0,
            headers={"Authorization": f"ApiKey {api_key}"},
        )

    async def test_connection(self) -> dict:
        try:
            response = await self.http.get(f"{self.url}/_cluster/health")

            if response.status_code == 200:
                health = response.json()
                return {
                    "success": True,
                    "cluster": health.get("cluster_name"),
                    "status": health.get("status"),
                }
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def send_event(self, event: dict) -> dict:
        index_name = f"{self.index_prefix}-{datetime.utcnow().strftime('%Y.%m.%d')}"
        event["@timestamp"] = datetime.utcnow().isoformat()

        try:
            response = await self.http.post(
                f"{self.url}/{index_name}/_doc",
                json=event,
            )

            if response.status_code in (200, 201):
                data = response.json()
                return {"success": True, "id": data.get("_id")}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def send_batch(self, events: list[dict]) -> dict:
        index_name = f"{self.index_prefix}-{datetime.utcnow().strftime('%Y.%m.%d')}"

        # Build bulk request body
        bulk_body = []
        for event in events:
            event["@timestamp"] = datetime.utcnow().isoformat()
            bulk_body.append(json.dumps({"index": {"_index": index_name}}))
            bulk_body.append(json.dumps(event))

        try:
            response = await self.http.post(
                f"{self.url}/_bulk",
                content="\n".join(bulk_body) + "\n",
                headers={"Content-Type": "application/x-ndjson"},
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": not data.get("errors", False),
                    "count": len(events),
                }
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}


class SentinelClient(SIEMClient):
    """Microsoft Sentinel (Azure Log Analytics) client."""

    def __init__(self, workspace_id: str, shared_key: str, log_type: str = "MobilicustosFindings"):
        self.workspace_id = workspace_id
        self.shared_key = shared_key
        self.log_type = log_type
        self.url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        self.http = httpx.AsyncClient(timeout=30.0)

    def _build_signature(self, date: str, content_length: int, content_type: str) -> str:
        """Build Azure Log Analytics signature."""
        import base64
        import hashlib
        import hmac

        method = "POST"
        resource = "/api/logs"

        string_to_hash = f"{method}\n{content_length}\n{content_type}\nx-ms-date:{date}\n{resource}"
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(self.shared_key)

        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode("utf-8")

        return f"SharedKey {self.workspace_id}:{encoded_hash}"

    async def test_connection(self) -> dict:
        # Send a test event
        return await self.send_event({"test": True})

    async def send_event(self, event: dict) -> dict:
        return await self.send_batch([event])

    async def send_batch(self, events: list[dict]) -> dict:
        from email.utils import formatdate

        body = json.dumps(events)
        content_length = len(body)
        rfc1123_date = formatdate(timeval=None, localtime=False, usegmt=True)

        signature = self._build_signature(rfc1123_date, content_length, "application/json")

        headers = {
            "Content-Type": "application/json",
            "Authorization": signature,
            "Log-Type": self.log_type,
            "x-ms-date": rfc1123_date,
        }

        try:
            response = await self.http.post(self.url, content=body, headers=headers)

            if response.status_code in (200, 202):
                return {"success": True, "count": len(events)}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}


class SIEMService:
    """Service for SIEM/SOAR integrations."""

    SIEM_TYPES = ["splunk", "elastic", "sentinel", "qradar", "sumo_logic"]

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_config(
        self,
        name: str,
        siem_type: str,
        config: dict,
        is_active: bool = True,
        auto_export: bool = False,
        export_severity: list[str] = None,
    ) -> dict:
        """Create a SIEM configuration."""
        config_id = str(uuid4())

        if siem_type not in self.SIEM_TYPES:
            raise ValueError(f"Unsupported SIEM type: {siem_type}")

        # Test connection
        client = self._get_client(siem_type, config)
        test_result = await client.test_connection()
        if not test_result.get("success"):
            raise ValueError(f"Connection failed: {test_result.get('error')}")

        query = """
            INSERT INTO siem_configs (
                config_id, name, siem_type, config, is_active,
                auto_export, export_severity, created_at
            ) VALUES (
                :config_id, :name, :siem_type, :config, :is_active,
                :auto_export, :export_severity, :created_at
            )
            RETURNING *
        """

        await self.db.execute(query, {
            "config_id": config_id,
            "name": name,
            "siem_type": siem_type,
            "config": json.dumps(config),
            "is_active": is_active,
            "auto_export": auto_export,
            "export_severity": export_severity or ["critical", "high"],
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        return {
            "config_id": config_id,
            "name": name,
            "siem_type": siem_type,
            "is_active": is_active,
            "auto_export": auto_export,
            "connection_status": "connected",
        }

    async def get_config(self, config_id: str) -> Optional[dict]:
        """Get a SIEM configuration."""
        query = "SELECT * FROM siem_configs WHERE config_id = :config_id"
        result = await self.db.execute(query, {"config_id": config_id})
        row = result.fetchone()

        if not row:
            return None

        config = dict(row._mapping)
        config["config"] = json.loads(config["config"])
        return config

    async def list_configs(self) -> list[dict]:
        """List all SIEM configurations."""
        query = """
            SELECT config_id, name, siem_type, is_active, auto_export,
                   export_severity, last_export_at, created_at
            FROM siem_configs
            ORDER BY created_at DESC
        """
        result = await self.db.execute(query)
        return [dict(row._mapping) for row in result.fetchall()]

    async def delete_config(self, config_id: str) -> bool:
        """Delete a SIEM configuration."""
        query = "DELETE FROM siem_configs WHERE config_id = :config_id"
        result = await self.db.execute(query, {"config_id": config_id})
        await self.db.commit()
        return result.rowcount > 0

    async def export_finding(
        self,
        config_id: str,
        finding_id: str,
    ) -> dict:
        """Export a single finding to SIEM."""
        config = await self.get_config(config_id)
        if not config:
            raise ValueError("Configuration not found")

        # Get finding
        finding_result = await self.db.execute(
            """
            SELECT f.*, a.app_name, a.package_name
            FROM findings f
            JOIN mobile_apps a ON f.app_id = a.app_id
            WHERE f.finding_id = :finding_id
            """,
            {"finding_id": finding_id}
        )
        finding = finding_result.fetchone()

        if not finding:
            raise ValueError("Finding not found")

        finding = dict(finding._mapping)

        # Format event
        event = self._format_finding_event(finding)

        # Send to SIEM
        client = self._get_client(config["siem_type"], config["config"])
        result = await client.send_event(event)

        if result.get("success"):
            await self._update_export_timestamp(config_id)

        return result

    async def export_findings_batch(
        self,
        config_id: str,
        finding_ids: list[str] = None,
        severity: list[str] = None,
        app_id: str = None,
    ) -> dict:
        """Export multiple findings to SIEM."""
        config = await self.get_config(config_id)
        if not config:
            raise ValueError("Configuration not found")

        # Build query
        conditions = []
        params = {}

        if finding_ids:
            conditions.append("f.finding_id = ANY(:finding_ids)")
            params["finding_ids"] = finding_ids

        if severity:
            conditions.append("f.severity = ANY(:severity)")
            params["severity"] = severity

        if app_id:
            conditions.append("f.app_id = :app_id")
            params["app_id"] = app_id

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT f.*, a.app_name, a.package_name
            FROM findings f
            JOIN mobile_apps a ON f.app_id = a.app_id
            WHERE {where_clause}
            LIMIT 1000
        """

        result = await self.db.execute(query, params)
        findings = [dict(row._mapping) for row in result.fetchall()]

        if not findings:
            return {"success": True, "exported": 0}

        # Format events
        events = [self._format_finding_event(f) for f in findings]

        # Send to SIEM
        client = self._get_client(config["siem_type"], config["config"])
        result = await client.send_batch(events)

        if result.get("success"):
            await self._update_export_timestamp(config_id)

        result["exported"] = len(events)
        return result

    async def export_scan_event(
        self,
        config_id: str,
        scan_id: str,
        event_type: str,  # started, completed, failed
    ) -> dict:
        """Export a scan event to SIEM."""
        config = await self.get_config(config_id)
        if not config:
            raise ValueError("Configuration not found")

        # Get scan
        scan_result = await self.db.execute(
            """
            SELECT s.*, a.app_name, a.package_name
            FROM scans s
            JOIN mobile_apps a ON s.app_id = a.app_id
            WHERE s.scan_id = :scan_id
            """,
            {"scan_id": scan_id}
        )
        scan = scan_result.fetchone()

        if not scan:
            raise ValueError("Scan not found")

        scan = dict(scan._mapping)

        event = {
            "event_type": f"scan.{event_type}",
            "scan_id": scan["scan_id"],
            "app_id": scan["app_id"],
            "app_name": scan.get("app_name"),
            "package_name": scan.get("package_name"),
            "scan_type": scan.get("scan_type"),
            "status": scan.get("status"),
            "findings_count": scan.get("findings_count"),
            "timestamp": datetime.utcnow().isoformat(),
            "source": "mobilicustos",
        }

        client = self._get_client(config["siem_type"], config["config"])
        return await client.send_event(event)

    def _format_finding_event(self, finding: dict) -> dict:
        """Format a finding as a SIEM event."""
        return {
            "event_type": "security_finding",
            "finding_id": finding["finding_id"],
            "app_id": finding["app_id"],
            "app_name": finding.get("app_name"),
            "package_name": finding.get("package_name"),
            "title": finding["title"],
            "description": finding.get("description", "")[:1000],
            "severity": finding["severity"],
            "category": finding.get("category"),
            "status": finding["status"],
            "cwe_id": finding.get("cwe_id"),
            "cvss_score": finding.get("cvss_score"),
            "file_path": finding.get("file_path"),
            "line_number": finding.get("line_number"),
            "tool": finding.get("tool"),
            "timestamp": datetime.utcnow().isoformat(),
            "source": "mobilicustos",
        }

    async def _update_export_timestamp(self, config_id: str) -> None:
        """Update last export timestamp."""
        await self.db.execute(
            """
            UPDATE siem_configs
            SET last_export_at = :now
            WHERE config_id = :config_id
            """,
            {"config_id": config_id, "now": datetime.utcnow()}
        )
        await self.db.commit()

    def _get_client(self, siem_type: str, config: dict) -> SIEMClient:
        """Get appropriate SIEM client."""
        if siem_type == "splunk":
            return SplunkClient(
                hec_url=config["hec_url"],
                token=config["token"],
                index=config.get("index", "main"),
                source=config.get("source", "mobilicustos"),
                verify_ssl=config.get("verify_ssl", False),
            )
        elif siem_type == "elastic":
            return ElasticClient(
                url=config["url"],
                api_key=config["api_key"],
                index_prefix=config.get("index_prefix", "mobilicustos"),
            )
        elif siem_type == "sentinel":
            return SentinelClient(
                workspace_id=config["workspace_id"],
                shared_key=config["shared_key"],
                log_type=config.get("log_type", "MobilicustosFindings"),
            )
        else:
            raise ValueError(f"Unsupported SIEM type: {siem_type}")
