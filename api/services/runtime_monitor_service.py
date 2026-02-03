"""
Runtime Behavior Monitor Service

Monitors mobile app behavior during runtime:
- System call tracing
- File system access monitoring
- Network connection tracking
- Permission usage monitoring
- Inter-process communication
- Cryptographic operations
"""

import asyncio
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class MonitorType(str, Enum):
    """Types of runtime monitoring."""
    SYSCALL = "syscall"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    PERMISSION = "permission"
    IPC = "ipc"
    CRYPTO = "crypto"
    ALL = "all"


class RuntimeEvent:
    """Represents a runtime event."""

    def __init__(
        self,
        event_type: str,
        timestamp: datetime,
        process_name: str,
        details: dict,
    ):
        self.event_type = event_type
        self.timestamp = timestamp
        self.process_name = process_name
        self.details = details

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "process_name": self.process_name,
            "details": self.details,
        }


class RuntimeMonitorService:
    """Service for runtime behavior monitoring."""

    # Suspicious patterns to detect
    SUSPICIOUS_PATTERNS = {
        "filesystem": {
            "sensitive_paths": [
                "/data/data/*/databases/",
                "/data/data/*/shared_prefs/",
                "/sdcard/DCIM/",
                "/sdcard/Download/",
                "/proc/",
                "/sys/",
            ],
            "dangerous_operations": ["delete", "write", "chmod"],
        },
        "network": {
            "suspicious_ports": [21, 22, 23, 25, 445, 1433, 3306, 5432],
            "data_exfil_indicators": ["base64", "encoded", "encrypted"],
        },
        "permission": {
            "sensitive_permissions": [
                "READ_CONTACTS",
                "READ_SMS",
                "READ_CALL_LOG",
                "ACCESS_FINE_LOCATION",
                "CAMERA",
                "RECORD_AUDIO",
                "READ_EXTERNAL_STORAGE",
            ],
        },
        "crypto": {
            "weak_algorithms": ["DES", "3DES", "MD5", "SHA1", "RC4"],
            "suspicious_operations": ["export", "import", "raw_key"],
        },
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_monitor_session(
        self,
        app_id: str,
        device_id: str,
        monitor_types: list[str],
        duration_seconds: int = 300,
    ) -> dict:
        """Create a new runtime monitoring session."""
        session_id = str(uuid4())

        query = """
            INSERT INTO runtime_monitor_sessions (
                session_id, app_id, device_id, monitor_types,
                duration_seconds, status, started_at
            ) VALUES (
                :session_id, :app_id, :device_id, :monitor_types,
                :duration_seconds, 'active', :started_at
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "app_id": app_id,
            "device_id": device_id,
            "monitor_types": json.dumps(monitor_types),
            "duration_seconds": duration_seconds,
            "started_at": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else {"session_id": session_id}

    async def stop_monitor_session(self, session_id: str) -> bool:
        """Stop a runtime monitoring session."""
        query = """
            UPDATE runtime_monitor_sessions
            SET status = 'stopped', completed_at = :completed_at
            WHERE session_id = :session_id AND status = 'active'
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "completed_at": datetime.utcnow(),
        })
        await self.db.commit()

        return result.rowcount > 0

    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get monitor session details."""
        query = """
            SELECT * FROM runtime_monitor_sessions
            WHERE session_id = :session_id
        """
        result = await self.db.execute(query, {"session_id": session_id})
        row = result.fetchone()
        if row:
            data = dict(row._mapping)
            if data.get("monitor_types"):
                data["monitor_types"] = json.loads(data["monitor_types"])
            return data
        return None

    async def list_sessions(
        self,
        app_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict]:
        """List runtime monitoring sessions."""
        query = """
            SELECT * FROM runtime_monitor_sessions
            WHERE (:app_id IS NULL OR app_id = :app_id)
            AND (:status IS NULL OR status = :status)
            ORDER BY started_at DESC
        """

        result = await self.db.execute(query, {
            "app_id": app_id,
            "status": status,
        })

        sessions = []
        for row in result.fetchall():
            data = dict(row._mapping)
            if data.get("monitor_types"):
                data["monitor_types"] = json.loads(data["monitor_types"])
            sessions.append(data)

        return sessions

    async def record_event(
        self,
        session_id: str,
        event_type: str,
        process_name: str,
        details: dict,
        is_suspicious: bool = False,
    ) -> dict:
        """Record a runtime event."""
        event_id = str(uuid4())

        query = """
            INSERT INTO runtime_events (
                event_id, session_id, event_type, process_name,
                details, is_suspicious, timestamp
            ) VALUES (
                :event_id, :session_id, :event_type, :process_name,
                :details, :is_suspicious, :timestamp
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "event_id": event_id,
            "session_id": session_id,
            "event_type": event_type,
            "process_name": process_name,
            "details": json.dumps(details),
            "is_suspicious": is_suspicious,
            "timestamp": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else {"event_id": event_id}

    async def get_events(
        self,
        session_id: str,
        event_type: Optional[str] = None,
        suspicious_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Get events for a monitoring session."""
        query = """
            SELECT * FROM runtime_events
            WHERE session_id = :session_id
            AND (:event_type IS NULL OR event_type = :event_type)
            AND (:suspicious_only = FALSE OR is_suspicious = TRUE)
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "event_type": event_type,
            "suspicious_only": suspicious_only,
            "limit": limit,
            "offset": offset,
        })

        events = []
        for row in result.fetchall():
            data = dict(row._mapping)
            if data.get("details"):
                data["details"] = json.loads(data["details"])
            events.append(data)

        return events

    async def analyze_session(self, session_id: str) -> dict:
        """Analyze all events in a monitoring session."""
        events = await self.get_events(session_id, limit=10000)

        analysis = {
            "session_id": session_id,
            "total_events": len(events),
            "event_counts": {},
            "suspicious_events": [],
            "findings": [],
            "permission_usage": {},
            "network_connections": [],
            "file_operations": [],
            "analyzed_at": datetime.utcnow().isoformat(),
        }

        for event in events:
            event_type = event.get("event_type", "unknown")
            analysis["event_counts"][event_type] = \
                analysis["event_counts"].get(event_type, 0) + 1

            if event.get("is_suspicious"):
                analysis["suspicious_events"].append(event)

            # Process specific event types
            details = event.get("details", {})

            if event_type == "permission":
                perm = details.get("permission", "")
                if perm:
                    analysis["permission_usage"][perm] = \
                        analysis["permission_usage"].get(perm, 0) + 1

            elif event_type == "network":
                analysis["network_connections"].append({
                    "host": details.get("host", ""),
                    "port": details.get("port", 0),
                    "protocol": details.get("protocol", "tcp"),
                    "timestamp": event.get("timestamp"),
                })

            elif event_type == "filesystem":
                analysis["file_operations"].append({
                    "path": details.get("path", ""),
                    "operation": details.get("operation", ""),
                    "timestamp": event.get("timestamp"),
                })

        # Generate findings from suspicious patterns
        analysis["findings"] = self._generate_findings(events)

        return analysis

    def _generate_findings(self, events: list[dict]) -> list[dict]:
        """Generate security findings from events."""
        findings = []

        for event in events:
            if not event.get("is_suspicious"):
                continue

            event_type = event.get("event_type", "")
            details = event.get("details", {})

            if event_type == "filesystem":
                path = details.get("path", "")
                operation = details.get("operation", "")

                for sensitive_path in self.SUSPICIOUS_PATTERNS["filesystem"]["sensitive_paths"]:
                    if sensitive_path.replace("*", "") in path:
                        findings.append({
                            "type": "sensitive_file_access",
                            "severity": "high",
                            "title": f"Access to sensitive path: {path}",
                            "description": f"App performed {operation} operation on sensitive path",
                            "details": details,
                        })
                        break

            elif event_type == "network":
                port = details.get("port", 0)
                if port in self.SUSPICIOUS_PATTERNS["network"]["suspicious_ports"]:
                    findings.append({
                        "type": "suspicious_network_connection",
                        "severity": "medium",
                        "title": f"Connection to suspicious port {port}",
                        "description": f"App connected to {details.get('host', '')}:{port}",
                        "details": details,
                    })

            elif event_type == "permission":
                perm = details.get("permission", "")
                if perm in self.SUSPICIOUS_PATTERNS["permission"]["sensitive_permissions"]:
                    findings.append({
                        "type": "sensitive_permission_usage",
                        "severity": "medium",
                        "title": f"Sensitive permission used: {perm}",
                        "description": f"App actively used permission: {perm}",
                        "details": details,
                    })

            elif event_type == "crypto":
                algorithm = details.get("algorithm", "")
                if algorithm in self.SUSPICIOUS_PATTERNS["crypto"]["weak_algorithms"]:
                    findings.append({
                        "type": "weak_cryptography",
                        "severity": "high",
                        "title": f"Weak cryptographic algorithm: {algorithm}",
                        "description": f"App used weak algorithm {algorithm} at runtime",
                        "details": details,
                    })

        return findings

    async def create_findings_from_analysis(
        self,
        session_id: str,
        app_id: str,
        scan_id: Optional[str] = None,
    ) -> list[str]:
        """Create findings from runtime analysis."""
        analysis = await self.analyze_session(session_id)

        finding_ids = []
        for runtime_finding in analysis.get("findings", []):
            finding_id = str(uuid4())

            query = """
                INSERT INTO findings (
                    finding_id, app_id, scan_id, title, description,
                    severity, category, tool, status, created_at
                ) VALUES (
                    :finding_id, :app_id, :scan_id, :title, :description,
                    :severity, :category, :tool, 'open', :created_at
                )
                RETURNING finding_id
            """

            await self.db.execute(query, {
                "finding_id": finding_id,
                "app_id": app_id,
                "scan_id": scan_id,
                "title": runtime_finding.get("title", "Runtime Finding"),
                "description": runtime_finding.get("description", ""),
                "severity": runtime_finding.get("severity", "medium"),
                "category": "runtime",
                "tool": "runtime_monitor",
                "created_at": datetime.utcnow(),
            })

            finding_ids.append(finding_id)

        await self.db.commit()
        return finding_ids

    def get_frida_monitor_script(self, monitor_types: list[str]) -> str:
        """Generate Frida script for runtime monitoring."""
        script_parts = ["""
// Mobilicustos Runtime Monitor
// Auto-generated Frida script for runtime behavior monitoring

var sessionId = '%SESSION_ID%';
var webhookUrl = '%WEBHOOK_URL%';

function sendEvent(eventType, processName, details) {
    var event = {
        session_id: sessionId,
        event_type: eventType,
        process_name: processName,
        details: details,
        timestamp: new Date().toISOString()
    };

    // Send to webhook (in practice, use proper HTTP client)
    console.log('[MONITOR] ' + JSON.stringify(event));
}
"""]

        if "filesystem" in monitor_types or "all" in monitor_types:
            script_parts.append("""
// File System Monitoring
if (Java.available) {
    Java.perform(function() {
        var File = Java.use('java.io.File');
        var FileInputStream = Java.use('java.io.FileInputStream');
        var FileOutputStream = Java.use('java.io.FileOutputStream');

        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            sendEvent('filesystem', 'java.io.FileInputStream', {
                operation: 'read',
                path: file.getAbsolutePath()
            });
            return this.$init(file);
        };

        FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
            sendEvent('filesystem', 'java.io.FileOutputStream', {
                operation: 'write',
                path: file.getAbsolutePath()
            });
            return this.$init(file);
        };
    });
}
""")

        if "network" in monitor_types or "all" in monitor_types:
            script_parts.append("""
// Network Monitoring
if (Java.available) {
    Java.perform(function() {
        var Socket = Java.use('java.net.Socket');
        var URL = Java.use('java.net.URL');

        Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
            sendEvent('network', 'java.net.Socket', {
                host: host,
                port: port,
                protocol: 'tcp'
            });
            return this.$init(host, port);
        };

        URL.openConnection.overload().implementation = function() {
            sendEvent('network', 'java.net.URL', {
                url: this.toString(),
                protocol: this.getProtocol()
            });
            return this.openConnection();
        };
    });
}
""")

        if "crypto" in monitor_types or "all" in monitor_types:
            script_parts.append("""
// Cryptographic Operations Monitoring
if (Java.available) {
    Java.perform(function() {
        var Cipher = Java.use('javax.crypto.Cipher');
        var MessageDigest = Java.use('java.security.MessageDigest');

        Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
            sendEvent('crypto', 'javax.crypto.Cipher', {
                algorithm: algo,
                operation: 'getInstance'
            });
            return this.getInstance(algo);
        };

        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
            sendEvent('crypto', 'java.security.MessageDigest', {
                algorithm: algo,
                operation: 'getInstance'
            });
            return this.getInstance(algo);
        };
    });
}
""")

        if "permission" in monitor_types or "all" in monitor_types:
            script_parts.append("""
// Permission Usage Monitoring
if (Java.available) {
    Java.perform(function() {
        var ContextWrapper = Java.use('android.content.ContextWrapper');

        ContextWrapper.checkSelfPermission.implementation = function(permission) {
            var result = this.checkSelfPermission(permission);
            sendEvent('permission', 'android.content.Context', {
                permission: permission,
                granted: result === 0
            });
            return result;
        };
    });
}
""")

        return "\n".join(script_parts)
