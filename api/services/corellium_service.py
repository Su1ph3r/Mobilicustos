"""
Corellium Integration Service

Integrates with Corellium for virtual device management:
- Virtual device provisioning
- App installation and testing
- Network capture
- Jailbroken/rooted testing
- Automated security testing
"""

import asyncio
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class DeviceOS(str, Enum):
    """Supported device operating systems."""
    IOS = "ios"
    ANDROID = "android"


class DeviceState(str, Enum):
    """Virtual device states."""
    CREATING = "creating"
    BOOTING = "booting"
    ON = "on"
    OFF = "off"
    PAUSED = "paused"
    DELETING = "deleting"
    ERROR = "error"


class CorelliumClient:
    """Corellium API client."""

    def __init__(self, api_url: str, api_token: str):
        self.api_url = api_url.rstrip("/")
        self.http = httpx.AsyncClient(
            base_url=self.api_url,
            headers={
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            },
            timeout=120.0,
        )

    async def close(self):
        """Close the HTTP client."""
        await self.http.aclose()

    async def get_projects(self) -> list[dict]:
        """Get all projects."""
        response = await self.http.get("/v1/projects")
        response.raise_for_status()
        return response.json()

    async def get_devices(self, project_id: str) -> list[dict]:
        """Get all devices in a project."""
        response = await self.http.get(f"/v1/projects/{project_id}/instances")
        response.raise_for_status()
        return response.json()

    async def create_device(
        self,
        project_id: str,
        flavor: str,
        os_version: str,
        name: str,
    ) -> dict:
        """Create a new virtual device."""
        payload = {
            "project": project_id,
            "flavor": flavor,
            "os": os_version,
            "name": name,
        }

        response = await self.http.post("/v1/instances", json=payload)
        response.raise_for_status()
        return response.json()

    async def get_device(self, instance_id: str) -> dict:
        """Get device details."""
        response = await self.http.get(f"/v1/instances/{instance_id}")
        response.raise_for_status()
        return response.json()

    async def start_device(self, instance_id: str) -> dict:
        """Start a virtual device."""
        response = await self.http.post(f"/v1/instances/{instance_id}/start")
        response.raise_for_status()
        return response.json()

    async def stop_device(self, instance_id: str) -> dict:
        """Stop a virtual device."""
        response = await self.http.post(f"/v1/instances/{instance_id}/stop")
        response.raise_for_status()
        return response.json()

    async def delete_device(self, instance_id: str) -> bool:
        """Delete a virtual device."""
        response = await self.http.delete(f"/v1/instances/{instance_id}")
        return response.status_code == 204

    async def take_snapshot(self, instance_id: str, name: str) -> dict:
        """Take a device snapshot."""
        payload = {"name": name}
        response = await self.http.post(
            f"/v1/instances/{instance_id}/snapshots",
            json=payload
        )
        response.raise_for_status()
        return response.json()

    async def restore_snapshot(self, instance_id: str, snapshot_id: str) -> dict:
        """Restore a device snapshot."""
        response = await self.http.post(
            f"/v1/instances/{instance_id}/snapshots/{snapshot_id}/restore"
        )
        response.raise_for_status()
        return response.json()

    async def install_app(self, instance_id: str, app_path: str) -> dict:
        """Install an app on the device."""
        with open(app_path, "rb") as f:
            files = {"file": f}
            response = await self.http.post(
                f"/v1/instances/{instance_id}/apps",
                files=files,
            )
        response.raise_for_status()
        return response.json()

    async def get_apps(self, instance_id: str) -> list[dict]:
        """Get installed apps on device."""
        response = await self.http.get(f"/v1/instances/{instance_id}/apps")
        response.raise_for_status()
        return response.json()

    async def uninstall_app(self, instance_id: str, bundle_id: str) -> bool:
        """Uninstall an app from the device."""
        response = await self.http.delete(
            f"/v1/instances/{instance_id}/apps/{bundle_id}"
        )
        return response.status_code == 204

    async def start_network_capture(self, instance_id: str) -> dict:
        """Start network traffic capture."""
        response = await self.http.post(
            f"/v1/instances/{instance_id}/networkMonitor"
        )
        response.raise_for_status()
        return response.json()

    async def stop_network_capture(self, instance_id: str) -> bytes:
        """Stop network capture and get PCAP data."""
        response = await self.http.delete(
            f"/v1/instances/{instance_id}/networkMonitor"
        )
        response.raise_for_status()
        return response.content

    async def get_console_log(self, instance_id: str) -> str:
        """Get device console log."""
        response = await self.http.get(f"/v1/instances/{instance_id}/console")
        response.raise_for_status()
        return response.text

    async def run_frida(
        self,
        instance_id: str,
        target: str,
        script: str,
    ) -> dict:
        """Run Frida script on device."""
        payload = {
            "target": target,
            "script": script,
        }
        response = await self.http.post(
            f"/v1/instances/{instance_id}/frida",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    async def get_supported_devices(self) -> list[dict]:
        """Get list of supported device models."""
        response = await self.http.get("/v1/supported")
        response.raise_for_status()
        return response.json()


class CorelliumService:
    """Service for Corellium integration."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._clients: dict[str, CorelliumClient] = {}

    async def create_connection(
        self,
        name: str,
        api_url: str,
        api_token: str,
    ) -> dict:
        """Create a new Corellium connection."""
        connection_id = str(uuid4())

        # Test connection
        client = CorelliumClient(api_url, api_token)
        try:
            await client.get_projects()
        except Exception as e:
            await client.close()
            raise ValueError(f"Connection test failed: {e}")

        await client.close()

        query = """
            INSERT INTO corellium_connections (
                connection_id, name, api_url, api_token,
                is_active, created_at
            ) VALUES (
                :connection_id, :name, :api_url, :api_token,
                TRUE, :created_at
            )
            RETURNING connection_id, name, api_url, is_active, created_at
        """

        result = await self.db.execute(query, {
            "connection_id": connection_id,
            "name": name,
            "api_url": api_url,
            "api_token": api_token,
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else {"connection_id": connection_id}

    async def list_connections(self) -> list[dict]:
        """List all Corellium connections."""
        query = """
            SELECT connection_id, name, api_url, is_active, created_at
            FROM corellium_connections
            ORDER BY created_at DESC
        """
        result = await self.db.execute(query)
        return [dict(row._mapping) for row in result.fetchall()]

    async def get_connection(self, connection_id: str) -> Optional[dict]:
        """Get a Corellium connection."""
        query = """
            SELECT * FROM corellium_connections
            WHERE connection_id = :connection_id
        """
        result = await self.db.execute(query, {"connection_id": connection_id})
        row = result.fetchone()
        return dict(row._mapping) if row else None

    async def delete_connection(self, connection_id: str) -> bool:
        """Delete a Corellium connection."""
        # Close cached client
        if connection_id in self._clients:
            await self._clients[connection_id].close()
            del self._clients[connection_id]

        query = "DELETE FROM corellium_connections WHERE connection_id = :connection_id"
        result = await self.db.execute(query, {"connection_id": connection_id})
        await self.db.commit()
        return result.rowcount > 0

    async def _get_client(self, connection_id: str) -> CorelliumClient:
        """Get or create a Corellium client."""
        if connection_id not in self._clients:
            conn = await self.get_connection(connection_id)
            if not conn:
                raise ValueError("Connection not found")

            self._clients[connection_id] = CorelliumClient(
                conn["api_url"],
                conn["api_token"],
            )

        return self._clients[connection_id]

    async def get_projects(self, connection_id: str) -> list[dict]:
        """Get all projects in Corellium."""
        client = await self._get_client(connection_id)
        return await client.get_projects()

    async def get_supported_devices(self, connection_id: str) -> list[dict]:
        """Get supported device models."""
        client = await self._get_client(connection_id)
        return await client.get_supported_devices()

    async def create_virtual_device(
        self,
        connection_id: str,
        project_id: str,
        flavor: str,
        os_version: str,
        name: str,
    ) -> dict:
        """Create a virtual device."""
        client = await self._get_client(connection_id)
        device = await client.create_device(project_id, flavor, os_version, name)

        # Store in database for tracking
        query = """
            INSERT INTO corellium_devices (
                device_id, connection_id, instance_id, project_id,
                name, flavor, os_version, state, created_at
            ) VALUES (
                :device_id, :connection_id, :instance_id, :project_id,
                :name, :flavor, :os_version, :state, :created_at
            )
            RETURNING *
        """

        device_id = str(uuid4())
        await self.db.execute(query, {
            "device_id": device_id,
            "connection_id": connection_id,
            "instance_id": device.get("id"),
            "project_id": project_id,
            "name": name,
            "flavor": flavor,
            "os_version": os_version,
            "state": device.get("state", "creating"),
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        return {
            "device_id": device_id,
            "instance_id": device.get("id"),
            "name": name,
            "state": device.get("state"),
        }

    async def list_virtual_devices(
        self,
        connection_id: Optional[str] = None,
    ) -> list[dict]:
        """List virtual devices."""
        query = """
            SELECT * FROM corellium_devices
            WHERE (:connection_id IS NULL OR connection_id = :connection_id)
            ORDER BY created_at DESC
        """
        result = await self.db.execute(query, {"connection_id": connection_id})
        return [dict(row._mapping) for row in result.fetchall()]

    async def get_device_status(
        self,
        connection_id: str,
        instance_id: str,
    ) -> dict:
        """Get virtual device status."""
        client = await self._get_client(connection_id)
        return await client.get_device(instance_id)

    async def start_virtual_device(
        self,
        connection_id: str,
        instance_id: str,
    ) -> dict:
        """Start a virtual device."""
        client = await self._get_client(connection_id)
        result = await client.start_device(instance_id)

        # Update state in database
        await self.db.execute(
            "UPDATE corellium_devices SET state = 'booting' WHERE instance_id = :instance_id",
            {"instance_id": instance_id}
        )
        await self.db.commit()

        return result

    async def stop_virtual_device(
        self,
        connection_id: str,
        instance_id: str,
    ) -> dict:
        """Stop a virtual device."""
        client = await self._get_client(connection_id)
        result = await client.stop_device(instance_id)

        # Update state in database
        await self.db.execute(
            "UPDATE corellium_devices SET state = 'off' WHERE instance_id = :instance_id",
            {"instance_id": instance_id}
        )
        await self.db.commit()

        return result

    async def delete_virtual_device(
        self,
        connection_id: str,
        instance_id: str,
    ) -> bool:
        """Delete a virtual device."""
        client = await self._get_client(connection_id)
        result = await client.delete_device(instance_id)

        if result:
            await self.db.execute(
                "DELETE FROM corellium_devices WHERE instance_id = :instance_id",
                {"instance_id": instance_id}
            )
            await self.db.commit()

        return result

    async def install_app_on_device(
        self,
        connection_id: str,
        instance_id: str,
        app_path: str,
    ) -> dict:
        """Install an app on a virtual device."""
        client = await self._get_client(connection_id)
        return await client.install_app(instance_id, app_path)

    async def start_network_capture(
        self,
        connection_id: str,
        instance_id: str,
    ) -> dict:
        """Start network capture on device."""
        client = await self._get_client(connection_id)
        return await client.start_network_capture(instance_id)

    async def stop_network_capture(
        self,
        connection_id: str,
        instance_id: str,
        output_path: str,
    ) -> str:
        """Stop network capture and save PCAP."""
        client = await self._get_client(connection_id)
        pcap_data = await client.stop_network_capture(instance_id)

        with open(output_path, "wb") as f:
            f.write(pcap_data)

        return output_path

    async def run_frida_script(
        self,
        connection_id: str,
        instance_id: str,
        target: str,
        script: str,
    ) -> dict:
        """Run Frida script on device."""
        client = await self._get_client(connection_id)
        return await client.run_frida(instance_id, target, script)

    async def take_snapshot(
        self,
        connection_id: str,
        instance_id: str,
        name: str,
    ) -> dict:
        """Take a device snapshot."""
        client = await self._get_client(connection_id)
        return await client.take_snapshot(instance_id, name)

    async def run_security_test(
        self,
        connection_id: str,
        instance_id: str,
        app_id: str,
        test_type: str,
    ) -> dict:
        """Run automated security test on app."""
        test_id = str(uuid4())

        # Get app info
        query = "SELECT * FROM mobile_apps WHERE app_id = :app_id"
        result = await self.db.execute(query, {"app_id": app_id})
        app = result.fetchone()

        if not app:
            raise ValueError("App not found")

        app = dict(app._mapping)

        # Install app
        await self.install_app_on_device(
            connection_id,
            instance_id,
            app.get("file_path"),
        )

        # Run appropriate security tests based on test_type
        findings = []

        if test_type in ["ssl_pinning", "all"]:
            # Run SSL pinning bypass test
            script = self._get_ssl_bypass_script()
            result = await self.run_frida_script(
                connection_id, instance_id,
                app.get("package_name", ""),
                script
            )
            if result.get("bypassed"):
                findings.append({
                    "type": "ssl_pinning_bypass",
                    "severity": "high",
                    "description": "SSL certificate pinning can be bypassed",
                })

        if test_type in ["root_detection", "all"]:
            # Run root detection bypass test
            script = self._get_root_detection_script()
            result = await self.run_frida_script(
                connection_id, instance_id,
                app.get("package_name", ""),
                script
            )
            if result.get("bypassed"):
                findings.append({
                    "type": "root_detection_bypass",
                    "severity": "medium",
                    "description": "Root/jailbreak detection can be bypassed",
                })

        return {
            "test_id": test_id,
            "app_id": app_id,
            "instance_id": instance_id,
            "test_type": test_type,
            "findings_count": len(findings),
            "findings": findings,
        }

    def _get_ssl_bypass_script(self) -> str:
        """Get Frida script for SSL pinning bypass test."""
        return """
Java.perform(function() {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function() {
        send({bypassed: true, type: 'ssl_pinning'});
        return arguments[0];
    };
});
"""

    def _get_root_detection_script(self) -> str:
        """Get Frida script for root detection bypass test."""
        return """
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        send({bypassed: true, type: 'root_detection'});
        return false;
    };
});
"""
