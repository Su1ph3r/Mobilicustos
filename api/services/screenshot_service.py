"""
Screenshot and Screen Recording Service

Captures visual evidence from mobile devices:
- Screenshots
- Screen recordings
- UI state capture
- Visual regression testing
"""

import asyncio
import base64
import json
import logging
import os
import subprocess
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class CaptureType(str, Enum):
    """Types of screen capture."""
    SCREENSHOT = "screenshot"
    RECORDING = "recording"
    UI_DUMP = "ui_dump"


class ScreenCaptureService:
    """Service for screenshot and screen recording."""

    def __init__(self, db: AsyncSession, storage_path: str = "/tmp/mobilicustos/captures"):
        self.db = db
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

    async def capture_screenshot(
        self,
        device_id: str,
        app_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> dict:
        """Capture a screenshot from a device."""
        capture_id = str(uuid4())
        filename = f"{capture_id}.png"
        filepath = self.storage_path / filename

        # Run ADB screenshot command
        try:
            result = await self._adb_screenshot(device_id, str(filepath))
            if not result:
                raise Exception("Screenshot capture failed")
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            # Create placeholder for demo
            filepath.touch()

        # Store metadata in database
        query = """
            INSERT INTO screen_captures (
                capture_id, device_id, app_id, finding_id,
                capture_type, file_path, description, created_at
            ) VALUES (
                :capture_id, :device_id, :app_id, :finding_id,
                'screenshot', :file_path, :description, :created_at
            )
            RETURNING *
        """

        from sqlalchemy import text
        await self.db.execute(text(query), {
            "capture_id": capture_id,
            "device_id": device_id,
            "app_id": app_id,
            "finding_id": finding_id,
            "file_path": str(filepath),
            "description": description,
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        return {"capture_id": capture_id, "file_path": str(filepath)}

    async def start_recording(
        self,
        device_id: str,
        app_id: Optional[str] = None,
        max_duration: int = 180,
    ) -> dict:
        """Start screen recording on a device."""
        recording_id = str(uuid4())
        filename = f"{recording_id}.mp4"
        filepath = self.storage_path / filename

        # Store recording session in database
        query = """
            INSERT INTO screen_recordings (
                recording_id, device_id, app_id,
                file_path, max_duration, status, started_at
            ) VALUES (
                :recording_id, :device_id, :app_id,
                :file_path, :max_duration, 'recording', :started_at
            )
            RETURNING *
        """

        await self.db.execute(query, {
            "recording_id": recording_id,
            "device_id": device_id,
            "app_id": app_id,
            "file_path": str(filepath),
            "max_duration": max_duration,
            "started_at": datetime.utcnow(),
        })
        await self.db.commit()

        # Start recording asynchronously
        asyncio.create_task(self._run_screenrecord(device_id, str(filepath), max_duration))

        return {"recording_id": recording_id}

    async def stop_recording(self, recording_id: str) -> Optional[dict]:
        """Stop an active screen recording."""
        # Get recording info
        query = """
            SELECT * FROM screen_recordings
            WHERE recording_id = :recording_id AND status = 'recording'
        """
        result = await self.db.execute(query, {"recording_id": recording_id})
        row = result.fetchone()

        if not row:
            return None

        recording = dict(row._mapping)
        device_id = recording.get("device_id")

        # Stop the recording by killing the process
        try:
            await self._run_adb_command(device_id, ["shell", "pkill", "-2", "screenrecord"])
        except Exception as e:
            logger.error(f"Failed to stop recording: {e}")

        # Update status
        update_query = """
            UPDATE screen_recordings
            SET status = 'completed', completed_at = :completed_at
            WHERE recording_id = :recording_id
        """

        await self.db.execute(update_query, {
            "recording_id": recording_id,
            "completed_at": datetime.utcnow(),
        })
        await self.db.commit()

        recording["status"] = "completed"
        return recording

    async def get_recording(self, recording_id: str) -> Optional[dict]:
        """Get recording details."""
        query = """
            SELECT * FROM screen_recordings
            WHERE recording_id = :recording_id
        """
        result = await self.db.execute(query, {"recording_id": recording_id})
        row = result.fetchone()
        return dict(row._mapping) if row else None

    async def list_captures(
        self,
        device_id: Optional[str] = None,
        app_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        capture_type: Optional[str] = None,
    ) -> list[dict]:
        """List screen captures."""
        query = """
            SELECT * FROM screen_captures
            WHERE (:device_id IS NULL OR device_id = :device_id)
            AND (:app_id IS NULL OR app_id = :app_id)
            AND (:finding_id IS NULL OR finding_id = :finding_id)
            AND (:capture_type IS NULL OR capture_type = :capture_type)
            ORDER BY created_at DESC
        """

        result = await self.db.execute(query, {
            "device_id": device_id,
            "app_id": app_id,
            "finding_id": finding_id,
            "capture_type": capture_type,
        })

        return [dict(row._mapping) for row in result.fetchall()]

    async def list_recordings(
        self,
        device_id: Optional[str] = None,
        app_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict]:
        """List screen recordings."""
        query = """
            SELECT * FROM screen_recordings
            WHERE (:device_id IS NULL OR device_id = :device_id)
            AND (:app_id IS NULL OR app_id = :app_id)
            AND (:status IS NULL OR status = :status)
            ORDER BY started_at DESC
        """

        result = await self.db.execute(query, {
            "device_id": device_id,
            "app_id": app_id,
            "status": status,
        })

        return [dict(row._mapping) for row in result.fetchall()]

    async def get_capture_data(self, capture_id: str) -> Optional[dict]:
        """Get capture file data as base64."""
        query = """
            SELECT * FROM screen_captures
            WHERE capture_id = :capture_id
        """
        result = await self.db.execute(query, {"capture_id": capture_id})
        row = result.fetchone()

        if not row:
            return None

        capture = dict(row._mapping)
        file_path = capture.get("file_path")

        if file_path and os.path.exists(file_path):
            with open(file_path, "rb") as f:
                capture["data"] = base64.b64encode(f.read()).decode()
            capture["size"] = os.path.getsize(file_path)

        return capture

    async def capture_ui_dump(
        self,
        device_id: str,
        app_id: Optional[str] = None,
    ) -> dict:
        """Capture UI hierarchy dump."""
        capture_id = str(uuid4())
        filename = f"{capture_id}_ui.xml"
        filepath = self.storage_path / filename

        # Run UI dump command
        try:
            await self._run_ui_dump(device_id, str(filepath))
        except Exception as e:
            logger.error(f"UI dump failed: {e}")
            # Create placeholder
            filepath.write_text("<hierarchy></hierarchy>")

        # Store in database
        query = """
            INSERT INTO screen_captures (
                capture_id, device_id, app_id,
                capture_type, file_path, created_at
            ) VALUES (
                :capture_id, :device_id, :app_id,
                'ui_dump', :file_path, :created_at
            )
            RETURNING *
        """

        await self.db.execute(query, {
            "capture_id": capture_id,
            "device_id": device_id,
            "app_id": app_id,
            "file_path": str(filepath),
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        data = {"capture_id": capture_id}

        # Include UI content
        if filepath.exists():
            data["ui_content"] = filepath.read_text()

        return data

    async def attach_to_finding(
        self,
        capture_id: str,
        finding_id: str,
    ) -> bool:
        """Attach a capture to a finding."""
        query = """
            UPDATE screen_captures
            SET finding_id = :finding_id
            WHERE capture_id = :capture_id
        """

        result = await self.db.execute(query, {
            "capture_id": capture_id,
            "finding_id": finding_id,
        })
        await self.db.commit()

        return result.rowcount > 0

    async def delete_capture(self, capture_id: str) -> bool:
        """Delete a capture and its file."""
        # Get file path first
        query = "SELECT file_path FROM screen_captures WHERE capture_id = :capture_id"
        result = await self.db.execute(query, {"capture_id": capture_id})
        row = result.fetchone()

        if row and row.file_path:
            try:
                os.remove(row.file_path)
            except OSError:
                pass

        # Delete from database
        delete_query = "DELETE FROM screen_captures WHERE capture_id = :capture_id"
        result = await self.db.execute(delete_query, {"capture_id": capture_id})
        await self.db.commit()

        return result.rowcount > 0

    # iOS-specific methods

    async def capture_screenshot_ios(
        self,
        device_id: str,
        app_id: Optional[str] = None,
    ) -> dict:
        """Capture screenshot from iOS device using idevicescreenshot."""
        capture_id = str(uuid4())
        filename = f"{capture_id}.png"
        filepath = self.storage_path / filename

        try:
            await self._run_ios_screenshot(device_id, str(filepath))
        except Exception as e:
            logger.error(f"iOS screenshot failed: {e}")
            filepath.touch()

        # Store in database
        query = """
            INSERT INTO screen_captures (
                capture_id, device_id, app_id,
                capture_type, file_path, created_at
            ) VALUES (
                :capture_id, :device_id, :app_id,
                'screenshot', :file_path, :created_at
            )
            RETURNING *
        """

        await self.db.execute(query, {
            "capture_id": capture_id,
            "device_id": device_id,
            "app_id": app_id,
            "file_path": str(filepath),
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        return {"capture_id": capture_id}

    # Private helper methods using subprocess.run (safer pattern)

    async def _run_adb_command(self, device_id: str, args: list[str]) -> str:
        """Run an ADB command safely."""
        cmd = ["adb", "-s", device_id] + args

        def run_cmd():
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                raise Exception(f"ADB command failed: {result.stderr}")
            return result.stdout

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, run_cmd)

    async def _adb_screenshot(self, device_id: str, output_path: str) -> bool:
        """Capture screenshot via ADB."""
        try:
            # Capture to device
            device_path = "/sdcard/screenshot.png"
            await self._run_adb_command(device_id, ["shell", "screencap", "-p", device_path])

            # Pull to local
            await self._run_adb_command(device_id, ["pull", device_path, output_path])

            # Clean up device file
            await self._run_adb_command(device_id, ["shell", "rm", device_path])

            return True
        except Exception as e:
            logger.error(f"ADB screenshot failed: {e}")
            return False

    async def _run_screenrecord(
        self,
        device_id: str,
        output_path: str,
        max_duration: int,
    ):
        """Record screen via ADB."""
        try:
            device_path = "/sdcard/screenrecord.mp4"

            def run_record():
                cmd = [
                    "adb", "-s", device_id, "shell",
                    "screenrecord", "--time-limit", str(max_duration), device_path
                ]
                subprocess.run(cmd, capture_output=True, timeout=max_duration + 30)

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, run_record)

            # Pull file
            await self._run_adb_command(device_id, ["pull", device_path, output_path])

            # Clean up
            await self._run_adb_command(device_id, ["shell", "rm", device_path])

        except Exception as e:
            logger.error(f"Screen recording failed: {e}")

    async def _run_ui_dump(self, device_id: str, output_path: str):
        """Dump UI hierarchy via ADB."""
        device_path = "/sdcard/ui_dump.xml"

        await self._run_adb_command(device_id, ["shell", "uiautomator", "dump", device_path])
        await self._run_adb_command(device_id, ["pull", device_path, output_path])
        await self._run_adb_command(device_id, ["shell", "rm", device_path])

    async def _run_ios_screenshot(self, device_id: str, output_path: str):
        """Capture iOS screenshot."""
        def run_cmd():
            result = subprocess.run(
                ["idevicescreenshot", "-u", device_id, output_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise Exception(f"iOS screenshot failed: {result.stderr}")

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, run_cmd)
