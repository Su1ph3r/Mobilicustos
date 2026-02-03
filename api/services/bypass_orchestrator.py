"""Bypass orchestrator for anti-detection framework."""

import logging
import zipfile
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.models.database import BypassResult, Device, FridaScript, MobileApp
from api.services.frida_service import FridaService

logger = logging.getLogger(__name__)


# Detection signatures database
DETECTION_SIGNATURES = {
    "frida": {
        "file_checks": [
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/system/lib/libc.so.6",  # Frida modifies libc
        ],
        "port_checks": [27042, 27043],
        "memory_signatures": [
            b"frida-agent",
            b"gum-js-loop",
            b"frida_agent_main",
        ],
        "thread_names": ["gum-js-loop", "gmain", "frida"],
    },
    "root": {
        "file_checks": [
            "/system/app/Superuser.apk",
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/app/SuperSU",
            "/system/app/Magisk",
        ],
        "binary_checks": ["su", "busybox", "magisk"],
        "prop_checks": ["ro.build.selinux", "ro.debuggable"],
    },
    "jailbreak": {
        "file_checks": [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
        ],
        "url_schemes": ["cydia://", "sileo://"],
    },
    "emulator": {
        "prop_checks": [
            "ro.kernel.qemu",
            "ro.product.model",  # Check for emulator models
            "ro.hardware",
        ],
        "build_checks": ["generic", "sdk", "goldfish", "ranchu"],
        "sensor_checks": ["accelerometer", "gyroscope"],
    },
    "debugger": {
        "status_checks": ["TracerPid"],
        "ptrace_checks": True,
    },
    "ssl_pinning": {
        "libraries": {
            "android": ["OkHttp", "TrustManager", "HttpsURLConnection"],
            "ios": ["NSURLSession", "Alamofire", "AFNetworking"],
        },
    },
}


class BypassOrchestrator:
    """Orchestrates anti-detection analysis and bypass attempts."""

    def __init__(self):
        self.frida = FridaService()

    async def analyze_protections(self, app: MobileApp) -> list[dict[str, Any]]:
        """Analyze an app's protection mechanisms via static analysis."""
        detections: list[dict[str, Any]] = []

        if not app.file_path:
            return detections

        try:
            with zipfile.ZipFile(app.file_path, "r") as archive:
                file_list = archive.namelist()

                # Check for anti-Frida
                frida_detection = await self._detect_anti_frida(archive, file_list)
                if frida_detection:
                    detections.append(frida_detection)

                # Check for root detection
                if app.platform == "android":
                    root_detection = await self._detect_root_detection(archive, file_list)
                    if root_detection:
                        detections.append(root_detection)

                # Check for jailbreak detection
                if app.platform == "ios":
                    jb_detection = await self._detect_jailbreak_detection(archive, file_list)
                    if jb_detection:
                        detections.append(jb_detection)

                # Check for SSL pinning
                ssl_detection = await self._detect_ssl_pinning(archive, file_list, app.platform)
                if ssl_detection:
                    detections.append(ssl_detection)

                # Check for emulator detection
                if app.platform == "android":
                    emu_detection = await self._detect_emulator_detection(archive, file_list)
                    if emu_detection:
                        detections.append(emu_detection)

        except Exception as e:
            logger.error(f"Protection analysis failed: {e}")

        return detections

    async def _detect_anti_frida(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect anti-Frida mechanisms."""
        evidence = []

        # Check for known anti-Frida libraries
        anti_frida_libs = ["libfrida-check", "libanti-frida"]
        for lib in anti_frida_libs:
            if any(lib in f for f in file_list):
                evidence.append(f"Found library: {lib}")

        # Search for Frida detection strings in DEX/native code
        frida_strings = ["frida", "27042", "frida-server", "gum-js"]
        for name in file_list:
            if name.endswith(".dex") or name.endswith(".so"):
                try:
                    content = archive.read(name).decode("utf-8", errors="ignore")
                    for s in frida_strings:
                        if s in content.lower():
                            evidence.append(f"Found '{s}' in {name}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "frida",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "high" if len(evidence) > 2 else "medium",
                "methods": ["file_check", "port_scan", "memory_scan"],
            }

        return None

    async def _detect_root_detection(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect root detection mechanisms."""
        evidence = []

        # Check for RootBeer or similar libraries
        root_libs = ["rootbeer", "rootchecker", "safetynet"]
        for name in file_list:
            if any(lib in name.lower() for lib in root_libs):
                evidence.append(f"Found root detection library: {name}")

        # Search for root detection strings
        root_strings = DETECTION_SIGNATURES["root"]["file_checks"]
        for name in file_list:
            if name.endswith(".dex"):
                try:
                    content = archive.read(name).decode("utf-8", errors="ignore")
                    for s in root_strings:
                        if s in content:
                            evidence.append(f"Found root path check: {s}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "root",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "high" if len(evidence) > 3 else "medium",
                "methods": ["file_check", "command_exec", "prop_check"],
            }

        return None

    async def _detect_jailbreak_detection(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect jailbreak detection mechanisms."""
        evidence = []

        jb_strings = DETECTION_SIGNATURES["jailbreak"]["file_checks"]
        jb_strings.extend(DETECTION_SIGNATURES["jailbreak"]["url_schemes"])

        # Search in binary
        for name in file_list:
            if name.endswith("App") or ".framework" in name:
                try:
                    content = archive.read(name)
                    for s in jb_strings:
                        if s.encode() in content:
                            evidence.append(f"Found jailbreak check: {s}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "jailbreak",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "high" if len(evidence) > 2 else "medium",
                "methods": ["file_check", "url_scheme", "fork_check"],
            }

        return None

    async def _detect_ssl_pinning(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
        platform: str,
    ) -> dict[str, Any] | None:
        """Detect SSL pinning implementation."""
        evidence = []

        libs = DETECTION_SIGNATURES["ssl_pinning"]["libraries"].get(platform, [])
        pinning_patterns = [
            "certificatepinner",
            "sslpinning",
            "trustmanager",
            "x509trustmanager",
            "pinnedcertificates",
        ]

        for name in file_list:
            if name.endswith((".dex", ".so")) or (platform == "ios" and name.endswith("App")):
                try:
                    content = archive.read(name).decode("utf-8", errors="ignore").lower()
                    for pattern in pinning_patterns:
                        if pattern in content:
                            evidence.append(f"Found SSL pinning pattern: {pattern}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "ssl_pinning",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "high" if len(evidence) > 1 else "medium",
                "libraries": libs,
            }

        return None

    async def _detect_emulator_detection(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect emulator detection mechanisms."""
        evidence = []

        emu_patterns = ["goldfish", "ranchu", "genymotion", "bluestacks", "qemu", "emulator"]

        for name in file_list:
            if name.endswith(".dex"):
                try:
                    content = archive.read(name).decode("utf-8", errors="ignore").lower()
                    for pattern in emu_patterns:
                        if pattern in content:
                            evidence.append(f"Found emulator check: {pattern}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "emulator",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "medium",
                "methods": ["prop_check", "build_check"],
            }

        return None

    async def attempt_bypass(
        self,
        app: MobileApp,
        device: Device,
        detection_type: str,
        script: FridaScript | None = None,
    ) -> dict[str, Any]:
        """Attempt to bypass a specific protection."""
        result = {
            "detection_type": detection_type,
            "status": "not_attempted",
            "notes": "",
            "poc_evidence": "",
        }

        try:
            # Get appropriate bypass script
            if script:
                script_content = script.script_content
            else:
                script_content = await self._get_default_bypass_script(detection_type)

            if not script_content:
                result["status"] = "failed"
                result["notes"] = "No bypass script available"
                return result

            # Inject bypass script
            session_id = await self.frida.inject(
                device_id=device.device_id,
                package_name=app.package_name,
                script_content=script_content,
            )

            # Wait and check if app is running
            import asyncio
            await asyncio.sleep(3)

            # Check session messages for success/failure
            messages = await self.frida.get_session_messages(session_id)

            bypass_success = any(
                "[+]" in str(m.get("payload", ""))
                for m in messages
            )

            if bypass_success:
                result["status"] = "success"
                result["notes"] = "Bypass appears successful based on script output"
                result["poc_evidence"] = "\n".join(
                    str(m.get("payload", "")) for m in messages[:10]
                )
            else:
                result["status"] = "partial"
                result["notes"] = "Script injected but effectiveness unclear"

            # Detach
            await self.frida.detach(session_id)

        except Exception as e:
            result["status"] = "failed"
            result["notes"] = str(e)
            logger.error(f"Bypass attempt failed: {e}")

        return result

    async def _get_default_bypass_script(self, detection_type: str) -> str | None:
        """Get the default bypass script for a detection type."""
        # These would come from the database in production
        scripts = {
            "frida": "// Anti-Frida bypass\nJava.perform(function(){...});",
            "root": "// Root detection bypass\nJava.perform(function(){...});",
            "ssl_pinning": "// SSL pinning bypass\nJava.perform(function(){...});",
        }
        return scripts.get(detection_type)

    async def auto_bypass(
        self,
        app: MobileApp,
        device: Device,
        db: AsyncSession,
    ) -> list[dict[str, Any]]:
        """Automatically detect and bypass all protections."""
        results: list[dict[str, Any]] = []

        # First, analyze protections
        detections = await self.analyze_protections(app)

        # Get bypass scripts from database
        scripts_result = await db.execute(
            select(FridaScript).where(FridaScript.category == "bypass")
        )
        scripts = {s.subcategory: s for s in scripts_result.scalars().all()}

        # Attempt bypass for each detection
        for detection in detections:
            if detection["detected"]:
                script = scripts.get(detection["type"])
                result = await self.attempt_bypass(
                    app=app,
                    device=device,
                    detection_type=detection["type"],
                    script=script,
                )
                result["detection"] = detection
                results.append(result)

                # Save result to database
                bypass_result = BypassResult(
                    app_id=app.app_id,
                    device_id=device.device_id,
                    detection_type=detection["type"],
                    detection_method=",".join(detection.get("methods", [])),
                    bypass_status=result["status"],
                    bypass_notes=result["notes"],
                    poc_evidence=result.get("poc_evidence"),
                )
                db.add(bypass_result)

        await db.commit()
        return results
