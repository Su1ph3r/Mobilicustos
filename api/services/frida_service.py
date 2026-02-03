"""Frida service for script injection and session management."""

import asyncio
import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# Track active sessions
_active_sessions: dict[str, dict[str, Any]] = {}


class FridaService:
    """Manages Frida script injection and sessions."""

    async def inject(
        self,
        device_id: str,
        package_name: str,
        script_content: str,
        spawn: bool = True,
    ) -> str:
        """Inject a Frida script into an app."""
        session_id = str(uuid.uuid4())

        try:
            # Dynamic import to avoid issues when frida not installed
            import frida

            # Get device
            if device_id.startswith("emulator-") or device_id.startswith("localhost:"):
                device = frida.get_device_manager().add_remote_device(device_id)
            else:
                device = frida.get_usb_device(timeout=5)

            # Attach or spawn
            if spawn:
                pid = device.spawn([package_name])
                session = device.attach(pid)
                device.resume(pid)
            else:
                session = device.attach(package_name)

            # Create and load script
            script = session.create_script(script_content)

            # Set up message handler
            messages: list[dict] = []

            def on_message(message: dict, data: Any):
                messages.append(message)
                if message["type"] == "send":
                    logger.info(f"[Frida] {message.get('payload', '')}")
                elif message["type"] == "error":
                    logger.error(f"[Frida Error] {message.get('description', '')}")

            script.on("message", on_message)
            script.load()

            # Store session info
            _active_sessions[session_id] = {
                "session_id": session_id,
                "device_id": device_id,
                "package_name": package_name,
                "session": session,
                "script": script,
                "messages": messages,
                "status": "active",
            }

            logger.info(f"Injected script into {package_name} (session: {session_id})")
            return session_id

        except ImportError:
            logger.error("Frida not installed")
            raise RuntimeError("Frida is not installed")
        except Exception as e:
            logger.error(f"Failed to inject script: {e}")
            raise

    async def detach(self, session_id: str) -> bool:
        """Detach from a Frida session."""
        if session_id not in _active_sessions:
            return False

        try:
            session_info = _active_sessions[session_id]
            session_info["script"].unload()
            session_info["session"].detach()
            session_info["status"] = "detached"
            del _active_sessions[session_id]
            return True
        except Exception as e:
            logger.error(f"Failed to detach session {session_id}: {e}")
            return False

    async def list_sessions(self) -> list[dict[str, Any]]:
        """List all active Frida sessions."""
        return [
            {
                "session_id": info["session_id"],
                "device_id": info["device_id"],
                "package_name": info["package_name"],
                "status": info["status"],
                "message_count": len(info["messages"]),
            }
            for info in _active_sessions.values()
        ]

    async def get_session_messages(self, session_id: str) -> list[dict]:
        """Get messages from a session."""
        if session_id not in _active_sessions:
            return []
        return _active_sessions[session_id]["messages"]

    async def send_rpc(
        self,
        session_id: str,
        method: str,
        *args: Any,
    ) -> Any:
        """Call an RPC method on a loaded script."""
        if session_id not in _active_sessions:
            raise ValueError(f"Session not found: {session_id}")

        try:
            script = _active_sessions[session_id]["script"]
            return await asyncio.to_thread(
                script.exports_sync.__getattr__(method),
                *args,
            )
        except Exception as e:
            logger.error(f"RPC call failed: {e}")
            raise

    async def list_processes(self, device_id: str) -> list[dict[str, Any]]:
        """List processes on a device."""
        try:
            import frida

            if device_id.startswith("emulator-") or device_id.startswith("localhost:"):
                device = frida.get_device_manager().add_remote_device(device_id)
            else:
                device = frida.get_usb_device(timeout=5)

            processes = device.enumerate_processes()
            return [
                {"pid": p.pid, "name": p.name}
                for p in processes
            ]
        except ImportError:
            logger.error("Frida not installed")
            return []
        except Exception as e:
            logger.error(f"Failed to list processes: {e}")
            return []

    async def list_apps(self, device_id: str) -> list[dict[str, Any]]:
        """List installed apps on a device."""
        try:
            import frida

            if device_id.startswith("emulator-") or device_id.startswith("localhost:"):
                device = frida.get_device_manager().add_remote_device(device_id)
            else:
                device = frida.get_usb_device(timeout=5)

            apps = device.enumerate_applications()
            return [
                {
                    "identifier": a.identifier,
                    "name": a.name,
                    "pid": a.pid if hasattr(a, "pid") else None,
                }
                for a in apps
            ]
        except ImportError:
            logger.error("Frida not installed")
            return []
        except Exception as e:
            logger.error(f"Failed to list apps: {e}")
            return []


class FridaScriptBuilder:
    """Helper to build Frida scripts."""

    def __init__(self):
        self.hooks: list[str] = []
        self.initialization: list[str] = []

    def add_java_hook(
        self,
        class_name: str,
        method_name: str,
        implementation: str,
    ) -> "FridaScriptBuilder":
        """Add a Java method hook."""
        hook = f"""
        try {{
            var {class_name.replace('.', '_')} = Java.use('{class_name}');
            {class_name.replace('.', '_')}.{method_name}.implementation = function() {{
                {implementation}
            }};
        }} catch(e) {{
            console.log('Hook failed for {class_name}.{method_name}: ' + e);
        }}
        """
        self.hooks.append(hook)
        return self

    def add_native_hook(
        self,
        module: str,
        export_name: str,
        on_enter: str = "",
        on_leave: str = "",
    ) -> "FridaScriptBuilder":
        """Add a native function hook."""
        hook = f"""
        try {{
            Interceptor.attach(Module.findExportByName('{module}', '{export_name}'), {{
                onEnter: function(args) {{
                    {on_enter}
                }},
                onLeave: function(retval) {{
                    {on_leave}
                }}
            }});
        }} catch(e) {{
            console.log('Native hook failed for {export_name}: ' + e);
        }}
        """
        self.hooks.append(hook)
        return self

    def build(self) -> str:
        """Build the final script."""
        java_hooks = "\n".join(self.hooks)
        init = "\n".join(self.initialization)

        return f"""
        {init}

        Java.perform(function() {{
            {java_hooks}
        }});
        """
