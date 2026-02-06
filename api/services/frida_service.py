"""Frida dynamic instrumentation service for script injection and session management.

This module provides a high-level Python interface to the Frida instrumentation
toolkit, enabling runtime injection of JavaScript hooks into running mobile
applications. It supports both USB-connected physical devices and TCP-connected
remote/emulator targets.

Key capabilities:
    - Spawn or attach to target applications on Android and iOS devices.
    - Inject arbitrary Frida JavaScript scripts with message capture.
    - Manage multiple concurrent instrumentation sessions.
    - Invoke RPC exports defined in loaded scripts.
    - Enumerate running processes and installed applications.

Important version constraints:
    - frida-server 17.x crashes with SIGABRT on some devices (e.g., Pixel 3 XL
      Android 11). Pin to frida>=16.5.9,<17.0.0 for stability.
    - Client and server major versions must match for spawn/attach to work.

Note:
    When running inside Docker, USB device access is unavailable. Use
    ``FRIDA_SERVER_HOST`` env var to connect via TCP tunnel instead of USB.
"""

import asyncio
import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# Track active sessions
_active_sessions: dict[str, dict[str, Any]] = {}


class FridaService:
    """Manages Frida script injection, session lifecycle, and device communication.

    Provides async wrappers around the synchronous Frida Python API using
    ``asyncio.to_thread`` to avoid blocking the event loop. Sessions are tracked
    in an in-memory dictionary keyed by session ID.

    All operations include timeouts (default 30s) to prevent indefinite hangs
    when devices become unresponsive.
    """

    async def inject(
        self,
        device_id: str,
        package_name: str,
        script_content: str,
        spawn: bool = True,
    ) -> str:
        """Inject a Frida script into a target application.

        Connects to the device (USB or TCP), spawns or attaches to the target
        process, loads the script, and registers a message handler that captures
        all ``send()`` and error messages.

        Args:
            device_id: ADB device serial or TCP address (e.g., "localhost:27042").
            package_name: Android package name or iOS bundle identifier.
            script_content: JavaScript source code to inject.
            spawn: If True, spawn a fresh process; if False, attach to running process.

        Returns:
            Session ID string (UUID4) for subsequent operations (detach, messages, RPC).

        Raises:
            RuntimeError: If Frida is not installed, operation times out, or injection fails.
        """
        session_id = str(uuid.uuid4())

        try:
            # Dynamic import to avoid issues when frida not installed
            import frida

            # Get device
            if device_id.startswith("emulator-") or device_id.startswith("localhost:"):
                device = frida.get_device_manager().add_remote_device(device_id)
            else:
                device = frida.get_usb_device(timeout=5)

            # Attach or spawn (with timeouts to prevent hanging)
            if spawn:
                pid = await asyncio.wait_for(
                    asyncio.to_thread(device.spawn, [package_name]),
                    timeout=30,
                )
                session = await asyncio.wait_for(
                    asyncio.to_thread(device.attach, pid),
                    timeout=30,
                )
                await asyncio.wait_for(
                    asyncio.to_thread(device.resume, pid),
                    timeout=30,
                )
            else:
                session = await asyncio.wait_for(
                    asyncio.to_thread(device.attach, package_name),
                    timeout=30,
                )

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
        except asyncio.TimeoutError:
            logger.error(f"Timed out injecting script into {package_name}")
            raise RuntimeError(f"Frida operation timed out for {package_name}")
        except Exception as e:
            logger.error(f"Failed to inject script: {e}")
            raise

    async def detach(self, session_id: str) -> bool:
        """Detach from a Frida session and clean up resources.

        Unloads the injected script, detaches the Frida session from the
        target process, and removes the session from the in-memory registry.

        Args:
            session_id: UUID4 session identifier returned by ``inject()``.

        Returns:
            True if the session was found and successfully detached, False if
            the session ID was not found or detachment failed.
        """
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
        """List all active Frida sessions with summary metadata.

        Returns:
            List of dicts, each containing: ``session_id``, ``device_id``,
            ``package_name``, ``status``, and ``message_count``.
        """
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
        """Retrieve all messages captured from a Frida session.

        Messages are accumulated by the ``on_message`` handler registered
        during ``inject()``. Each message dict contains at minimum a ``type``
        field (``"send"`` or ``"error"``) and a ``payload`` or ``description``.

        Args:
            session_id: UUID4 session identifier returned by ``inject()``.

        Returns:
            List of message dicts, or an empty list if the session is not found.
        """
        if session_id not in _active_sessions:
            return []
        return _active_sessions[session_id]["messages"]

    async def send_rpc(
        self,
        session_id: str,
        method: str,
        *args: Any,
    ) -> Any:
        """Invoke an RPC export defined in a loaded Frida script.

        Calls a method exposed via ``rpc.exports`` in the injected JavaScript.
        The call is executed synchronously on the Frida agent thread via
        ``asyncio.to_thread`` to avoid blocking the event loop.

        Args:
            session_id: UUID4 session identifier returned by ``inject()``.
            method: Name of the RPC export to invoke (must match a key in
                ``rpc.exports`` within the loaded script).
            *args: Positional arguments to pass to the RPC method.

        Returns:
            The return value from the RPC export.

        Raises:
            ValueError: If the session ID is not found.
            Exception: If the RPC call fails on the Frida agent side.
        """
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
        """Enumerate running processes on a connected device.

        Connects to the device via USB or TCP and calls
        ``device.enumerate_processes()``. Unlike spawn/attach, process
        enumeration works even with mismatched client/server major versions.

        Args:
            device_id: ADB device serial or TCP address (e.g., ``"localhost:27042"``).

        Returns:
            List of dicts with ``pid`` (int) and ``name`` (str) for each
            running process, or an empty list on failure.
        """
        try:
            import frida

            if device_id.startswith("emulator-") or device_id.startswith("localhost:"):
                device = frida.get_device_manager().add_remote_device(device_id)
            else:
                device = frida.get_usb_device(timeout=5)

            processes = await asyncio.wait_for(
                asyncio.to_thread(device.enumerate_processes),
                timeout=30,
            )
            return [
                {"pid": p.pid, "name": p.name}
                for p in processes
            ]
        except ImportError:
            logger.error("Frida not installed")
            return []
        except asyncio.TimeoutError:
            logger.error("Timed out listing processes")
            return []
        except Exception as e:
            logger.error(f"Failed to list processes: {e}")
            return []

    async def list_apps(self, device_id: str) -> list[dict[str, Any]]:
        """Enumerate installed applications on a connected device.

        Connects to the device via USB or TCP and calls
        ``device.enumerate_applications()``.

        Args:
            device_id: ADB device serial or TCP address (e.g., ``"localhost:27042"``).

        Returns:
            List of dicts with ``identifier`` (package/bundle ID), ``name``
            (display name), and ``pid`` (int or None if not running) for each
            installed application, or an empty list on failure.
        """
        try:
            import frida

            if device_id.startswith("emulator-") or device_id.startswith("localhost:"):
                device = frida.get_device_manager().add_remote_device(device_id)
            else:
                device = frida.get_usb_device(timeout=5)

            apps = await asyncio.wait_for(
                asyncio.to_thread(device.enumerate_applications),
                timeout=30,
            )
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
        except asyncio.TimeoutError:
            logger.error("Timed out listing apps")
            return []
        except Exception as e:
            logger.error(f"Failed to list apps: {e}")
            return []


class FridaScriptBuilder:
    """Fluent builder for composing Frida JavaScript instrumentation scripts.

    Provides a programmatic interface for constructing Frida scripts that
    hook Java methods (via ``Java.use``) and native functions (via
    ``Interceptor.attach``). Hooks are accumulated via chained method calls
    and assembled into a single script by ``build()``.

    The generated script wraps all hooks inside ``Java.perform()`` so they
    execute after the Dalvik/ART VM is ready.

    Attributes:
        hooks: Accumulated JavaScript hook code fragments.
        initialization: JavaScript code to run before hooks (e.g., variable
            declarations, module imports).

    Example::

        script = (
            FridaScriptBuilder()
            .add_java_hook("com.example.Auth", "checkPassword",
                           "return true;")
            .add_native_hook("libc.so", "open",
                             on_enter="console.log(args[0].readUtf8String());")
            .build()
        )
    """

    def __init__(self):
        self.hooks: list[str] = []
        self.initialization: list[str] = []

    def add_java_hook(
        self,
        class_name: str,
        method_name: str,
        implementation: str,
    ) -> "FridaScriptBuilder":
        """Add a Java method hook using ``Java.use``.

        Generates JavaScript that replaces the target method's implementation
        with the provided code. The hook is wrapped in a try/catch to log
        failures without crashing the instrumentation session.

        Args:
            class_name: Fully qualified Java class name (e.g.,
                ``"com.example.security.PinCheck"``). Dots are replaced with
                underscores for the JavaScript variable name.
            method_name: Name of the method to hook.
            implementation: JavaScript code for the replacement implementation.
                Has access to ``this`` (the hooked object) and original
                arguments.

        Returns:
            Self for method chaining.
        """
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
        """Add a native function hook using ``Interceptor.attach``.

        Generates JavaScript that intercepts calls to the specified native
        export, invoking callbacks on function entry and/or exit. The hook
        is wrapped in a try/catch to handle missing exports gracefully.

        Args:
            module: Shared library name (e.g., ``"libc.so"``).
            export_name: Exported function symbol name (e.g., ``"open"``).
            on_enter: JavaScript code to execute on function entry. Has access
                to ``args`` (NativePointer array of function arguments).
            on_leave: JavaScript code to execute on function exit. Has access
                to ``retval`` (NativePointer return value, replaceable).

        Returns:
            Self for method chaining.
        """
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
        """Assemble all accumulated hooks into a complete Frida script.

        Combines initialization code and hooks, wrapping them in a
        ``Java.perform()`` callback so hooks are applied after the VM is
        ready.

        Returns:
            Complete JavaScript source string ready for injection via
            ``FridaService.inject()``.
        """
        java_hooks = "\n".join(self.hooks)
        init = "\n".join(self.initialization)

        return f"""
        {init}

        Java.perform(function() {{
            {java_hooks}
        }});
        """
