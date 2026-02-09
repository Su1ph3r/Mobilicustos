"""Docker executor service for running analysis containers.

Provides an async interface for executing security analysis tools (jadx,
apktool, blutter, hermes-dec) inside isolated Docker containers. Uses the
docker-py client to manage container lifecycle.

Architecture:
    The Mobilicustos API itself runs in a Docker container and spawns
    **sibling containers** (not nested containers) by mounting the host's
    Docker socket (``/var/run/docker.sock``). Volume mounts must reference
    host paths, not container paths -- see ``_container_to_host_path()`` for
    the path translation logic.

    The ``ANALYZER_TEMP_PATH`` environment variable defines a shared
    filesystem path that is bind-mounted identically on the host and API
    container, so no path translation is needed for files under that prefix.
"""

import asyncio
import logging
import uuid
from pathlib import Path
from typing import Any, Callable

import docker
from docker.errors import ContainerError, ImageNotFound

logger = logging.getLogger(__name__)


class DockerExecutor:
    """Executes analysis tools in isolated Docker containers.

    Manages the full container lifecycle: image resolution, container creation,
    log streaming, result collection, and cleanup. All blocking Docker API
    calls are delegated to ``asyncio.to_thread`` to avoid blocking the event
    loop.

    Attributes:
        client: docker-py ``DockerClient`` initialized from the host environment.
        network: Docker network name for inter-container communication.
    """

    def __init__(self):
        self.client = docker.from_env()
        self.network = "mobilicustos_mobilicustos"
        import os
        # Shared analyzer temp path - same on host and in container
        self._analyzer_temp_path = os.environ.get("ANALYZER_TEMP_PATH", "/tmp/mobilicustos_analyzer")

    def close(self) -> None:
        """Close the Docker client and release its connection pool."""
        try:
            self.client.close()
        except Exception:
            pass

    def _container_to_host_path(self, container_path: Path) -> Path:
        """Convert a container path to the corresponding host path.

        For paths under ANALYZER_TEMP_PATH, no conversion needed as the path
        is the same on host and in container (bind mount with same path).
        """
        path_str = str(container_path)
        # Paths under analyzer temp are the same on host and in container
        if path_str.startswith(self._analyzer_temp_path):
            return container_path
        # For other paths, return as-is (might need additional mappings)
        return container_path

    async def run_analyzer(
        self,
        image: str,
        command: list[str],
        volumes: dict[str, dict[str, str]] | None = None,
        environment: dict[str, str] | None = None,
        timeout: int = 3600,
        memory_limit: str = "4g",
        progress_callback: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Run an analysis tool in a Docker container and collect results.

        Creates a detached container with the given image and command, waits
        for it to complete (with timeout enforcement), collects stdout/stderr,
        and removes the container.

        Args:
            image: Docker image name and tag (e.g., ``"mobilicustos/jadx:latest"``).
            command: Command and arguments to execute inside the container.
            volumes: Docker volume mount specification mapping host paths to
                container bind mounts (e.g., ``{"/host/path": {"bind": "/container/path", "mode": "ro"}}``).
            environment: Environment variables to set inside the container.
            timeout: Maximum execution time in seconds (default 3600 = 1 hour).
            memory_limit: Container memory limit (default ``"4g"``).
            progress_callback: Optional callable invoked with each log line
                for real-time progress streaming.

        Returns:
            Dict with keys: ``exit_code`` (int), ``stdout`` (str),
            ``stderr`` (str), ``error`` (str or None).

        Raises:
            ValueError: If the Docker image is not found.
            RuntimeError: If the container exits with an error.
            TimeoutError: If the container exceeds the timeout.
        """
        container_name = f"mobilicustos-analyzer-{uuid.uuid4().hex[:8]}"

        try:
            # Run container
            container = await asyncio.to_thread(
                self.client.containers.run,
                image,
                command=command,
                name=container_name,
                volumes=volumes or {},
                environment=environment or {},
                network=self.network,
                mem_limit=memory_limit,
                detach=True,
                remove=False,
            )

            # Stream logs if callback provided
            if progress_callback:
                asyncio.create_task(
                    self._stream_logs(container, progress_callback)
                )

            # Wait for completion with timeout
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(container.wait),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning(f"Container {container_name} timed out, killing...")
                await asyncio.to_thread(container.kill)
                raise TimeoutError(f"Analyzer timed out after {timeout}s")

            # Get logs
            stdout = await asyncio.to_thread(
                container.logs, stdout=True, stderr=False
            )
            stderr = await asyncio.to_thread(
                container.logs, stdout=False, stderr=True
            )

            # Cleanup
            await asyncio.to_thread(container.remove)

            return {
                "exit_code": result.get("StatusCode", -1),
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "error": result.get("Error"),
            }

        except ImageNotFound:
            logger.error(f"Image not found: {image}")
            raise ValueError(f"Docker image not found: {image}")
        except ContainerError as e:
            logger.error(f"Container error: {e}")
            raise RuntimeError(f"Container failed: {e}")
        except Exception as e:
            logger.error(f"Docker execution error: {e}")
            raise

    async def _stream_logs(
        self,
        container,
        callback: Callable[[str], None],
    ) -> None:
        """Stream container logs to a callback function in real time.

        Runs the blocking Docker log stream in a background thread. Each
        decoded log line is passed to the callback. Exceptions in the
        callback are caught and logged to prevent stream interruption.

        Args:
            container: docker-py ``Container`` object to stream from.
            callback: Callable that receives each log line as a string.
        """
        def _blocking_stream():
            try:
                for log_line in container.logs(stream=True, follow=True):
                    decoded = log_line.decode("utf-8", errors="replace").strip()
                    if decoded:
                        try:
                            callback(decoded)
                        except Exception as e:
                            logger.debug(f"Log callback error: {e}")
            except Exception as e:
                logger.debug(f"Log streaming ended: {e}")

        await asyncio.to_thread(_blocking_stream)

    async def run_tool(
        self,
        tool_name: str,
        input_path: Path,
        output_path: Path,
        extra_args: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run a preconfigured analysis tool on an input file.

        Looks up the tool in the internal registry (jadx, apktool, blutter,
        hermes-dec), configures volume mounts with appropriate path translation
        for the sibling-container architecture, and delegates to
        ``run_analyzer()``.

        Args:
            tool_name: Name of the tool to run. Must be one of: ``"jadx"``,
                ``"apktool"``, ``"blutter"``, ``"hermes-dec"``.
            input_path: Path to the input file (e.g., APK, DEX, or Hermes bundle).
            output_path: Directory path where tool output will be written.
            extra_args: Additional command-line arguments to append to the
                tool's default command.

        Returns:
            Result dict from ``run_analyzer()`` with ``exit_code``, ``stdout``,
            ``stderr``, and ``error``.

        Raises:
            ValueError: If the tool name is not recognized.
        """
        tool_configs = {
            "jadx": {
                "image": "mobilicustos/jadx:latest",
                "command": ["jadx", "-d", "/output", "/input/{input_file}"],
            },
            "apktool": {
                "image": "mobilicustos/apktool:latest",
                "command": ["apktool", "d", "-o", "/output", "/input/{input_file}"],
            },
            "blutter": {
                "image": "mobilicustos/blutter:latest",
                "command": ["/input/{input_file}", "/output"],
            },
            "hermes-dec": {
                "image": "mobilicustos/hermes-dec:latest",
                "command": ["python", "/opt/hermes-dec/hbc_decompiler.py", "/input/{input_file}", "/output"],
            },
        }

        if tool_name not in tool_configs:
            raise ValueError(f"Unknown tool: {tool_name}")

        config = tool_configs[tool_name]

        # Replace {input_file} placeholder with actual filename
        input_filename = input_path.name
        command = [
            c.replace("{input_file}", input_filename) for c in config["command"]
        ] + (extra_args or [])

        # Map container paths to host paths for Docker volume mounts
        # The API runs in a container but spawns sibling containers via host Docker
        host_input_path = self._container_to_host_path(input_path.parent)
        host_output_path = self._container_to_host_path(output_path)

        volumes = {
            str(host_input_path): {"bind": "/input", "mode": "ro"},
            str(host_output_path): {"bind": "/output", "mode": "rw"},
        }

        # Ensure output directory exists
        output_path.mkdir(parents=True, exist_ok=True)

        return await self.run_analyzer(
            image=config["image"],
            command=command,
            volumes=volumes,
        )

    async def build_image(
        self,
        dockerfile_path: Path,
        tag: str,
    ) -> bool:
        """Build a Docker image from a Dockerfile.

        Args:
            dockerfile_path: Path to the Dockerfile. The parent directory is
                used as the build context.
            tag: Image tag to apply (e.g., ``"mobilicustos/jadx:latest"``).

        Returns:
            True if the image was built successfully, False on failure.
        """
        try:
            await asyncio.to_thread(
                self.client.images.build,
                path=str(dockerfile_path.parent),
                dockerfile=dockerfile_path.name,
                tag=tag,
                rm=True,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to build image {tag}: {e}")
            return False

    async def pull_image(self, image: str) -> bool:
        """Pull a Docker image from a registry.

        Args:
            image: Full image reference (e.g., ``"mobilicustos/jadx:latest"``).

        Returns:
            True if the pull succeeded, False on failure.
        """
        try:
            await asyncio.to_thread(self.client.images.pull, image)
            return True
        except Exception as e:
            logger.error(f"Failed to pull image {image}: {e}")
            return False

    async def image_exists(self, image: str) -> bool:
        """Check if a Docker image exists in the local image cache.

        Args:
            image: Full image reference to check.

        Returns:
            True if the image is available locally, False otherwise.
        """
        try:
            await asyncio.to_thread(self.client.images.get, image)
            return True
        except ImageNotFound:
            return False

    async def cleanup_old_containers(self, prefix: str = "mobilicustos-analyzer"):
        """Remove exited analyzer containers matching a name prefix.

        Iterates over all containers (including stopped ones) whose names
        match the prefix and removes those in the ``"exited"`` state.

        Args:
            prefix: Container name prefix to filter on (default
                ``"mobilicustos-analyzer"``).
        """
        containers = await asyncio.to_thread(
            self.client.containers.list,
            all=True,
            filters={"name": prefix},
        )

        for container in containers:
            try:
                if container.status == "exited":
                    await asyncio.to_thread(container.remove)
                    logger.info(f"Removed container: {container.name}")
            except Exception as e:
                logger.warning(f"Failed to remove container {container.name}: {e}")
