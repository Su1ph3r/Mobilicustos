"""Docker executor service for running analysis containers."""

import asyncio
import logging
import uuid
from pathlib import Path
from typing import Any, Callable

import docker
from docker.errors import ContainerError, ImageNotFound

logger = logging.getLogger(__name__)


class DockerExecutor:
    """Executes analysis tools in Docker containers."""

    def __init__(self):
        self.client = docker.from_env()
        self.network = "mobilicustos_mobilicustos"
        import os
        # Shared analyzer temp path - same on host and in container
        self._analyzer_temp_path = os.environ.get("ANALYZER_TEMP_PATH", "/tmp/mobilicustos_analyzer")

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
        """Run an analyzer container and return results.

        Args:
            progress_callback: Optional callback(log_line: str) for streaming progress
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
        """Stream container logs to a callback function."""
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
        """Run a specific tool on an input file."""
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
        """Build a Docker image."""
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
        """Pull a Docker image."""
        try:
            await asyncio.to_thread(self.client.images.pull, image)
            return True
        except Exception as e:
            logger.error(f"Failed to pull image {image}: {e}")
            return False

    async def image_exists(self, image: str) -> bool:
        """Check if a Docker image exists locally."""
        try:
            await asyncio.to_thread(self.client.images.get, image)
            return True
        except ImageNotFound:
            return False

    async def cleanup_old_containers(self, prefix: str = "mobilicustos-analyzer"):
        """Clean up old analyzer containers."""
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
