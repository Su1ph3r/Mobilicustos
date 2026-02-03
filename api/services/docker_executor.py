"""Docker executor service for running analysis containers."""

import asyncio
import logging
import uuid
from pathlib import Path
from typing import Any

import docker
from docker.errors import ContainerError, ImageNotFound

logger = logging.getLogger(__name__)


class DockerExecutor:
    """Executes analysis tools in Docker containers."""

    def __init__(self):
        self.client = docker.from_env()
        self.network = "mobilicustos_mobilicustos"

    async def run_analyzer(
        self,
        image: str,
        command: list[str],
        volumes: dict[str, dict[str, str]] | None = None,
        environment: dict[str, str] | None = None,
        timeout: int = 3600,
        memory_limit: str = "4g",
    ) -> dict[str, Any]:
        """Run an analyzer container and return results."""
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
                "command": ["jadx", "-d", "/output", "/input/app"],
            },
            "apktool": {
                "image": "mobilicustos/apktool:latest",
                "command": ["apktool", "d", "-o", "/output", "/input/app"],
            },
            "blutter": {
                "image": "mobilicustos/blutter:latest",
                "command": ["python", "/opt/blutter/blutter.py", "/input/app", "/output"],
            },
            "hermes-dec": {
                "image": "mobilicustos/hermes-dec:latest",
                "command": ["python", "/opt/hermes-dec/hbc_decompiler.py", "/input/bundle", "/output"],
            },
        }

        if tool_name not in tool_configs:
            raise ValueError(f"Unknown tool: {tool_name}")

        config = tool_configs[tool_name]
        command = config["command"] + (extra_args or [])

        volumes = {
            str(input_path.parent): {"bind": "/input", "mode": "ro"},
            str(output_path): {"bind": "/output", "mode": "rw"},
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
