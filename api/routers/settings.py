"""Settings router for configuration and health status."""

import logging
import socket

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import get_settings
from api.database import get_db

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("")
async def get_settings_config():
    """Return safe (non-secret) configuration values."""
    settings = get_settings()
    return {
        "database": {
            "host": settings.postgres_host,
            "port": settings.postgres_port,
            "database": settings.postgres_db,
            "user": settings.postgres_user,
        },
        "neo4j": {
            "uri": settings.neo4j_uri,
        },
        "redis": {
            "url": settings.redis_url,
        },
        "api": {
            "host": settings.api_host,
            "port": settings.api_port,
            "debug": settings.api_debug,
            "log_level": settings.api_log_level,
        },
        "frida": {
            "server_version": settings.frida_server_version,
            "server_host": settings.frida_server_host,
        },
        "analysis": {
            "max_apk_size_mb": settings.max_apk_size_mb,
            "max_ipa_size_mb": settings.max_ipa_size_mb,
            "timeout_seconds": settings.analysis_timeout_seconds,
        },
        "paths": {
            "uploads": str(settings.uploads_path),
            "reports": str(settings.reports_path),
            "frida_scripts": str(settings.frida_scripts_path),
        },
        "tools": {
            "jadx": settings.jadx_path,
            "apktool": settings.apktool_path,
        },
    }


@router.get("/status")
async def get_system_status(db: AsyncSession = Depends(get_db)):
    """Return connection status for all services."""
    status = {}

    # PostgreSQL
    try:
        await db.execute(text("SELECT 1"))
        status["postgres"] = {"connected": True, "message": "Connected"}
    except Exception as e:
        status["postgres"] = {"connected": False, "message": str(e)}

    # Neo4j
    settings = get_settings()
    try:
        from neo4j import AsyncGraphDatabase

        driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        async with driver.session() as session:
            await session.run("RETURN 1")
        await driver.close()
        status["neo4j"] = {"connected": True, "message": "Connected"}
    except Exception as e:
        status["neo4j"] = {"connected": False, "message": str(e)}

    # Redis
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.close()
        status["redis"] = {"connected": True, "message": "Connected"}
    except Exception as e:
        status["redis"] = {"connected": False, "message": str(e)}

    # Frida Server
    if settings.frida_server_host:
        try:
            host, port = settings.frida_server_host.split(":")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, int(port)))
            sock.close()
            if result == 0:
                status["frida"] = {
                    "connected": True,
                    "message": f"Reachable at {settings.frida_server_host}",
                }
            else:
                status["frida"] = {
                    "connected": False,
                    "message": f"Cannot reach {settings.frida_server_host}",
                }
        except Exception as e:
            status["frida"] = {"connected": False, "message": str(e)}
    else:
        status["frida"] = {
            "connected": False,
            "message": "FRIDA_SERVER_HOST not configured",
        }

    return status
