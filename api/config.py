"""Configuration settings for the Mobilicustos API.

All settings are loaded from environment variables (or a ``.env`` file) using
pydantic-settings. The ``get_settings()`` function returns a cached singleton
instance.

Environment variables are case-insensitive and extra variables (e.g.,
``VITE_*`` frontend vars) are silently ignored.
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Attributes:
        postgres_host: PostgreSQL server hostname.
        postgres_port: PostgreSQL server port.
        postgres_db: PostgreSQL database name.
        postgres_user: PostgreSQL username.
        postgres_password: PostgreSQL password.
        neo4j_uri: Neo4j Bolt connection URI for attack path graph storage.
        neo4j_user: Neo4j username.
        neo4j_password: Neo4j password.
        redis_url: Redis connection URL for caching and task queues.
        api_host: Bind address for the API server.
        api_port: Bind port for the API server.
        api_debug: Enable FastAPI debug mode.
        api_log_level: Logging level (debug, info, warning, error, critical).
        secret_key: Secret key for JWT signing and session encryption.
        jwt_algorithm: JWT signing algorithm (default HS256).
        jwt_expiration_hours: JWT token lifetime in hours.
        uploads_path: Directory for uploaded APK/IPA files.
        reports_path: Directory for generated PDF/HTML reports.
        frida_scripts_path: Directory for Frida JavaScript scripts.
        max_apk_size_mb: Maximum allowed APK upload size in megabytes.
        max_ipa_size_mb: Maximum allowed IPA upload size in megabytes.
        analysis_timeout_seconds: Maximum time for a single scan to complete.
        jadx_path: Path to the jadx decompiler binary.
        apktool_path: Path to the apktool binary.
        blutter_path: Path to the Blutter Flutter analyzer script.
        hermes_dec_path: Path to the hermes-dec React Native decompiler.
        corellium_api_key: API key for Corellium virtual device integration.
        corellium_domain: Corellium API base URL.
        frida_server_version: Frida server version to install on devices.
            Pin to 16.x for stability on some devices.
        frida_server_host: TCP ``host:port`` for remote frida-server access.
            Used when running inside Docker where USB is unavailable.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # Ignore extra env vars like VITE_* which are for frontend
    )

    # Database
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "mobilicustos"
    postgres_user: str = "mobilicustos"
    postgres_password: str = "changeme"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_debug: bool = False
    api_log_level: str = "info"

    # Security
    secret_key: str = "changeme_generate_random_key"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24

    # Paths
    uploads_path: Path = Path("/app/uploads")
    reports_path: Path = Path("/app/reports")
    frida_scripts_path: Path = Path("/app/frida-scripts")

    # Analysis
    max_apk_size_mb: int = 500
    max_ipa_size_mb: int = 1000
    analysis_timeout_seconds: int = 3600

    # Tools
    jadx_path: str = "/opt/jadx/bin/jadx"
    apktool_path: str = "/usr/local/bin/apktool"
    blutter_path: str = "/opt/blutter/blutter.py"
    hermes_dec_path: str = "/opt/hermes-dec/hbc_decompiler.py"

    # Corellium
    corellium_api_key: str = ""
    corellium_domain: str = "https://app.corellium.com"

    # Frida
    frida_server_version: str = "16.5.9"
    frida_server_host: str = ""  # TCP host:port for remote frida-server (e.g. host.docker.internal:27042)

    @property
    def database_url(self) -> str:
        """Construct the async PostgreSQL connection URL for asyncpg.

        Returns:
            Connection string in the format
            ``postgresql+asyncpg://user:pass@host:port/db``.
        """
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_database_url(self) -> str:
        """Construct the synchronous PostgreSQL connection URL for Alembic migrations.

        Returns:
            Connection string in the format
            ``postgresql://user:pass@host:port/db``.
        """
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    """Get or create the cached application settings singleton.

    Uses ``functools.lru_cache`` to ensure only one Settings instance is
    created per process, reading environment variables and ``.env`` file
    on first invocation.

    Returns:
        Cached Settings instance.
    """
    return Settings()
