"""Configuration settings for Mobilicustos API."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

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
        """Get async database URL."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_database_url(self) -> str:
        """Get sync database URL for migrations."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
