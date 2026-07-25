"""Application settings loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

BACKEND_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SQLITE_PATH = BACKEND_ROOT / "sentinelai.db"


class Settings(BaseModel):
    """Runtime configuration for the SentinelAI API."""

    app_name: str = "SentinelAI"
    app_version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"
    database_url: str = f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    )


def _env_bool(name: str, default: bool = False) -> bool:
    import os

    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    import os

    raw = os.getenv(name)
    if not raw:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance (singleton for process lifetime)."""
    import os

    return Settings(
        app_name=os.getenv("APP_NAME", "SentinelAI"),
        app_version=os.getenv("APP_VERSION", "0.1.0"),
        debug=_env_bool("DEBUG", False),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        database_url=os.getenv(
            "DATABASE_URL",
            f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}",
        ),
        cors_origins=_env_list(
            "CORS_ORIGINS",
            ["http://localhost:5173", "http://127.0.0.1:5173"],
        ),
    )
