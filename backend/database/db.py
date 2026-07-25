"""Database engine and connection helpers."""

from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from core.config import get_settings
from core.logging import get_logger

logger = get_logger(__name__)


def build_engine() -> Engine:
    """Create the SQLAlchemy engine from application settings."""
    settings = get_settings()
    connect_args: dict[str, object] = {}

    # SQLite needs this flag when used with FastAPI's multi-threaded workers.
    if settings.database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(
        settings.database_url,
        connect_args=connect_args,
        pool_pre_ping=True,
        future=True,
    )
    logger.info("Database engine configured (%s)", settings.database_url.split("://", 1)[0])
    return engine


engine: Engine = build_engine()


def verify_connection(db_engine: Engine | None = None) -> None:
    """Verify the database is reachable with a lightweight probe query."""
    target = db_engine or engine
    with target.connect() as connection:
        connection.execute(text("SELECT 1"))
    logger.info("Database connection verified")
