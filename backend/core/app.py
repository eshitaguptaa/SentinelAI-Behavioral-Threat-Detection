"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import get_settings
from core.logging import get_logger, setup_logging
from database import verify_connection

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Run startup/shutdown hooks for the API process."""
    logger.info("Starting %s", get_settings().app_name)
    verify_connection()
    yield
    logger.info("Shutting down %s", get_settings().app_name)


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    settings = get_settings()
    setup_logging(settings.log_level)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        """Liveness probe — no business logic."""
        return {"status": "ok"}

    return app
