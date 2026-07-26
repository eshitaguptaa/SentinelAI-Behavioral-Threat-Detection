"""FastAPI application factory for the SentinelAI inference API.

Loads a pre-fitted Behavioural Transformer from ``SENTINELAI_MODEL_PATH``
at startup. Never trains or retrains models.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from synthetic_data.api.model_loader import load_anomaly_model
from synthetic_data.api.routes import router

APP_TITLE = "SentinelAI"
APP_VERSION = "2.0"

_DEFAULT_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)


def _cors_origins() -> list[str]:
    """Local defaults plus optional comma-separated ``CORS_ALLOW_ORIGINS``."""
    origins = list(_DEFAULT_ORIGINS)
    extra = (os.environ.get("CORS_ALLOW_ORIGINS") or "").strip()
    if extra:
        origins.extend(item.strip() for item in extra.split(",") if item.strip())
    seen: set[str] = set()
    unique: list[str] = []
    for origin in origins:
        if origin not in seen:
            seen.add(origin)
            unique.append(origin)
    return unique


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Attach a fitted anomaly detector + drift tracker (no training)."""
    from synthetic_data.adaptation import ConceptDriftTracker, set_drift_tracker

    app.state.model = load_anomaly_model()
    tracker = ConceptDriftTracker()
    set_drift_tracker(tracker)
    app.state.drift_tracker = tracker
    yield
    app.state.model = None
    app.state.drift_tracker = None


def create_app() -> FastAPI:
    """Build the SentinelAI FastAPI application."""
    application = FastAPI(
        title=APP_TITLE,
        version=APP_VERSION,
        description=(
            "SentinelAI inference API. Transformer-based behavioural anomaly "
            "detection with risk scoring, attack classification, MITRE mapping, "
            "explainability, cold-start handling, and concept-drift tracking. "
            "Does not retrain models."
        ),
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        """Return 422 without leaking internal exception objects."""
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": exc.errors(), "code": "request_validation_error"},
        )

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(
        _request: Request,
        _exc: Exception,
    ) -> JSONResponse:
        """Catch-all 500 without stack traces in the response body."""
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An unexpected server error occurred",
                "code": "internal_error",
            },
        )

    application.include_router(router)
    return application


app: FastAPI = create_app()
