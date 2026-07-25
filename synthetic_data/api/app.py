"""FastAPI application factory for the SentinelAI inference API.

Loads a pre-fitted Isolation Forest from ``SENTINELAI_MODEL_PATH`` at startup.
Never trains or retrains models.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from synthetic_data.anomaly_detection import IsolationForestModel
from synthetic_data.anomaly_detection.validation import InvalidModelFileError
from synthetic_data.api.routes import router

APP_TITLE = "SentinelAI"
APP_VERSION = "1.0"
MODEL_PATH_ENV = "SENTINELAI_MODEL_PATH"


def _load_model_from_env() -> IsolationForestModel | None:
    """Load a fitted model from ``SENTINELAI_MODEL_PATH`` when configured."""
    raw = os.environ.get(MODEL_PATH_ENV, "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.exists():
        # Defer failure to predict endpoints (503) rather than crashing startup.
        return None
    try:
        return IsolationForestModel.load(path)
    except (InvalidModelFileError, OSError, ValueError):
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Attach a fitted Isolation Forest to ``app.state`` (no training)."""
    app.state.model = _load_model_from_env()
    yield
    app.state.model = None


def create_app() -> FastAPI:
    """Build the SentinelAI FastAPI application."""
    application = FastAPI(
        title=APP_TITLE,
        version=APP_VERSION,
        description=(
            "SentinelAI inference API. Exposes anomaly detection, risk scoring, "
            "and explainability over pre-computed Phase 8 feature vectors. "
            "Does not retrain models."
        ),
        lifespan=lifespan,
    )

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        """Return 422 without leaking internal exception objects."""
        # Keep Pydantic's structured errors; omit traceback.
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
