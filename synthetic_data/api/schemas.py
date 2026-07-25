"""Pydantic request/response schemas for the SentinelAI FastAPI layer.

These models are the HTTP contract only. Domain objects remain in Phase 8–11
packages and are constructed/converted at the route boundary.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RootResponse(BaseModel):
    """Response for ``GET /``."""

    application: str = "SentinelAI"
    version: str = "1.0"
    status: str = "running"


class HealthResponse(BaseModel):
    """Response for ``GET /health``."""

    status: str = "healthy"


class FeatureVectorPayload(BaseModel):
    """HTTP representation of a Phase 8 feature vector.

    Requires identity fields. Additional FeatureVector columns may be supplied
    as extra keys and are forwarded when constructing the domain object.
    """

    model_config = ConfigDict(extra="allow")

    employee_id: str = Field(..., min_length=1, description="Employee identifier")
    simulation_day: str = Field(
        ...,
        min_length=1,
        description="ISO simulation day (YYYY-MM-DD)",
    )


class PredictRequest(BaseModel):
    """Request body for ``POST /predict``."""

    feature_vector: FeatureVectorPayload


class PredictBatchRequest(BaseModel):
    """Request body for ``POST /predict/batch``."""

    feature_vectors: list[FeatureVectorPayload] = Field(
        ...,
        description="Non-empty list of feature vectors",
    )


class AnomalyPredictionOut(BaseModel):
    """Phase 9 anomaly prediction fields exposed over HTTP."""

    employee_id: str
    simulation_day: str
    raw_score: float
    normalized_score: float
    prediction: int
    is_anomaly: bool


class RiskAssessmentOut(BaseModel):
    """Phase 10 risk assessment fields exposed over HTTP."""

    employee_id: str
    simulation_day: str
    anomaly_score: float
    risk_score: float
    risk_level: str
    contributing_factors: list[str]
    recommendation: str


class RiskExplanationOut(BaseModel):
    """Phase 11 explanation fields exposed over HTTP."""

    employee_id: str
    simulation_day: str
    risk_score: float
    risk_level: str
    summary: str
    contributing_factors: list[str]
    observations: list[str]
    recommendation: str


class PredictResponse(BaseModel):
    """Combined pipeline result for one employee-day."""

    prediction: AnomalyPredictionOut
    risk_assessment: RiskAssessmentOut
    explanation: RiskExplanationOut


class PredictBatchResponse(BaseModel):
    """Batch pipeline results."""

    results: list[PredictResponse]


class ErrorResponse(BaseModel):
    """Uniform error payload (no stack traces)."""

    detail: str
    code: str | None = None


def feature_payload_to_dict(payload: FeatureVectorPayload) -> dict[str, Any]:
    """Flatten a feature payload into a plain dict (includes extras)."""
    return payload.model_dump()
