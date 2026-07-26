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
    """Anomaly prediction fields exposed over HTTP."""

    employee_id: str
    simulation_day: str
    raw_score: float
    normalized_score: float
    prediction: int
    is_anomaly: bool


class SuspiciousEventOut(BaseModel):
    """Single influential event from Transformer reconstruction error."""

    index: int
    event_type: str
    reconstruction_error: float
    attention_mass: float = 0.0
    explanation: str = ""


class BehaviourInsightOut(BaseModel):
    """Transformer behavioural explainability payload for the SOC dashboard."""

    session_id: str = ""
    reconstruction_error: float = 0.0
    anomaly_score: float = 0.0
    behaviour_score: float = 0.0
    confidence_score: float = 0.0
    behaviour_embedding: list[float] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=list)
    per_event_errors: list[float] = Field(default_factory=list)
    attention_weights: list[list[float]] = Field(default_factory=list)
    attention_available: bool = True
    top_suspicious_events: list[SuspiciousEventOut] = Field(default_factory=list)
    model: str = "behaviour_transformer"


class MitreMappingOut(BaseModel):
    """MITRE ATT&CK mapping for a classified attack."""

    attack_type: str
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    description: str


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


class AttackClassificationOut(BaseModel):
    """Rule-based attack classification fields exposed over HTTP."""

    employee_id: str
    simulation_day: str
    attack_type: str
    attack_confidence: float
    matched_signals: list[str]


class ColdStartOut(BaseModel):
    """Cold-start handling metadata for thin-history entities."""

    is_cold_start: bool
    event_count: int
    trust: float
    reason: str
    adjusted_normalized_score: float


class ConceptDriftOut(BaseModel):
    """Concept-drift EWMA metadata for evolving legitimate behaviour."""

    entity_id: str
    ewma: float
    delta: float
    is_gradual_drift: bool
    is_abrupt_shift: bool
    reason: str
    adjusted_normalized_score: float


class PredictResponse(BaseModel):
    """Combined pipeline result for one employee-day."""

    prediction: AnomalyPredictionOut
    risk_assessment: RiskAssessmentOut
    attack_classification: AttackClassificationOut
    explanation: RiskExplanationOut
    status: str = Field(
        ...,
        description="Final SOC status: Normal | Suspicious | Confirmed Threat",
    )
    behaviour_insight: BehaviourInsightOut | None = None
    mitre: MitreMappingOut | None = None
    cold_start: ColdStartOut | None = None
    concept_drift: ConceptDriftOut | None = None
    campaign_id: str | None = Field(
        default=None,
        description=(
            "Optional correlation metadata from the request payload "
            "(not an ML feature)."
        ),
    )


class PredictBatchResponse(BaseModel):
    """Batch pipeline results."""

    results: list[PredictResponse]


class CampaignStageOut(BaseModel):
    """One stage in a correlated kill-chain case."""

    stage_index: int
    stage_label: str
    employee_id: str
    simulation_day: str
    attack_type: str
    attack_confidence: float
    risk_score: float
    risk_level: str
    status: str
    matched_signals: list[str] = Field(default_factory=list)
    contributing_factors: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    mitre: MitreMappingOut | None = None
    is_focus: bool = False
    result_index: int | None = None


class CampaignCaseOut(BaseModel):
    """Correlated multi-stage campaign for SOC investigation."""

    case_id: str
    campaign_id: str | None = None
    campaign_name: str
    campaign_type: str
    correlation_basis: str
    summary: str
    entity_ids: list[str]
    stage_count: int
    peak_risk_score: float
    peak_risk_level: str
    status: str
    stages: list[CampaignStageOut]
    focus_stage_index: int | None = None


class CorrelateCampaignsRequest(BaseModel):
    """Request body for ``POST /correlate/campaigns``."""

    results: list[PredictResponse] = Field(
        ...,
        min_length=1,
        description="Scored batch results to correlate into campaign cases",
    )
    focus_employee_id: str | None = Field(
        default=None,
        description="Highlight / prefer the case containing this employee",
    )
    focus_simulation_day: str | None = Field(
        default=None,
        description="Optional day to mark as the focus stage",
    )


class CorrelateCampaignsResponse(BaseModel):
    """Correlated campaign cases for a scored batch."""

    cases: list[CampaignCaseOut]
    focus_case: CampaignCaseOut | None = None
    multi_stage_count: int = 0


class TimelineEventPayload(BaseModel):
    """Raw timeline event for streaming / window scoring."""

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(..., min_length=1)
    employee_id: str = Field(..., min_length=1)
    timestamp: str = Field(..., description="ISO timestamp")
    event_type: str = Field(..., min_length=1)
    device_id: str = "DEV-UNKNOWN"
    location_id: str = "LOC-UNKNOWN"
    session_id: str = "SESS-UNKNOWN"
    resource_id: str | None = None
    browser: str | None = None
    operating_system: str | None = None
    result: str = "success"
    metadata: dict[str, Any] = Field(default_factory=dict)


class StreamWindowRequest(BaseModel):
    """Near-real-time window of events to score as employee-days."""

    events: list[TimelineEventPayload] = Field(
        ...,
        min_length=1,
        description="Buffered stream window (one or more entities)",
    )
    flush_every: int = Field(
        32,
        ge=1,
        le=500,
        description="Soft flush size for StreamingScorer buffering",
    )


class StreamWindowResponse(BaseModel):
    """Streaming window scoring results."""

    windows_scored: int
    results: list[PredictResponse]
    mode: str = "stream-window"


class ErrorResponse(BaseModel):
    """Uniform error payload (no stack traces)."""

    detail: str
    code: str | None = None


def feature_payload_to_dict(payload: FeatureVectorPayload) -> dict[str, Any]:
    """Flatten a feature payload into a plain dict (includes extras)."""
    return payload.model_dump()
