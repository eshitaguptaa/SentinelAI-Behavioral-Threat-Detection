"""FastAPI routes exposing the SentinelAI inference pipeline.

Pipeline (no retraining)::

    FeatureVector (+ optional event_sequence)
        → Anomaly Detector (Transformer or Isolation Forest)
        → RiskEngine → AttackClassification → MITRE → Final Status
        → Explainability (+ behavioural insight when Transformer)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from synthetic_data.anomaly_detection.scoring import AnomalyPrediction
from synthetic_data.api.schemas import (
    AnomalyPredictionOut,
    AttackClassificationOut,
    BehaviourInsightOut,
    ErrorResponse,
    HealthResponse,
    MitreMappingOut,
    PredictBatchRequest,
    PredictBatchResponse,
    PredictRequest,
    PredictResponse,
    RiskAssessmentOut,
    RiskExplanationOut,
    RootResponse,
    SuspiciousEventOut,
)
from synthetic_data.api.validation import (
    ApiValidationError,
    build_feature_vector_with_sequence,
    build_feature_vectors_with_sequences,
    require_fitted_model,
)
from synthetic_data.attack_classification import classify_attack
from synthetic_data.attack_classification.schema import AttackClassification
from synthetic_data.behavioural_transformer.schema import SessionSequence
from synthetic_data.decision_status import derive_final_status
from synthetic_data.explainability import explain as explain_risk
from synthetic_data.explainability.schema import RiskExplanation
from synthetic_data.feature_engineering.feature_schema import FeatureVector
from synthetic_data.mitre import mitre_dict
from synthetic_data.risk_engine import assess_risk
from synthetic_data.risk_engine.schema import RiskAssessment

router = APIRouter()


class _VectorWithSequence:
    """Adapter so Transformer models can read an explicit event sequence."""

    def __init__(
        self,
        vector: FeatureVector,
        event_sequence: list[str] | None,
    ) -> None:
        self._vector = vector
        self.event_sequence = event_sequence

    @property
    def employee_id(self) -> str:
        return self._vector.employee_id

    @property
    def simulation_day(self) -> str:
        return self._vector.simulation_day

    def ml_features(self) -> dict[str, float]:
        return self._vector.ml_features()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._vector, name)


def _get_model(request: Request) -> Any:
    """Resolve the fitted anomaly detector from application state."""
    return require_fitted_model(getattr(request.app.state, "model", None))


def _prediction_out(prediction: AnomalyPrediction) -> AnomalyPredictionOut:
    return AnomalyPredictionOut(
        employee_id=prediction.employee_id,
        simulation_day=prediction.simulation_day,
        raw_score=float(prediction.raw_score),
        normalized_score=float(prediction.normalized_score),
        prediction=int(prediction.prediction),
        is_anomaly=bool(prediction.is_anomaly),
    )


def _assessment_out(assessment: RiskAssessment) -> RiskAssessmentOut:
    return RiskAssessmentOut(
        employee_id=assessment.employee_id,
        simulation_day=assessment.simulation_day,
        anomaly_score=float(assessment.anomaly_score),
        risk_score=float(assessment.risk_score),
        risk_level=assessment.risk_level,
        contributing_factors=list(assessment.contributing_factors),
        recommendation=assessment.recommendation,
    )


def _attack_out(classification: AttackClassification) -> AttackClassificationOut:
    return AttackClassificationOut(
        employee_id=classification.employee_id,
        simulation_day=classification.simulation_day,
        attack_type=classification.attack_type,
        attack_confidence=float(classification.attack_confidence),
        matched_signals=list(classification.matched_signals),
    )


def _explanation_out(explanation: RiskExplanation) -> RiskExplanationOut:
    return RiskExplanationOut(
        employee_id=explanation.employee_id,
        simulation_day=explanation.simulation_day,
        risk_score=float(explanation.risk_score),
        risk_level=explanation.risk_level,
        summary=explanation.summary,
        contributing_factors=list(explanation.contributing_factors),
        observations=list(explanation.observations),
        recommendation=explanation.recommendation,
    )


def _behaviour_out(insight: dict[str, Any] | None) -> BehaviourInsightOut | None:
    if not insight:
        return None
    top_events = [
        SuspiciousEventOut(
            index=int(item.get("index", 0)),
            event_type=str(item.get("event_type", "")),
            reconstruction_error=float(item.get("reconstruction_error", 0.0)),
            attention_mass=float(item.get("attention_mass", 0.0)),
            explanation=str(item.get("explanation", "")),
        )
        for item in list(insight.get("top_suspicious_events") or [])
        if isinstance(item, dict) and "event_type" in item
    ]
    attention_available = bool(insight.get("attention_available", True))
    attention_weights = (
        [
            [float(cell) for cell in row]
            for row in list(insight.get("attention_weights") or [])
        ]
        if attention_available
        else []
    )
    return BehaviourInsightOut(
        session_id=str(insight.get("session_id", "")),
        reconstruction_error=float(insight.get("reconstruction_error", 0.0)),
        anomaly_score=float(insight.get("anomaly_score", 0.0)),
        behaviour_score=float(insight.get("behaviour_score", 0.0)),
        confidence_score=float(insight.get("confidence_score", 0.0)),
        behaviour_embedding=[float(x) for x in list(insight.get("behaviour_embedding") or [])],
        event_types=[str(x) for x in list(insight.get("event_types") or [])],
        per_event_errors=[float(x) for x in list(insight.get("per_event_errors") or [])],
        attention_weights=attention_weights,
        attention_available=attention_available,
        top_suspicious_events=top_events,
        model=str(insight.get("model", "behaviour_transformer")),
    )


def _mitre_out(attack_type: str) -> MitreMappingOut | None:
    payload = mitre_dict(attack_type)
    if not payload:
        return None
    return MitreMappingOut(**payload)


def _predict_vector(
    model: Any,
    vector: FeatureVector,
    event_sequence: list[str] | None,
) -> AnomalyPrediction:
    """Run the detector, preferring explicit sequences for Transformer models."""
    if (
        event_sequence
        and getattr(model, "detector_kind", None) == "transformer"
        and hasattr(model, "predict_one_sequence")
    ):
        sequence = SessionSequence(
            employee_id=vector.employee_id,
            session_id=f"API::{vector.employee_id}::{vector.simulation_day}",
            simulation_day=vector.simulation_day,
            event_types=list(event_sequence),
        )
        return model.predict_one_sequence(sequence)
    wrapped = _VectorWithSequence(vector, event_sequence)
    return model.predict_one(wrapped)


def _run_pipeline(
    model: Any,
    vector: FeatureVector,
    event_sequence: list[str] | None = None,
) -> PredictResponse:
    """Execute Detector → Risk → Attack → Status → Explainability."""
    prediction = _predict_vector(model, vector, event_sequence)
    assessment = assess_risk(prediction, vector)
    attack = classify_attack(vector)
    final_status = derive_final_status(assessment.risk_level, attack.attack_type)
    explanation = explain_risk(
        assessment,
        vector,
        attack_type=attack.attack_type,
        matched_signals=attack.matched_signals,
    )

    insight: dict[str, Any] | None = None
    if getattr(model, "detector_kind", None) == "transformer" and hasattr(
        model, "get_insight"
    ):
        raw_insight = model.get_insight(vector.employee_id, vector.simulation_day)
        if isinstance(raw_insight, dict):
            insight = raw_insight

    return PredictResponse(
        prediction=_prediction_out(prediction),
        risk_assessment=_assessment_out(assessment),
        attack_classification=_attack_out(attack),
        explanation=_explanation_out(explanation),
        status=final_status,
        behaviour_insight=_behaviour_out(insight),
        mitre=_mitre_out(attack.attack_type),
    )


@router.get(
    "/",
    response_model=RootResponse,
    summary="Application info",
    description="Return SentinelAI application metadata and running status.",
    responses={200: {"model": RootResponse}},
    tags=["system"],
)
def root() -> RootResponse:
    """Return application identity."""
    return RootResponse(application="SentinelAI", version="2.0", status="running")


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Liveness probe for process health (does not require a loaded model).",
    responses={200: {"model": HealthResponse}},
    tags=["system"],
)
def health() -> HealthResponse:
    """Return healthy status."""
    return HealthResponse(status="healthy")


@router.post(
    "/predict",
    response_model=PredictResponse,
    summary="Predict risk for one feature vector",
    description=(
        "Run the SentinelAI inference pipeline on a single Phase 8 feature vector "
        "(optional event_sequence for Transformer): Detector → Risk Engine → "
        "Attack Classification → MITRE → Explainability. Does not retrain models."
    ),
    responses={
        200: {"model": PredictResponse},
        400: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    tags=["inference"],
)
def predict(request: Request, body: PredictRequest) -> PredictResponse:
    """Predict anomaly, risk, attack type, and explanation for one employee-day."""
    model = _get_model(request)
    try:
        vector, event_sequence = build_feature_vector_with_sequence(body.feature_vector)
        return _run_pipeline(model, vector, event_sequence)
    except ApiValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — map to safe 500
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Prediction failed due to an internal error",
        ) from exc


@router.post(
    "/predict/batch",
    response_model=PredictBatchResponse,
    summary="Predict risk for a batch of feature vectors",
    description=(
        "Run the SentinelAI inference pipeline on a non-empty batch of feature "
        "vectors, including rule-based attack classification and optional "
        "Transformer behavioural insights. Deterministic O(n)."
    ),
    responses={
        200: {"model": PredictBatchResponse},
        400: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    tags=["inference"],
)
def predict_batch(request: Request, body: PredictBatchRequest) -> PredictBatchResponse:
    """Batch-predict anomaly, risk, attack type, and explanation."""
    model = _get_model(request)
    try:
        vectors, sequences = build_feature_vectors_with_sequences(body.feature_vectors)
        results = [
            _run_pipeline(model, vector, sequence)
            for vector, sequence in zip(vectors, sequences, strict=True)
        ]
        return PredictBatchResponse(results=results)
    except ApiValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — map to safe 500
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Batch prediction failed due to an internal error",
        ) from exc
