"""FastAPI routes exposing the SentinelAI inference pipeline.

Pipeline (no retraining)::

    FeatureVector → IsolationForest → RiskEngine → AttackClassification
        → Final Status → Explainability
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from synthetic_data.anomaly_detection.scoring import AnomalyPrediction
from synthetic_data.api.schemas import (
    AnomalyPredictionOut,
    AttackClassificationOut,
    ErrorResponse,
    HealthResponse,
    PredictBatchRequest,
    PredictBatchResponse,
    PredictRequest,
    PredictResponse,
    RiskAssessmentOut,
    RiskExplanationOut,
    RootResponse,
)
from synthetic_data.api.validation import (
    ApiValidationError,
    build_feature_vector,
    build_feature_vectors,
    require_fitted_model,
)
from synthetic_data.attack_classification import classify_attack
from synthetic_data.attack_classification.schema import AttackClassification
from synthetic_data.decision_status import derive_final_status
from synthetic_data.explainability import explain as explain_risk
from synthetic_data.explainability.schema import RiskExplanation
from synthetic_data.feature_engineering.feature_schema import FeatureVector
from synthetic_data.risk_engine import assess_risk
from synthetic_data.risk_engine.schema import RiskAssessment

router = APIRouter()


def _get_model(request: Request) -> Any:
    """Resolve the fitted Isolation Forest from application state."""
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


def _run_pipeline(model: Any, vector: FeatureVector) -> PredictResponse:
    """Execute IF → Risk → Attack Classification → Final Status → Explainability."""
    prediction = model.predict_one(vector)
    assessment = assess_risk(prediction, vector)
    attack = classify_attack(vector)
    final_status = derive_final_status(assessment.risk_level, attack.attack_type)
    explanation = explain_risk(assessment, vector)
    return PredictResponse(
        prediction=_prediction_out(prediction),
        risk_assessment=_assessment_out(assessment),
        attack_classification=_attack_out(attack),
        explanation=_explanation_out(explanation),
        status=final_status,
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
    return RootResponse(application="SentinelAI", version="1.0", status="running")


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
        "Run the SentinelAI inference pipeline on a single Phase 8 feature vector: "
        "Isolation Forest → Risk Engine → Attack Classification → Explainability. "
        "Does not retrain models."
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
        vector = build_feature_vector(body.feature_vector)
        return _run_pipeline(model, vector)
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
        "vectors, including rule-based attack classification. Deterministic O(n)."
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
        vectors = build_feature_vectors(body.feature_vectors)
        predictions = model.predict(vectors)
        results: list[PredictResponse] = []
        for prediction, vector in zip(predictions, vectors, strict=True):
            assessment = assess_risk(prediction, vector)
            attack = classify_attack(vector)
            final_status = derive_final_status(
                assessment.risk_level,
                attack.attack_type,
            )
            explanation = explain_risk(assessment, vector)
            results.append(
                PredictResponse(
                    prediction=_prediction_out(prediction),
                    risk_assessment=_assessment_out(assessment),
                    attack_classification=_attack_out(attack),
                    explanation=_explanation_out(explanation),
                    status=final_status,
                )
            )
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
