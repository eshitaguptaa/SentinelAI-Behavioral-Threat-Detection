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
    CampaignCaseOut,
    CampaignStageOut,
    ColdStartOut,
    ConceptDriftOut,
    CorrelateCampaignsRequest,
    CorrelateCampaignsResponse,
    ErrorResponse,
    FeatureVectorPayload,
    HealthResponse,
    MitreMappingOut,
    PredictBatchRequest,
    PredictBatchResponse,
    PredictRequest,
    PredictResponse,
    RiskAssessmentOut,
    RiskExplanationOut,
    RootResponse,
    StreamWindowRequest,
    StreamWindowResponse,
    SuspiciousEventOut,
    TimelineEventPayload,
    feature_payload_to_dict,
)
from synthetic_data.api.validation import (
    ApiValidationError,
    build_feature_vector_with_sequence,
    build_feature_vectors_with_sequences,
    require_fitted_model,
)
from synthetic_data.adaptation import (
    apply_cold_start,
    assess_cold_start,
    cold_start_dict,
    drift_dict,
    get_drift_tracker,
)
from synthetic_data.attack_classification import classify_attack
from synthetic_data.attack_classification.schema import AttackClassification
from synthetic_data.behavioural_transformer.schema import SessionSequence
from synthetic_data.campaign_correlation import (
    CampaignCase,
    correlate_campaigns,
    find_focus_case,
    sessions_from_predict_payloads,
)
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


def _extract_campaign_id(payload: FeatureVectorPayload | dict[str, Any]) -> str | None:
    """Pull optional campaign_id correlation metadata (not an ML feature)."""
    raw = (
        feature_payload_to_dict(payload)
        if isinstance(payload, FeatureVectorPayload)
        else dict(payload)
    )
    value = raw.get("campaign_id")
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _campaign_stage_out(stage: Any) -> CampaignStageOut:
    mitre = None
    if stage.mitre:
        mitre = MitreMappingOut(
            attack_type=str(stage.mitre.get("attack_type", stage.attack_type)),
            tactic_id=str(stage.mitre.get("tactic_id", "")),
            tactic_name=str(stage.mitre.get("tactic_name", "")),
            technique_id=str(stage.mitre.get("technique_id", "")),
            technique_name=str(stage.mitre.get("technique_name", "")),
            description=str(stage.mitre.get("description", "")),
        )
    return CampaignStageOut(
        stage_index=int(stage.stage_index),
        stage_label=str(stage.stage_label),
        employee_id=str(stage.employee_id),
        simulation_day=str(stage.simulation_day),
        attack_type=str(stage.attack_type),
        attack_confidence=float(stage.attack_confidence),
        risk_score=float(stage.risk_score),
        risk_level=str(stage.risk_level),
        status=str(stage.status),
        matched_signals=list(stage.matched_signals),
        contributing_factors=list(stage.contributing_factors),
        observations=list(stage.observations),
        mitre=mitre,
        is_focus=bool(stage.is_focus),
        result_index=stage.result_index,
    )


def _campaign_case_out(case: CampaignCase) -> CampaignCaseOut:
    return CampaignCaseOut(
        case_id=case.case_id,
        campaign_id=case.campaign_id,
        campaign_name=case.campaign_name,
        campaign_type=case.campaign_type,
        correlation_basis=case.correlation_basis,
        summary=case.summary,
        entity_ids=list(case.entity_ids),
        stage_count=int(case.stage_count),
        peak_risk_score=float(case.peak_risk_score),
        peak_risk_level=str(case.peak_risk_level),
        status=str(case.status),
        stages=[_campaign_stage_out(stage) for stage in case.stages],
        focus_stage_index=case.focus_stage_index,
    )


def _mitre_out(attack_type: str) -> MitreMappingOut | None:
    payload = mitre_dict(attack_type)
    if not payload:
        return None
    return MitreMappingOut(**payload)


def _cold_start_out(payload: dict[str, Any] | None) -> ColdStartOut | None:
    if not payload:
        return None
    return ColdStartOut(**payload)


def _drift_out(payload: dict[str, Any] | None) -> ConceptDriftOut | None:
    if not payload:
        return None
    return ConceptDriftOut(**payload)


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
    *,
    campaign_id: str | None = None,
) -> PredictResponse:
    """Execute Detector → Cold-start/Drift → Attack → Risk → Status → Explain.

    Attack classification runs before risk fusion so rule severity can feed
    the weighted risk score. Response schema gains optional cold_start /
    concept_drift metadata without breaking existing clients.
    """
    prediction = _predict_vector(model, vector, event_sequence)

    cold = assess_cold_start(vector, prediction)
    prediction = apply_cold_start(prediction, cold)

    tracker = get_drift_tracker()
    drift = tracker.assess(vector.employee_id, float(prediction.normalized_score))
    prediction = tracker.apply(prediction, drift)

    insight: dict[str, Any] | None = None
    if getattr(model, "detector_kind", None) == "transformer" and hasattr(
        model, "get_insight"
    ):
        raw_insight = model.get_insight(vector.employee_id, vector.simulation_day)
        if isinstance(raw_insight, dict):
            insight = raw_insight

    attack = classify_attack(
        vector,
        anomaly_score=float(prediction.normalized_score),
    )
    model_confidence = None
    if insight and insight.get("confidence_score") is not None:
        model_confidence = float(insight["confidence_score"])
    # Cold-start reduces effective confidence so thin history does not auto-confirm.
    if cold.is_cold_start and model_confidence is not None:
        model_confidence = model_confidence * cold.trust
    elif cold.is_cold_start:
        model_confidence = cold.trust

    assessment = assess_risk(
        prediction,
        vector,
        attack_confidence=float(attack.attack_confidence),
        model_confidence=model_confidence,
    )

    confidence_for_status = (
        model_confidence
        if model_confidence is not None
        else float(attack.attack_confidence)
    )
    final_status = derive_final_status(
        assessment.risk_score,
        attack.attack_type,
        confidence_for_status,
    )

    explanation = explain_risk(
        assessment,
        vector,
        attack_type=attack.attack_type,
        matched_signals=attack.matched_signals,
        status=final_status,
        confidence=confidence_for_status if confidence_for_status is not None else 0.5,
        behaviour_insight=insight,
    )

    # Surface adaptation signals in observations for analysts.
    if cold.is_cold_start:
        explanation.observations = [
            f"Cold-start: {cold.reason}",
            *list(explanation.observations),
        ]
    if drift.is_gradual_drift or drift.is_abrupt_shift:
        explanation.observations = [
            f"Concept drift: {drift.reason}",
            *list(explanation.observations),
        ]

    return PredictResponse(
        prediction=_prediction_out(prediction),
        risk_assessment=_assessment_out(assessment),
        attack_classification=_attack_out(attack),
        explanation=_explanation_out(explanation),
        status=final_status,
        behaviour_insight=_behaviour_out(insight),
        mitre=_mitre_out(attack.attack_type),
        cold_start=_cold_start_out(cold_start_dict(cold)),
        concept_drift=_drift_out(drift_dict(drift)),
        campaign_id=campaign_id,
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
        campaign_id = _extract_campaign_id(body.feature_vector)
        vector, event_sequence = build_feature_vector_with_sequence(body.feature_vector)
        return _run_pipeline(
            model,
            vector,
            event_sequence,
            campaign_id=campaign_id,
        )
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
            _run_pipeline(
                model,
                vector,
                sequence,
                campaign_id=_extract_campaign_id(payload),
            )
            for vector, sequence, payload in zip(
                vectors,
                sequences,
                body.feature_vectors,
                strict=True,
            )
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


@router.post(
    "/correlate/campaigns",
    response_model=CorrelateCampaignsResponse,
    summary="Correlate scored sessions into kill-chain campaign cases",
    description=(
        "Group batch prediction results into multi-stage CampaignCase objects "
        "using campaign_id metadata and/or same-entity signature attacks within "
        "a 7-day window. Does not retrain models or alter detection scores."
    ),
    responses={
        200: {"model": CorrelateCampaignsResponse},
        400: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
    tags=["correlation"],
)
def correlate_campaign_cases(
    body: CorrelateCampaignsRequest,
) -> CorrelateCampaignsResponse:
    """Build kill-chain cases from already-scored PredictResponse rows."""
    try:
        payloads = [result.model_dump() for result in body.results]
        sessions = sessions_from_predict_payloads(payloads)
        if not sessions:
            raise ApiValidationError(
                "No correlatable sessions in results",
                code="empty_sessions",
            )
        cases = correlate_campaigns(
            sessions,
            focus_employee_id=body.focus_employee_id,
            focus_simulation_day=body.focus_simulation_day,
        )
        focus = find_focus_case(
            cases,
            focus_employee_id=body.focus_employee_id,
            focus_simulation_day=body.focus_simulation_day,
        )
        case_outs = [_campaign_case_out(case) for case in cases]
        focus_out = _campaign_case_out(focus) if focus else None
        return CorrelateCampaignsResponse(
            cases=case_outs,
            focus_case=focus_out,
            multi_stage_count=sum(1 for case in cases if case.stage_count >= 2),
        )
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
            detail="Campaign correlation failed due to an internal error",
        ) from exc


def _timeline_from_payload(payload: TimelineEventPayload):
    """Convert an HTTP timeline payload into a ``TimelineEvent``."""
    from datetime import datetime

    from synthetic_data.generators.event_factory import TimelineEvent

    raw_ts = payload.timestamp.strip()
    try:
        timestamp = datetime.fromisoformat(raw_ts)
    except ValueError as exc:
        raise ApiValidationError(f"Invalid timestamp: {raw_ts}") from exc

    metadata = dict(payload.metadata or {})
    return TimelineEvent(
        event_id=payload.event_id,
        employee_id=payload.employee_id,
        timestamp=timestamp,
        event_type=payload.event_type,
        device_id=payload.device_id,
        location_id=payload.location_id,
        session_id=payload.session_id,
        resource_id=payload.resource_id,
        browser=payload.browser,
        operating_system=payload.operating_system,
        result=payload.result or "success",
        metadata=metadata,
    )


@router.post(
    "/predict/stream-window",
    response_model=StreamWindowResponse,
    summary="Score a near-real-time event window",
    description=(
        "Accept a buffered stream of raw timeline events, aggregate them into "
        "employee-day FeatureVectors, and run the full inference pipeline. "
        "Demonstrates streaming feasibility without requiring Kafka/Redis."
    ),
    responses={
        200: {"model": StreamWindowResponse},
        400: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    tags=["inference", "streaming"],
)
def predict_stream_window(
    request: Request,
    body: StreamWindowRequest,
) -> StreamWindowResponse:
    """Score one flushed stream window of raw events."""
    from synthetic_data.feature_engineering import build_feature_vectors
    from synthetic_data.streaming import StreamingScorer

    model = _get_model(request)
    try:
        timeline = [_timeline_from_payload(item) for item in body.events]
        scored: list[PredictResponse] = []

        def _score_window(window_events: list) -> list[PredictResponse]:
            if not window_events:
                return []
            vectors = build_feature_vectors(window_events)
            return [_run_pipeline(model, vector, None) for vector in vectors]

        scorer = StreamingScorer(
            score_fn=_score_window,
            flush_every=int(body.flush_every),
        )
        # Feed events; collect flush outputs, then flush remainder.
        for result in scorer.on_events(timeline):
            if isinstance(result, list):
                scored.extend(result)
        for result in scorer.flush_all():
            if isinstance(result, list):
                scored.extend(result)

        return StreamWindowResponse(
            windows_scored=len(scored),
            results=scored,
            mode="stream-window",
        )
    except ApiValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stream-window prediction failed due to an internal error",
        ) from exc
