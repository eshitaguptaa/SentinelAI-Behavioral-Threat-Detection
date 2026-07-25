"""FastAPI route tests with a mocked fitted Isolation Forest.

No model training occurs in this module.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from synthetic_data.anomaly_detection.scoring import AnomalyPrediction
from synthetic_data.api.app import create_app
from synthetic_data.api.routes import health, predict, predict_batch, root
from synthetic_data.api.schemas import (
    FeatureVectorPayload,
    PredictBatchRequest,
    PredictRequest,
)
from synthetic_data.feature_engineering.feature_schema import FeatureVector


def _vector_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "employee_id": "EMP-100",
        "simulation_day": "2026-03-10",
        "total_events": 25,
        "auth_failure_rate": 0.5,
        "max_failed_login_streak": 6,
        "country_change_count": 2,
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def mock_prediction() -> AnomalyPrediction:
    return AnomalyPrediction(
        employee_id="EMP-100",
        simulation_day="2026-03-10",
        raw_score=-0.2,
        normalized_score=68.0,
        prediction=-1,
        is_anomaly=True,
    )


@pytest.fixture
def mock_model(mock_prediction: AnomalyPrediction) -> MagicMock:
    model = MagicMock()
    model.is_fitted = True

    def _predict_one(vector: FeatureVector) -> AnomalyPrediction:
        return AnomalyPrediction(
            employee_id=vector.employee_id,
            simulation_day=vector.simulation_day,
            raw_score=mock_prediction.raw_score,
            normalized_score=mock_prediction.normalized_score,
            prediction=mock_prediction.prediction,
            is_anomaly=mock_prediction.is_anomaly,
        )

    def _predict(vectors: list[FeatureVector]) -> list[AnomalyPrediction]:
        return [_predict_one(vector) for vector in vectors]

    model.predict_one.side_effect = _predict_one
    model.predict.side_effect = _predict
    return model


@pytest.fixture
def request_with_model(mock_model: MagicMock) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(model=mock_model)))


def test_root_and_health() -> None:
    """System endpoints return expected payloads."""
    assert root().application == "SentinelAI"
    assert root().version == "2.0"
    assert health().status == "healthy"


def test_predict_route(
    request_with_model: SimpleNamespace,
    mock_model: MagicMock,
) -> None:
    """POST /predict pipeline via route function returns all sections."""
    body = PredictRequest(
        feature_vector=FeatureVectorPayload.model_validate(_vector_payload())
    )
    response = predict(request_with_model, body)
    mock_model.predict_one.assert_called_once()
    assert response.prediction.employee_id == "EMP-100"
    assert response.attack_classification.attack_type
    assert 0.0 <= response.attack_classification.attack_confidence <= 1.0
    assert response.risk_assessment.risk_level in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }
    assert response.explanation.summary
    assert response.explanation.recommendation
    assert response.status in {
        "Normal",
        "Suspicious",
        "Under Investigation",
        "Confirmed Threat",
    }
    # Status follows SOC workflow: Confirmed Threat needs rule + risk>=80 + conf>=80.
    assert response.attack_classification.attack_type != "Normal Activity"
    if response.attack_classification.attack_type in {
        "None",
        "Behavioural Anomaly",
        "Unknown Behaviour",
    }:
        assert response.status != "Confirmed Threat"
    if response.status == "Confirmed Threat":
        assert response.attack_classification.attack_type not in {
            "None",
            "Behavioural Anomaly",
            "Unknown Behaviour",
            "Normal Activity",
        }
        assert response.risk_assessment.risk_score >= 80.0
    if response.risk_assessment.risk_level == "LOW" and response.attack_classification.attack_type == "None":
        assert response.status == "Normal"
        assert response.attack_classification.attack_confidence == 0.0


def test_predict_batch_empty_rejected(request_with_model: SimpleNamespace) -> None:
    """Empty batch yields HTTP 400."""
    with pytest.raises(HTTPException) as exc_info:
        predict_batch(
            request_with_model,
            PredictBatchRequest(feature_vectors=[]),
        )
    assert exc_info.value.status_code == 400


def test_predict_batch_ok(request_with_model: SimpleNamespace) -> None:
    """Batch prediction returns one result per vector."""
    payloads = [
        FeatureVectorPayload.model_validate(_vector_payload(employee_id="EMP-100")),
        FeatureVectorPayload.model_validate(_vector_payload(employee_id="EMP-101")),
    ]
    response = predict_batch(
        request_with_model,
        PredictBatchRequest(feature_vectors=payloads),
    )
    assert len(response.results) == 2
    assert response.results[0].prediction.employee_id == "EMP-100"
    assert response.results[1].prediction.employee_id == "EMP-101"


def test_predict_without_model_returns_503() -> None:
    """Missing fitted model maps to HTTP 503."""
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(model=None)))
    body = PredictRequest(
        feature_vector=FeatureVectorPayload.model_validate(_vector_payload())
    )
    with pytest.raises(HTTPException) as exc_info:
        predict(request, body)
    assert exc_info.value.status_code == 503


def test_app_health_via_testclient() -> None:
    """ASGI app serves /health (does not require a loaded model)."""
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["application"] == "SentinelAI"
