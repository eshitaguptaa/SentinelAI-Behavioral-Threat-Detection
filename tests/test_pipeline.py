"""End-to-end pipeline tests (FeatureVector → Risk → Explain).

Isolation Forest is mocked — tests never retrain models.
"""

from __future__ import annotations

from dataclasses import fields
from typing import Any
from unittest.mock import MagicMock

import pytest

from synthetic_data.anomaly_detection.scoring import AnomalyPrediction
from synthetic_data.explainability import explain
from synthetic_data.feature_engineering.feature_schema import FeatureVector
from synthetic_data.risk_engine import assess_risk


def _feature_vector(**overrides: Any) -> FeatureVector:
    allowed = {f.name for f in fields(FeatureVector)}
    payload: dict[str, Any] = {
        "employee_id": "EMP-001",
        "simulation_day": "2026-03-10",
        "total_events": 30,
        "auth_failure_rate": 0.4,
        "max_failed_login_streak": 5,
        "country_change_count": 2,
        "after_hours_event_count": 12,
        "download_size_mb_sum": 90.0,
        "resource_entropy": 2.1,
    }
    payload.update(overrides)
    return FeatureVector(**{k: v for k, v in payload.items() if k in allowed})


@pytest.fixture
def feature_vector() -> FeatureVector:
    return _feature_vector()


@pytest.fixture
def anomaly_prediction(feature_vector: FeatureVector) -> AnomalyPrediction:
    return AnomalyPrediction(
        employee_id=feature_vector.employee_id,
        simulation_day=feature_vector.simulation_day,
        raw_score=-0.15,
        normalized_score=72.0,
        prediction=-1,
        is_anomaly=True,
    )


@pytest.fixture
def mock_model(anomaly_prediction: AnomalyPrediction) -> MagicMock:
    model = MagicMock()
    model.is_fitted = True
    model.predict_one.return_value = anomaly_prediction
    model.predict.return_value = [anomaly_prediction]
    return model


def test_pipeline_predict_risk_explain(
    mock_model: MagicMock,
    feature_vector: FeatureVector,
    anomaly_prediction: AnomalyPrediction,
) -> None:
    """Mocked IF → risk → explainability produces aligned identities."""
    prediction = mock_model.predict_one(feature_vector)
    assessment = assess_risk(prediction, feature_vector)
    explanation = explain(assessment, feature_vector)

    mock_model.predict_one.assert_called_once_with(feature_vector)
    assert prediction.employee_id == feature_vector.employee_id
    assert assessment.employee_id == feature_vector.employee_id
    assert explanation.employee_id == feature_vector.employee_id
    assert assessment.anomaly_score == anomaly_prediction.normalized_score
    assert 0.0 <= assessment.risk_score <= 100.0
    assert explanation.risk_score == assessment.risk_score
    assert explanation.recommendation == assessment.recommendation
    assert explanation.contributing_factors == assessment.contributing_factors


def test_pipeline_risk_score_ge_anomaly(
    anomaly_prediction: AnomalyPrediction,
    feature_vector: FeatureVector,
) -> None:
    """Behavioural uplifts must not decrease the anomaly starting score below itself when uplifts apply."""
    assessment = assess_risk(anomaly_prediction, feature_vector)
    assert assessment.risk_score >= assessment.anomaly_score


def test_pipeline_rejects_identity_mismatch(
    anomaly_prediction: AnomalyPrediction,
) -> None:
    """Risk engine rejects mismatched employee identities."""
    other = _feature_vector(employee_id="EMP-999")
    with pytest.raises(Exception) as exc_info:
        assess_risk(anomaly_prediction, other)
    assert "mismatch" in str(exc_info.value).lower() or getattr(
        exc_info.value, "code", ""
    ) == "identity_mismatch"
