"""Deterministic Risk Engine unit tests (no ML / no model training)."""

from __future__ import annotations

from dataclasses import fields
from typing import Any

import pytest

from synthetic_data.anomaly_detection.scoring import AnomalyPrediction
from synthetic_data.feature_engineering.feature_schema import FeatureVector
from synthetic_data.risk_engine import RiskEngine, assess_risk, assess_risks
from synthetic_data.risk_engine.schema import FORBIDDEN_RISK_FIELDS, RiskLevel
from synthetic_data.risk_engine.scoring import clamp_score, map_risk_level
from synthetic_data.risk_engine.validation import RiskEngineError


def _vector(**overrides: Any) -> FeatureVector:
    allowed = {f.name for f in fields(FeatureVector)}
    base: dict[str, Any] = {
        "employee_id": "EMP-001",
        "simulation_day": "2026-03-10",
        "total_events": 20,
        "auth_failure_rate": 0.0,
        "max_failed_login_streak": 0,
        "country_change_count": 0,
        "after_hours_event_count": 0,
        "download_size_mb_sum": 0.0,
        "mass_download_event_count": 0,
        "resource_entropy": 0.0,
        "device_entropy": 0.0,
        "unique_device_count": 1,
        "unique_location_count": 1,
        "location_change_count": 0,
        "vpn_usage_ratio": 0.1,
        "burst_max_5min": 3,
        "active_duration_hours": 8.0,
        "file_access_ratio": 0.1,
        # Ground-truth fields present on the object but unused by scoring.
        "has_attack": 1,
        "attack_event_count": 99,
        "brute_force_count": 5,
        "label": 1,
    }
    base.update(overrides)
    return FeatureVector(**{k: v for k, v in base.items() if k in allowed})


def _prediction(
    *,
    employee_id: str = "EMP-001",
    simulation_day: str = "2026-03-10",
    normalized_score: float = 10.0,
) -> AnomalyPrediction:
    return AnomalyPrediction(
        employee_id=employee_id,
        simulation_day=simulation_day,
        raw_score=0.1,
        normalized_score=normalized_score,
        prediction=1 if normalized_score < 50 else -1,
        is_anomaly=normalized_score >= 50,
    )


def test_clamp_and_risk_levels() -> None:
    """Score clamping and band mapping are deterministic."""
    assert clamp_score(-5) == 0.0
    assert clamp_score(150) == 100.0
    assert map_risk_level(0) == RiskLevel.LOW
    assert map_risk_level(24) == RiskLevel.LOW
    assert map_risk_level(25) == RiskLevel.MEDIUM
    assert map_risk_level(50) == RiskLevel.HIGH
    assert map_risk_level(75) == RiskLevel.CRITICAL


def test_low_risk_quiet_day() -> None:
    """Low anomaly + quiet behaviour → LOW fused risk."""
    assessment = assess_risk(
        _prediction(normalized_score=5.0),
        _vector(),
        attack_confidence=0.0,
        model_confidence=0.55,
    )
    assert assessment.risk_level == "LOW"
    assert 0.0 <= assessment.risk_score < 35.0
    assert assessment.recommendation == "Continue monitoring."


def test_fused_risk_not_equal_to_anomaly() -> None:
    """Weighted fusion produces a distinct risk score (not a copy of anomaly)."""
    assessment = assess_risk(
        _prediction(normalized_score=40.0),
        _vector(auth_failure_rate=0.3, max_failed_login_streak=4),
        attack_confidence=0.84,
        model_confidence=0.7,
    )
    assert assessment.risk_score != assessment.anomaly_score
    assert 0.0 <= assessment.risk_score <= 100.0


def test_attack_ground_truth_does_not_change_score() -> None:
    """Identical behavioural features yield identical risk regardless of labels."""
    pred = _prediction(normalized_score=40.0)
    with_labels = _vector(has_attack=1, attack_event_count=50, brute_force_count=9, label=1)
    clean = _vector(has_attack=0, attack_event_count=0, brute_force_count=0, label=0)
    a = assess_risk(pred, with_labels)
    b = assess_risk(pred, clean)
    assert a.risk_score == b.risk_score
    assert a.risk_level == b.risk_level
    assert a.contributing_factors == b.contributing_factors


def test_behavioural_uplift_and_factors() -> None:
    """Elevated behavioural signals increase fused risk via behaviour_score."""
    pred = _prediction(normalized_score=55.0)
    vector = _vector(
        auth_failure_rate=0.6,
        max_failed_login_streak=8,
        country_change_count=3,
        after_hours_event_count=20,
        download_size_mb_sum=200.0,
    )
    quiet = assess_risk(pred, _vector(), attack_confidence=0.0, model_confidence=0.7)
    assessment = assess_risk(
        pred, vector, attack_confidence=0.9, model_confidence=0.85
    )
    assert assessment.risk_score > quiet.risk_score
    assert assessment.contributing_factors
    assert all(isinstance(factor, str) and factor for factor in assessment.contributing_factors)
    joined = " ".join(assessment.contributing_factors).lower()
    assert "attack" not in joined


def test_forbidden_fields_constant() -> None:
    """Forbidden production fields remain documented and non-empty."""
    assert "has_attack" in FORBIDDEN_RISK_FIELDS
    assert "label" in FORBIDDEN_RISK_FIELDS
    assert "brute_force_count" in FORBIDDEN_RISK_FIELDS


def test_batch_assess_risks() -> None:
    """Batch assessment preserves order and length."""
    engine = RiskEngine()
    preds = [
        _prediction(employee_id="EMP-001", normalized_score=10),
        _prediction(employee_id="EMP-002", normalized_score=80),
    ]
    vectors = [
        _vector(employee_id="EMP-001"),
        _vector(employee_id="EMP-002", auth_failure_rate=0.55, max_failed_login_streak=6),
    ]
    results = engine.assess_risks(preds, vectors)
    assert len(results) == 2
    assert results[0].employee_id == "EMP-001"
    assert results[1].employee_id == "EMP-002"
    assert results[1].risk_score >= results[0].risk_score


def test_invalid_anomaly_score_raises() -> None:
    """Out-of-range anomaly scores are rejected."""
    bad = _prediction(normalized_score=120.0)
    with pytest.raises(RiskEngineError):
        assess_risk(bad, _vector())


def test_assess_risks_functional_api() -> None:
    """Module-level assess_risks mirrors RiskEngine.assess_risks."""
    results = assess_risks(
        [_prediction(normalized_score=12.0)],
        [_vector()],
    )
    assert len(results) == 1
    assert results[0].risk_level == "LOW"
