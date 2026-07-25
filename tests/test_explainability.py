"""Explainability Engine unit tests (deterministic, no ML)."""

from __future__ import annotations

from dataclasses import fields
from typing import Any

import pytest

from synthetic_data.explainability import ExplainabilityEngine, explain, explain_batch
from synthetic_data.explainability.explanations import summary_for_risk_level
from synthetic_data.explainability.schema import RiskExplanation
from synthetic_data.explainability.validation import ExplainabilityError
from synthetic_data.feature_engineering.feature_schema import FeatureVector
from synthetic_data.risk_engine.schema import RiskAssessment


def _vector(**overrides: Any) -> FeatureVector:
    allowed = {f.name for f in fields(FeatureVector)}
    base: dict[str, Any] = {
        "employee_id": "EMP-001",
        "simulation_day": "2026-03-10",
        "auth_failure_rate": 0.55,
        "max_failed_login_streak": 6,
        "country_change_count": 2,
        "unique_location_count": 3,
        "resource_entropy": 2.2,
        "device_entropy": 1.1,
        "unique_device_count": 3,
        "download_size_mb_sum": 120.0,
        "mass_download_event_count": 1,
        "after_hours_event_count": 11,
        "active_duration_hours": 13.0,
        "vpn_usage_ratio": 0.7,
        "burst_max_5min": 22,
        "has_attack": 1,
        "attack_event_count": 3,
        "label": 1,
    }
    base.update(overrides)
    return FeatureVector(**{k: v for k, v in base.items() if k in allowed})


def _assessment(**overrides: Any) -> RiskAssessment:
    base: dict[str, Any] = {
        "employee_id": "EMP-001",
        "simulation_day": "2026-03-10",
        "anomaly_score": 70.0,
        "risk_score": 88.0,
        "risk_level": "CRITICAL",
        "contributing_factors": [
            "High anomaly score",
            "High authentication failure rate",
        ],
        "recommendation": "Immediate incident response required.",
    }
    base.update(overrides)
    return RiskAssessment(**base)


def test_summaries_by_level() -> None:
    """Each risk level maps to a fixed summary string."""
    assert "consistent" in summary_for_risk_level("LOW").lower()
    assert "moderate" in summary_for_risk_level("MEDIUM").lower()
    assert "elevated" in summary_for_risk_level("HIGH").lower()
    assert "malicious" in summary_for_risk_level("CRITICAL").lower()


def test_explain_reuses_assessment_fields() -> None:
    """Factors and recommendation are copied; risk score is unchanged."""
    assessment = _assessment()
    vector = _vector()
    explanation = explain(assessment, vector)

    assert isinstance(explanation, RiskExplanation)
    assert explanation.risk_score == assessment.risk_score
    assert explanation.risk_level == assessment.risk_level
    assert explanation.recommendation == assessment.recommendation
    assert explanation.contributing_factors == assessment.contributing_factors
    assert explanation.summary == summary_for_risk_level("CRITICAL")
    assert explanation.observations
    assert all(isinstance(item, str) and item for item in explanation.observations)
    assert all("attack" not in item.lower() for item in explanation.observations)


def test_quiet_day_has_no_observations() -> None:
    """Thresholds produce an empty observation list for calm behaviour."""
    assessment = _assessment(
        risk_score=5.0,
        risk_level="LOW",
        contributing_factors=[],
        recommendation="Continue monitoring.",
        anomaly_score=5.0,
    )
    vector = _vector(
        auth_failure_rate=0.0,
        max_failed_login_streak=0,
        country_change_count=0,
        unique_location_count=1,
        resource_entropy=0.0,
        device_entropy=0.0,
        unique_device_count=1,
        download_size_mb_sum=0.0,
        mass_download_event_count=0,
        after_hours_event_count=0,
        active_duration_hours=8.0,
        vpn_usage_ratio=0.1,
        burst_max_5min=3,
        has_attack=0,
        attack_event_count=0,
        label=0,
    )
    explanation = explain(assessment, vector)
    assert explanation.observations == []
    assert "consistent" in explanation.summary.lower()


def test_identity_mismatch_raises() -> None:
    """Explainability rejects mismatched employee IDs."""
    with pytest.raises(ExplainabilityError) as exc_info:
        explain(_assessment(), _vector(employee_id="EMP-999"))
    assert exc_info.value.code == "identity_mismatch"


def test_explain_batch() -> None:
    """Batch explain returns aligned explanations."""
    engine = ExplainabilityEngine()
    assessments = [
        _assessment(employee_id="EMP-001"),
        _assessment(
            employee_id="EMP-002",
            risk_level="LOW",
            risk_score=8.0,
            anomaly_score=8.0,
            contributing_factors=[],
            recommendation="Continue monitoring.",
        ),
    ]
    vectors = [
        _vector(employee_id="EMP-001"),
        _vector(
            employee_id="EMP-002",
            auth_failure_rate=0.0,
            max_failed_login_streak=0,
            country_change_count=0,
            unique_location_count=1,
            resource_entropy=0.0,
            device_entropy=0.0,
            unique_device_count=1,
            download_size_mb_sum=0.0,
            mass_download_event_count=0,
            after_hours_event_count=0,
            burst_max_5min=2,
            vpn_usage_ratio=0.1,
            active_duration_hours=8.0,
        ),
    ]
    results = engine.explain_batch(assessments, vectors)
    assert len(results) == 2
    assert results[0].employee_id == "EMP-001"
    assert results[1].risk_level == "LOW"

    # Functional API parity
    again = explain_batch(assessments, vectors)
    assert again[0].summary == results[0].summary
