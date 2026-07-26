"""Unit tests for cold-start, concept drift, new rules, and evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from synthetic_data.adaptation.cold_start import apply_cold_start, assess_cold_start
from synthetic_data.adaptation.concept_drift import ConceptDriftTracker
from synthetic_data.attack_classification.rules import (
    rule_insider_drift,
    rule_low_and_slow,
)
from synthetic_data.attack_types import AttackType
from synthetic_data.attacks import get_default_injectors
from synthetic_data.decision_status import derive_final_status, is_confirmable_attack
from synthetic_data.evaluation.metrics import (
    evaluate_predictions,
    is_insider_drift_only,
    is_true_intrusion,
    primary_gt_attack_label,
)
from synthetic_data.feature_engineering.feature_schema import FeatureVector


@dataclass
class _Pred:
    employee_id: str
    simulation_day: str
    raw_score: float
    normalized_score: float
    prediction: int
    is_anomaly: bool


def test_new_attack_types_registered() -> None:
    injectors = get_default_injectors()
    assert AttackType.DEVICE_SPOOFING in injectors
    assert AttackType.LOW_AND_SLOW_EXFIL in injectors
    assert AttackType.INSIDER_DRIFT in injectors


def test_cold_start_shrinks_high_score() -> None:
    vector = FeatureVector(
        employee_id="E1",
        simulation_day="2024-01-01",
        total_events=5,
    )
    pred = _Pred("E1", "2024-01-01", -1.0, 80.0, -1, True)
    assessment = assess_cold_start(vector, pred)
    assert assessment.is_cold_start is True
    assert assessment.adjusted_normalized_score < 80.0
    adjusted = apply_cold_start(pred, assessment)
    assert adjusted.normalized_score == assessment.adjusted_normalized_score


def test_cold_start_full_trust() -> None:
    vector = FeatureVector(
        employee_id="E1",
        simulation_day="2024-01-01",
        total_events=40,
    )
    pred = _Pred("E1", "2024-01-01", -1.0, 80.0, -1, True)
    assessment = assess_cold_start(vector, pred)
    assert assessment.is_cold_start is False
    assert assessment.trust == 1.0


def test_concept_drift_gradual_and_abrupt() -> None:
    tracker = ConceptDriftTracker()
    first = tracker.assess("E1", 20.0)
    assert first.is_gradual_drift is False
    gradual = tracker.assess("E1", 30.0)
    assert gradual.is_gradual_drift is True
    abrupt = tracker.assess("E1", 80.0)
    assert abrupt.is_abrupt_shift is True


def test_low_and_slow_and_insider_drift_rules() -> None:
    slow = rule_low_and_slow(
        {
            "download_size_mb_sum": 40.0,
            "median_idle_gap_sec": 900.0,
            "burst_max_5min": 3.0,
            "active_duration_hours": 5.0,
            "mass_download_event_count": 0.0,
        }
    )
    assert slow.matched is True
    drift = rule_insider_drift(
        {
            "unique_resource_count": 8.0,
            "resource_entropy": 2.0,
            "resource_switch_count": 6.0,
            "after_hours_event_count": 2.0,
            "mass_download_event_count": 0.0,
        }
    )
    assert drift.matched is True


def test_insider_drift_not_confirmable() -> None:
    assert is_confirmable_attack("Insider Drift") is False
    assert is_confirmable_attack("Brute Force") is True
    status = derive_final_status(90.0, "Insider Drift", 95.0)
    assert status != "Confirmed Threat"


def test_evaluation_metrics_imbalance_and_edge_case() -> None:
    vectors = [
        FeatureVector(
            employee_id="A",
            simulation_day="2024-01-01",
            brute_force_count=3,
            has_attack=1,
        ),
        FeatureVector(
            employee_id="B",
            simulation_day="2024-01-01",
            has_attack=0,
        ),
        FeatureVector(
            employee_id="C",
            simulation_day="2024-01-01",
            insider_drift_count=4,
            has_attack=1,
        ),
    ]
    assert is_true_intrusion(vectors[0]) is True
    assert is_insider_drift_only(vectors[2]) is True
    assert primary_gt_attack_label(vectors[0]) == "Brute Force"

    preds = [
        _Pred("A", "2024-01-01", -1.0, 80.0, -1, True),
        _Pred("B", "2024-01-01", 1.0, 10.0, 1, False),
        _Pred("C", "2024-01-01", -1.0, 60.0, -1, True),
    ]
    report = evaluate_predictions(
        vectors,
        preds,
        predicted_attack_types=["Brute Force", "None", "Insider Drift"],
        alert_budgets=(33.0,),
    )
    assert report.binary.true_positives == 1
    assert report.binary.support_positive == 1  # drift excluded
    assert report.attack_types.overall_accuracy == 1.0
    assert report.edge_case_insider_drift["days"] == 1
    assert len(report.alert_budgets) == 1
