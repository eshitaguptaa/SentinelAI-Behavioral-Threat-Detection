"""Tests for non-signature attack labeling from anomaly score."""

from __future__ import annotations

from synthetic_data.attack_classification.labeling import resolve_unmatched_attack_type
from synthetic_data.attack_classification.rules import evaluate_rules
from synthetic_data.attack_classification.schema import AttackType


def test_resolve_unmatched_labels() -> None:
    assert resolve_unmatched_attack_type(10.0) is AttackType.NONE
    assert resolve_unmatched_attack_type(24.0) is AttackType.NONE
    assert resolve_unmatched_attack_type(35.0) is AttackType.UNKNOWN_BEHAVIOUR
    assert resolve_unmatched_attack_type(50.0) is AttackType.BEHAVIOURAL_ANOMALY
    assert resolve_unmatched_attack_type(90.0) is AttackType.BEHAVIOURAL_ANOMALY


def test_evaluate_rules_never_returns_normal_activity() -> None:
    quiet = {
        "country_change_count": 0.0,
        "auth_failure_rate": 0.0,
        "max_failed_login_streak": 0.0,
        "login_count": 1.0,
        "download_size_mb_sum": 0.0,
        "mass_download_event_count": 0.0,
        "unique_device_count": 1.0,
        "device_entropy": 0.0,
        "after_hours_event_count": 0.0,
        "active_duration_hours": 8.0,
        "file_access_ratio": 0.1,
        "vpn_usage_ratio": 0.1,
        "unique_location_count": 1.0,
        "location_change_count": 0.0,
    }
    low = evaluate_rules(quiet, anomaly_score=12.0)
    assert low.attack_type is AttackType.NONE
    high = evaluate_rules(quiet, anomaly_score=80.0)
    assert high.attack_type is AttackType.BEHAVIOURAL_ANOMALY
    assert high.attack_type is not AttackType.NORMAL_ACTIVITY
