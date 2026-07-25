"""Final status derivation tests (deterministic hierarchy)."""

from __future__ import annotations

import pytest

from synthetic_data.decision_status import FinalStatus, derive_final_status


@pytest.mark.parametrize(
    ("risk_level", "attack_type", "expected"),
    [
        ("LOW", "Normal Activity", FinalStatus.NORMAL.value),
        ("LOW", "Impossible Travel", FinalStatus.SUSPICIOUS.value),
        ("LOW", "Brute Force", FinalStatus.SUSPICIOUS.value),
        ("LOW", "Lateral Movement", FinalStatus.SUSPICIOUS.value),
        ("MEDIUM", "Device Spoofing", FinalStatus.SUSPICIOUS.value),
        ("MEDIUM", "Normal Activity", FinalStatus.SUSPICIOUS.value),
        ("HIGH", "Brute Force", FinalStatus.CONFIRMED_THREAT.value),
        ("HIGH", "Normal Activity", FinalStatus.UNDER_INVESTIGATION.value),
        ("CRITICAL", "Credential Stuffing", FinalStatus.CONFIRMED_THREAT.value),
        ("CRITICAL", "Normal Activity", FinalStatus.UNDER_INVESTIGATION.value),
    ],
)
def test_derive_final_status(
    risk_level: str,
    attack_type: str,
    expected: str,
) -> None:
    assert derive_final_status(risk_level, attack_type) == expected


def test_normal_activity_never_confirmed_threat() -> None:
    for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        status = derive_final_status(level, "Normal Activity")
        assert status != FinalStatus.CONFIRMED_THREAT.value


def test_normal_activity_confidence_is_zero() -> None:
    from dataclasses import fields

    from synthetic_data.attack_classification import classify_attack
    from synthetic_data.feature_engineering.feature_schema import FeatureVector

    allowed = {f.name for f in fields(FeatureVector)}
    vector = FeatureVector(
        **{
            k: v
            for k, v in {
                "employee_id": "EMP-1",
                "simulation_day": "2026-03-10",
                "total_events": 10,
            }.items()
            if k in allowed
        }
    )
    result = classify_attack(vector)
    assert result.attack_type == "Normal Activity"
    assert result.attack_confidence == 0.0
