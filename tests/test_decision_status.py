"""Final status derivation tests (SOC workflow thresholds)."""

from __future__ import annotations

import pytest

from synthetic_data.decision_status import FinalStatus, derive_final_status
from synthetic_data.risk_engine.config import DEFAULT_RISK_CONFIG


@pytest.mark.parametrize(
    ("risk_score", "attack_type", "confidence", "expected"),
    [
        # Quiet / none
        (17.0, "None", 0.55, FinalStatus.NORMAL.value),
        (20.0, "Brute Force", 0.90, FinalStatus.NORMAL.value),
        # Suspicious band
        (41.0, "Unknown Behaviour", 0.55, FinalStatus.SUSPICIOUS.value),
        (48.0, "Mass Download", 0.70, FinalStatus.SUSPICIOUS.value),
        # Under investigation
        (68.0, "Behavioural Anomaly", 0.70, FinalStatus.UNDER_INVESTIGATION.value),
        (82.0, "Mass Download", 0.57, FinalStatus.UNDER_INVESTIGATION.value),
        (90.0, "Brute Force", 0.70, FinalStatus.UNDER_INVESTIGATION.value),
        # Confirmed threat: rule + risk>=80 + confidence>=80
        (82.0, "Brute Force", 0.85, FinalStatus.CONFIRMED_THREAT.value),
        (93.0, "Impossible Travel", 0.90, FinalStatus.CONFIRMED_THREAT.value),
    ],
)
def test_derive_final_status_soc_workflow(
    risk_score: float,
    attack_type: str,
    confidence: float,
    expected: str,
) -> None:
    assert (
        derive_final_status(risk_score, attack_type, confidence) == expected
    )


def test_normal_activity_never_confirmed_threat() -> None:
    for score in (20.0, 40.0, 70.0, 95.0):
        for conf in (0.5, 0.9, 0.99):
            for label in ("None", "Behavioural Anomaly", "Unknown Behaviour", "Normal Activity"):
                status = derive_final_status(score, label, conf)
                assert status != FinalStatus.CONFIRMED_THREAT.value


def test_confirmed_requires_confidence_threshold() -> None:
    """High risk + rule match without confidence stays Under Investigation."""
    status = derive_final_status(
        90.0,
        "Brute Force",
        DEFAULT_RISK_CONFIG.confirmed_confidence_min / 100.0 - 0.05,
    )
    assert status == FinalStatus.UNDER_INVESTIGATION.value


def test_legacy_level_string_still_callable() -> None:
    """Legacy (level, attack) form maps levels to representative scores."""
    # HIGH≈65 → Under Investigation when attack matched but conf defaults to 0
    assert (
        derive_final_status("HIGH", "Brute Force")
        == FinalStatus.UNDER_INVESTIGATION.value
    )
    assert derive_final_status("LOW", "Normal Activity") == FinalStatus.NORMAL.value
    assert derive_final_status("LOW", "None") == FinalStatus.NORMAL.value
