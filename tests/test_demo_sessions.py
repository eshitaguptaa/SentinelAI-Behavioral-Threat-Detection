"""Tests for the enterprise-realistic demo session mix."""

from __future__ import annotations

from pathlib import Path

from synthetic_data.api.validation import build_feature_vector
from synthetic_data.attack_classification.engine import classify_attack
from synthetic_data.demo import build_demo_feature_vectors, kind_counts, mix_counts

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ROOT / "datasets" / "events.csv"
MODEL = ROOT / "models" / "sentinelai_transformer.pt"

_TRAINING_TYPES = {
    "APPLICATION_ACCESS",
    "FILE_ACCESS",
    "EMAIL_ACCESS",
    "RESOURCE_ACCESS",
    "MEETING_JOIN",
    "DEVICE_CONNECT",
    "LOGIN",
    "LOGOUT",
    "BREAK_START",
    "BREAK_END",
    "VPN_CONNECT",
    "VPN_DISCONNECT",
}


def test_mix_counts_for_24() -> None:
    assert mix_counts(24) == (18, 2, 4)


def test_demo_mix_and_normal_vocabulary() -> None:
    vectors = build_demo_feature_vectors(24, events_path=EVENTS, model_path=MODEL)
    counts = kind_counts(vectors)
    assert counts["normal"] == 18
    assert counts["mild_anomaly"] == 2
    assert counts["confirmed_attack"] == 4

    for vector in vectors:
        if vector.demo_kind != "normal":
            continue
        assert set(vector.event_sequence).issubset(_TRAINING_TYPES)
        assert vector.country_change_count == 0
        assert vector.auth_failure_rate < 0.1
        assert vector.mass_download_event_count == 0
        assert vector.unique_device_count == 1
        attack = classify_attack(build_feature_vector(vector.to_payload()))
        assert attack.attack_type == "Normal Activity"


def test_mild_anomalies_do_not_match_attack_rules() -> None:
    vectors = build_demo_feature_vectors(24, events_path=EVENTS, model_path=MODEL)
    mild = [v for v in vectors if v.demo_kind == "mild_anomaly"]
    assert len(mild) == 2
    for vector in mild:
        attack = classify_attack(build_feature_vector(vector.to_payload()))
        assert attack.attack_type == "Normal Activity"


def test_confirmed_attacks_match_attack_rules() -> None:
    vectors = build_demo_feature_vectors(24, events_path=EVENTS, model_path=MODEL)
    attacks = [v for v in vectors if v.demo_kind == "confirmed_attack"]
    assert len(attacks) == 4
    for vector in attacks:
        attack = classify_attack(build_feature_vector(vector.to_payload()))
        assert attack.attack_type != "Normal Activity"
