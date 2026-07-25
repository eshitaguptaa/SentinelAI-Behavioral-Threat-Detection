"""Tests for the behavioural Transformer sequence + inference path."""

from __future__ import annotations

from synthetic_data.behavioural_transformer import (
    SequenceBuilder,
    SessionSequence,
    TransformerConfig,
    train_transformer,
)
from synthetic_data.behavioural_transformer.inference import (
    TransformerAnomalyModel,
    infer_sessions,
)
from synthetic_data.behavioural_transformer.calibration import (
    ErrorCalibration,
    normalize_error,
)
from synthetic_data.decision_status import derive_final_status
from synthetic_data.mitre import mitre_dict


def _toy_sequences(n: int = 24) -> list[SessionSequence]:
    normal = [
        "DEVICE_CONNECT",
        "LOGIN",
        "EMAIL_ACCESS",
        "SLACK_ACCESS",
        "JIRA_ACCESS",
        "FILE_READ",
        "LOGOUT",
    ]
    sequences: list[SessionSequence] = []
    for index in range(n):
        events = list(normal)
        if index % 7 == 0:
            events = [
                "DEVICE_CONNECT",
                "FAILED_LOGIN",
                "FAILED_LOGIN",
                "LOGIN",
                "FILE_DOWNLOAD",
                "USB_INSERT",
                "LOGOUT",
            ]
        sequences.append(
            SessionSequence(
                employee_id=f"EMP-{index:03d}",
                session_id=f"SESS-{index:03d}",
                simulation_day="2026-03-10",
                event_types=events,
            )
        )
    return sequences


def test_normalize_error_percentile_bands() -> None:
    """Normals below p80 map to LOW; above p95 map to CRITICAL."""
    cal = ErrorCalibration(
        mean=1.0,
        std=0.2,
        p80=1.2,
        p90=1.4,
        p95=1.6,
        p99=2.0,
        error_min=0.5,
        error_max=2.5,
        n_samples=100,
    )
    assert normalize_error(1.0, cal) <= 24.0
    assert 25.0 <= normalize_error(1.3, cal) <= 49.0
    assert 50.0 <= normalize_error(1.5, cal) <= 74.0
    assert normalize_error(2.2, cal) >= 75.0


def test_sequence_builder_encode_pad_and_unk() -> None:
    builder = SequenceBuilder(config=TransformerConfig(max_seq_len=8))
    sequences = [
        SessionSequence(
            employee_id="E1",
            session_id="S1",
            simulation_day="2026-01-01",
            event_types=["LOGIN", "EMAIL_ACCESS", "LOGOUT"],
        )
    ]
    encoded = builder.encode(sequences)
    assert len(encoded.token_ids[0]) == 8
    assert encoded.lengths[0] == 3
    assert sum(encoded.attention_mask[0]) == 3
    assert builder.vocabulary.encode_token("NOT_A_REAL_EVENT") == builder.vocabulary.unk_id


def test_train_and_infer_transformer_produces_scores() -> None:
    sequences = _toy_sequences(20)
    config = TransformerConfig(
        max_epochs=2,
        batch_size=8,
        patience=2,
        validation_fraction=0.2,
        d_model=32,
        nhead=4,
        num_layers=2,
        dim_feedforward=64,
        max_seq_len=16,
    )
    artifact = train_transformer(sequences, config=config)
    model = TransformerAnomalyModel(artifact)
    predictions = model.predict_sequences(sequences[:3])
    assert len(predictions) == 3
    for prediction in predictions:
        assert 0.0 <= prediction.normalized_score <= 100.0
    insights = infer_sessions(artifact, sequences[:1])
    assert insights[0].event_types
    assert insights[0].top_suspicious_events is not None
    if insights[0].attention_weights:
        row = insights[0].attention_weights[0]
        assert abs(sum(row) - 1.0) < 0.15


def test_mitre_mapping_and_status_hierarchy() -> None:
    assert mitre_dict("Normal Activity") is None
    brute = mitre_dict("Brute Force")
    assert brute is not None
    assert brute["technique_id"] == "T1110"
    assert derive_final_status(17.0, "None", 0.55) == "Normal"
    assert derive_final_status(20.0, "Brute Force", 0.9) == "Normal"
    assert derive_final_status(41.0, "Brute Force", 0.7) == "Suspicious"
    assert derive_final_status(85.0, "Brute Force", 0.9) == "Confirmed Threat"
    assert derive_final_status(85.0, "Behavioural Anomaly", 0.9) == "Under Investigation"
    assert derive_final_status(85.0, "Brute Force", 0.57) == "Under Investigation"
