"""Inference utilities for the trained behavioural Transformer."""

from __future__ import annotations

import math
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np
import torch

from synthetic_data.anomaly_detection.scoring import (
    SKLEARN_ANOMALY,
    SKLEARN_NORMAL,
    AnomalyPrediction,
)
from synthetic_data.behavioural_transformer.calibration import (
    confidence_from_error,
    normalize_error,
)
from synthetic_data.behavioural_transformer.schema import (
    BehaviourInferenceResult,
    SessionSequence,
)
from synthetic_data.behavioural_transformer.sequence_builder import SequenceBuilder
from synthetic_data.behavioural_transformer.train import (
    TrainedTransformerArtifact,
    load_trained_artifact,
)


def _rank_suspicious_events(
    event_types: Sequence[str],
    per_event_errors: Sequence[float],
    attention_matrix: Sequence[Sequence[float]],
    *,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Rank events by contribution above the session baseline."""
    if not per_event_errors:
        return []

    errors = np.asarray(per_event_errors, dtype=np.float64)
    baseline = float(np.median(errors))
    margin = max(0.05 * max(baseline, 1e-6), 1e-4)
    skip_unless_outlier = {
        "DEVICE_CONNECT",
        "DEVICE_DISCONNECT",
        "BREAK_START",
        "BREAK_END",
        "LOGOUT",
        "LOGIN",
    }
    candidates: list[dict[str, Any]] = []
    for index, (event_type, err) in enumerate(zip(event_types, per_event_errors)):
        err_f = float(err)
        if err_f < baseline + margin:
            continue
        if event_type in skip_unless_outlier and err_f < baseline + 2.5 * margin:
            continue
        attn_mass = 0.0
        if index < len(attention_matrix):
            attn_mass = float(sum(attention_matrix[index]))
        delta = err_f - baseline
        candidates.append(
            {
                "index": index,
                "event_type": event_type,
                "reconstruction_error": err_f,
                "attention_mass": attn_mass,
                "explanation": (
                    f"Higher reconstruction error than session baseline "
                    f"(+{delta:.3f} vs median {baseline:.3f})."
                ),
            }
        )

    candidates.sort(key=lambda row: row["reconstruction_error"], reverse=True)
    return candidates[:top_k]


def _infer_sessions_with_flags(
    artifact: TrainedTransformerArtifact,
    sequences: Sequence[SessionSequence],
    *,
    top_k_events: int = 5,
) -> tuple[list[BehaviourInferenceResult], list[bool]]:
    """Infer sessions and return attention-availability flags."""
    if not sequences:
        return [], []

    cfg = artifact.config
    device = torch.device(
        cfg.device if torch.cuda.is_available() and cfg.device != "cpu" else "cpu"
    )
    model = artifact.model.to(device)
    model.eval()

    builder = SequenceBuilder(config=cfg, vocabulary=artifact.vocabulary)
    encoded = builder.encode(sequences)
    results: list[BehaviourInferenceResult] = []
    flags: list[bool] = []

    with torch.no_grad():
        for index, sequence in enumerate(sequences):
            token_ids = torch.tensor(
                [encoded.token_ids[index]], dtype=torch.long, device=device
            )
            attention_mask = torch.tensor(
                [encoded.attention_mask[index]], dtype=torch.long, device=device
            )
            outputs = model(token_ids, attention_mask)
            seq_err, token_err = model.reconstruction_errors(token_ids, attention_mask)

            length = int(encoded.lengths[index])
            attention_available = True
            attention_matrix: list[list[float]] = []
            try:
                attn = model.extract_attention(token_ids, attention_mask)
                attention_matrix = attn[0, :length, :length].cpu().tolist()
                if not attention_matrix or not math.isfinite(
                    float(sum(attention_matrix[0]))
                ):
                    attention_available = False
                    attention_matrix = []
            except Exception:  # noqa: BLE001
                attention_available = False
                attention_matrix = []

            error = float(seq_err[0].item())
            per_event = [float(x) for x in token_err[0, :length].cpu().tolist()]
            event_types = list(sequence.event_types[:length])
            embedding = [
                float(x) for x in outputs["behaviour_embedding"][0].cpu().tolist()
            ]
            ranked = _rank_suspicious_events(
                event_types,
                per_event,
                attention_matrix,
                top_k=top_k_events,
            )
            cal = artifact.resolved_calibration()
            normalized = normalize_error(error, cal)
            is_anomaly = error >= cal.p95
            prediction = SKLEARN_ANOMALY if is_anomaly else SKLEARN_NORMAL
            confidence = confidence_from_error(error, cal)
            results.append(
                BehaviourInferenceResult(
                    employee_id=sequence.employee_id,
                    simulation_day=sequence.simulation_day,
                    session_id=sequence.session_id,
                    reconstruction_error=error,
                    anomaly_score=normalized,
                    confidence_score=confidence,
                    behaviour_embedding=embedding,
                    event_types=event_types,
                    per_event_errors=per_event,
                    attention_weights=attention_matrix,
                    top_suspicious_events=ranked,
                    is_anomaly=is_anomaly,
                    raw_score=-error,
                    normalized_score=normalized,
                    prediction=prediction,
                )
            )
            flags.append(attention_available)

    return results, flags


def infer_sessions(
    artifact: TrainedTransformerArtifact,
    sequences: Sequence[SessionSequence],
    *,
    top_k_events: int = 5,
) -> list[BehaviourInferenceResult]:
    """Run Transformer inference on session sequences."""
    results, _flags = _infer_sessions_with_flags(
        artifact, sequences, top_k_events=top_k_events
    )
    return results


def to_anomaly_prediction(result: BehaviourInferenceResult) -> AnomalyPrediction:
    """Adapt Transformer output to the Risk Engine contract."""
    return AnomalyPrediction(
        employee_id=result.employee_id,
        simulation_day=result.simulation_day,
        raw_score=result.raw_score,
        normalized_score=result.normalized_score,
        prediction=result.prediction,
        is_anomaly=result.is_anomaly,
    )


def behaviour_insight_dict(
    result: BehaviourInferenceResult,
    *,
    attention_available: bool = True,
) -> dict[str, Any]:
    """Serialize extended Transformer fields for the API/dashboard."""
    return {
        "session_id": result.session_id,
        "reconstruction_error": result.reconstruction_error,
        "anomaly_score": result.anomaly_score,
        "behaviour_score": float(max(0.0, 100.0 - result.anomaly_score)),
        "confidence_score": result.confidence_score,
        "behaviour_embedding": result.behaviour_embedding[:16],
        "event_types": result.event_types,
        "per_event_errors": result.per_event_errors,
        "attention_weights": result.attention_weights if attention_available else [],
        "attention_available": bool(attention_available),
        "top_suspicious_events": result.top_suspicious_events,
        "model": "behaviour_transformer",
    }


class TransformerAnomalyModel:
    """Drop-in anomaly detector producing ``AnomalyPrediction`` from sequences."""

    detector_kind = "transformer"

    def __init__(self, artifact: TrainedTransformerArtifact) -> None:
        self.artifact = artifact
        self._last_insights: dict[tuple[str, str], dict[str, Any]] = {}

    @classmethod
    def load(cls, path: str | Path) -> TransformerAnomalyModel:
        return cls(load_trained_artifact(path))

    @property
    def is_fitted(self) -> bool:
        return True

    def predict_sequences(
        self, sequences: Sequence[SessionSequence]
    ) -> list[AnomalyPrediction]:
        results, attention_flags = _infer_sessions_with_flags(self.artifact, sequences)
        predictions: list[AnomalyPrediction] = []
        for result, attn_ok in zip(results, attention_flags, strict=True):
            self._last_insights[(result.employee_id, result.simulation_day)] = (
                behaviour_insight_dict(result, attention_available=attn_ok)
            )
            predictions.append(to_anomaly_prediction(result))
        return predictions

    def predict_one_sequence(self, sequence: SessionSequence) -> AnomalyPrediction:
        return self.predict_sequences([sequence])[0]

    def get_insight(self, employee_id: str, simulation_day: str) -> dict[str, Any] | None:
        return self._last_insights.get((employee_id, simulation_day))

    def predict(self, feature_vectors: Sequence[Any]) -> list[AnomalyPrediction]:
        from synthetic_data.behavioural_transformer.sequence_builder import (
            synthesize_sequence_from_features,
        )

        sequences: list[SessionSequence] = []
        for vector in feature_vectors:
            explicit = getattr(vector, "event_sequence", None)
            if explicit is None and isinstance(vector, dict):
                explicit = vector.get("event_sequence")
            employee_id = str(
                getattr(vector, "employee_id", None) or vector["employee_id"]
            )
            simulation_day = str(
                getattr(vector, "simulation_day", None) or vector["simulation_day"]
            )
            if explicit:
                sequences.append(
                    SessionSequence(
                        employee_id=employee_id,
                        session_id=f"API::{employee_id}::{simulation_day}",
                        simulation_day=simulation_day,
                        event_types=[str(item) for item in list(explicit)],
                    )
                )
            else:
                features = (
                    vector.ml_features()
                    if hasattr(vector, "ml_features")
                    else {
                        k: float(v)
                        for k, v in dict(vector).items()
                        if isinstance(v, (int, float))
                    }
                )
                sequences.append(
                    synthesize_sequence_from_features(
                        employee_id=employee_id,
                        simulation_day=simulation_day,
                        features=features,
                        max_len=self.artifact.config.max_seq_len,
                    )
                )
        return self.predict_sequences(sequences)

    def predict_one(self, feature_vector: Any) -> AnomalyPrediction:
        return self.predict([feature_vector])[0]
