"""Session sequence schemas for Transformer behavioural modelling."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SessionSequence:
    """Ordered event-type sequence for one employee session (or employee-day).

    Attributes:
        employee_id: Employee identifier.
        session_id: Session or synthetic day-session identifier.
        simulation_day: ISO day string ``YYYY-MM-DD``.
        event_types: Chronological event type labels.
        timestamps: Optional ISO timestamps aligned with ``event_types``.
        metadata: Optional extensible details.
    """

    employee_id: str
    session_id: str
    simulation_day: str
    event_types: list[str]
    timestamps: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.event_types)


@dataclass(slots=True)
class EncodedBatch:
    """Padded integer tensors ready for the Transformer."""

    token_ids: list[list[int]]
    attention_mask: list[list[int]]
    lengths: list[int]
    identities: list[tuple[str, str, str]]  # employee_id, session_id, day


@dataclass(slots=True)
class BehaviourInferenceResult:
    """Rich Transformer inference output for one session/day.

    Compatible fields feed ``AnomalyPrediction``; extended fields power the
    SOC dashboard (timeline, attention, confidence).
    """

    employee_id: str
    simulation_day: str
    session_id: str
    reconstruction_error: float
    anomaly_score: float
    confidence_score: float
    behaviour_embedding: list[float]
    event_types: list[str]
    per_event_errors: list[float]
    attention_weights: list[list[float]]
    top_suspicious_events: list[dict[str, Any]]
    is_anomaly: bool
    raw_score: float
    normalized_score: float
    prediction: int
