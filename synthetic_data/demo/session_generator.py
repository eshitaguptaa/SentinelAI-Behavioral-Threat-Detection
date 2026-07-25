"""Enterprise-realistic demo session generator for the SOC dashboard.

Mix (default 24 users)::

    ~75% Normal Activity          — sampled from Transformer training events
    ~10% Behavioural anomalies    — odd sequences, no attack-rule match
    ~15% Confirmed attacks        — attack subsequences + matching rule features

Normal sessions reuse the same event-type distribution as
``datasets/events.csv`` (the Transformer training corpus). Attack / mild
features are never injected into normal rows.
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import pandas as pd

from synthetic_data.generators.attack_sequences import (
    BRUTE_FORCE_SEQUENCE,
    DATA_EXFILTRATION_SEQUENCE,
    INSIDER_THREAT_SEQUENCE,
    LATERAL_MOVEMENT_SEQUENCE,
)

DemoKind = Literal["normal", "mild_anomaly", "confirmed_attack"]

_DEFAULT_EVENTS = Path(__file__).resolve().parents[2] / "datasets" / "events.csv"
_TRAINING_EVENT_TYPES = frozenset(
    {
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
)


@dataclass
class DemoFeatureVector:
    """Serializable demo payload matching the API FeatureVector contract."""

    employee_id: str
    simulation_day: str
    event_sequence: list[str]
    demo_kind: DemoKind
    total_events: int = 0
    login_count: int = 1
    logout_count: int = 1
    auth_failure_rate: float = 0.02
    max_failed_login_streak: int = 0
    country_change_count: int = 0
    location_change_count: int = 1
    unique_device_count: int = 1
    unique_location_count: int = 1
    resource_entropy: float = 0.55
    device_entropy: float = 0.2
    after_hours_event_count: int = 0
    download_size_mb_sum: float = 6.0
    mass_download_event_count: int = 0
    vpn_usage_ratio: float = 0.1
    burst_max_5min: float = 5.0
    active_duration_hours: float = 8.0
    file_access_ratio: float = 0.15
    night_event_count: int = 0
    application_access_count: int = 6
    file_access_count: int = 4
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_payload(self) -> dict[str, Any]:
        """HTTP / frontend payload (drops internal demo_kind unless requested)."""
        payload = {
            "employee_id": self.employee_id,
            "simulation_day": self.simulation_day,
            "event_sequence": list(self.event_sequence),
            "total_events": self.total_events or len(self.event_sequence),
            "login_count": self.login_count,
            "logout_count": self.logout_count,
            "auth_failure_rate": self.auth_failure_rate,
            "max_failed_login_streak": self.max_failed_login_streak,
            "country_change_count": self.country_change_count,
            "location_change_count": self.location_change_count,
            "unique_device_count": self.unique_device_count,
            "unique_location_count": self.unique_location_count,
            "resource_entropy": self.resource_entropy,
            "device_entropy": self.device_entropy,
            "after_hours_event_count": self.after_hours_event_count,
            "download_size_mb_sum": self.download_size_mb_sum,
            "mass_download_event_count": self.mass_download_event_count,
            "vpn_usage_ratio": self.vpn_usage_ratio,
            "burst_max_5min": self.burst_max_5min,
            "active_duration_hours": self.active_duration_hours,
            "file_access_ratio": self.file_access_ratio,
            "night_event_count": self.night_event_count,
            "application_access_count": self.application_access_count,
            "file_access_count": self.file_access_count,
            "demo_kind": self.demo_kind,
        }
        payload.update(self.extra)
        return payload


def mix_counts(count: int = 24) -> tuple[int, int, int]:
    """Return (n_normal, n_mild, n_attack) ≈ 75% / 10% / 15%."""
    n_attack = max(1, round(count * 0.15))
    n_mild = max(1, round(count * 0.10))
    n_normal = count - n_attack - n_mild
    if n_normal < 1:
        n_normal = 1
        n_mild = max(0, count - n_normal - n_attack)
    return n_normal, n_mild, n_attack


def _load_training_sessions(
    events_path: Path,
) -> list[tuple[str, str, list[str]]]:
    """Load (employee_id, simulation_day, event_types) from the training CSV."""
    df = pd.read_csv(events_path)
    required = {"employee_id", "session_id", "timestamp", "event_type", "simulation_date"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"events CSV missing columns: {sorted(missing)}")

    sessions: list[tuple[str, str, list[str]]] = []
    for (_emp, _sess), group in df.groupby(["employee_id", "session_id"], sort=False):
        ordered = group.sort_values("timestamp")
        event_types = [str(x) for x in ordered["event_type"].tolist()]
        if len(event_types) < 8:
            continue
        # Keep only sessions whose tokens match the Transformer training mass.
        if not set(event_types).issubset(_TRAINING_EVENT_TYPES):
            continue
        day = str(ordered["simulation_date"].iloc[0])[:10]
        sessions.append((str(ordered["employee_id"].iloc[0]), day, event_types))
    if len(sessions) < 20:
        raise ValueError(
            f"Need >=20 training-like sessions from {events_path}, got {len(sessions)}"
        )
    return sessions


def _quiet_normal_features(index: int, event_sequence: list[str]) -> dict[str, Any]:
    """Behavioural features for a normal day — no attack-rule triggers."""
    app = sum(1 for e in event_sequence if e == "APPLICATION_ACCESS")
    files = sum(1 for e in event_sequence if e == "FILE_ACCESS")
    vpn = 1 if "VPN_CONNECT" in event_sequence else 0
    return {
        "total_events": len(event_sequence),
        "login_count": 1,
        "logout_count": 1,
        "auth_failure_rate": 0.01 + (index % 3) * 0.005,
        "max_failed_login_streak": 0,
        "country_change_count": 0,
        "location_change_count": 1,
        "unique_device_count": 1,
        "unique_location_count": 1,
        "resource_entropy": 0.45 + (index % 4) * 0.05,
        "device_entropy": 0.15,
        "after_hours_event_count": 0,
        "download_size_mb_sum": 4.0 + (index % 5),
        "mass_download_event_count": 0,
        "vpn_usage_ratio": 0.35 if vpn else 0.05,
        "burst_max_5min": 3.0 + (index % 3),
        "active_duration_hours": 7.5 + (index % 3) * 0.5,
        "file_access_ratio": min(0.25, files / max(len(event_sequence), 1)),
        "night_event_count": 0,
        "application_access_count": max(app, 3),
        "file_access_count": max(files, 2),
    }


def _mild_anomaly_sequence(normal: list[str], variant: int) -> list[str]:
    """Odd but non-rule-matching behaviour on a thin training-like frame.

    Keeps connect/login/logout tokens from the training distribution so the
    session is still a workday, but replaces most mid-day activity with rare
    tokens the Transformer did not see in ``events.csv`` — raising
    reconstruction error without firing attack-classification rules.
    """
    head = list(normal[:3]) if len(normal) >= 3 else ["DEVICE_CONNECT", "LOGIN"]
    # Keep a short stretch of training-like mid-day so error is elevated but
    # not necessarily in the extreme CRITICAL tail.
    train_mid = [
        e
        for e in normal[3:-2]
        if e in {"APPLICATION_ACCESS", "FILE_ACCESS", "EMAIL_ACCESS", "RESOURCE_ACCESS"}
    ][:4]
    tail = list(normal[-2:]) if len(normal) >= 2 else ["LOGOUT"]
    if variant % 2 == 0:
        odd = [
            "FAILED_LOGIN",
            "FAILED_LOGIN",
            "USB_INSERT",
            "FILE_DOWNLOAD",
            "SSH_LOGIN",
            "FILE_DOWNLOAD",
        ]
    else:
        odd = [
            "ADMIN_LOGIN",
            "REMOTE_DESKTOP",
            "FILE_DOWNLOAD",
            "SSH_LOGIN",
            "USB_INSERT",
            "FILE_UPLOAD",
        ]
    return head + train_mid[:2] + odd + train_mid[2:] + tail


def _attack_session_sequence(normal: list[str], attack_events: tuple[str, ...] | list[str]) -> list[str]:
    """Build an attack-dominated day on a short training-like frame.

    Attack tokens must dominate length so reconstruction error rises enough
    that anomaly_score + capped rule uplift (>= +20) reaches HIGH/CRITICAL.
    """
    head = list(normal[:2]) if len(normal) >= 2 else ["DEVICE_CONNECT", "LOGIN"]
    tail = list(normal[-1:]) if normal else ["LOGOUT"]
    body = list(attack_events) + ["FILE_DOWNLOAD", "USB_INSERT"] + list(attack_events)
    return head + body + tail


def _score_sequences(
    sequences: list[list[str]],
    *,
    model_path: Path | None,
) -> list[float]:
    """Return reconstruction errors for sequences (empty if model unavailable)."""
    if model_path is None or not model_path.is_file():
        return []
    try:
        from synthetic_data.behavioural_transformer.inference import infer_sessions
        from synthetic_data.behavioural_transformer.schema import SessionSequence
        from synthetic_data.behavioural_transformer.train import load_trained_artifact
    except ImportError:
        return []

    artifact = load_trained_artifact(model_path)
    session_objs = [
        SessionSequence(
            employee_id=f"CAL-{index}",
            session_id=f"CAL-SESS-{index}",
            simulation_day="2026-01-01",
            event_types=events,
        )
        for index, events in enumerate(sequences)
    ]
    results = infer_sessions(artifact, session_objs)
    return [float(r.reconstruction_error) for r in results]


def _select_low_error_normals(
    pool: list[tuple[str, str, list[str]]],
    n: int,
    rng: random.Random,
    *,
    model_path: Path | None,
    max_error: float | None,
) -> list[tuple[str, str, list[str]]]:
    """Pick ``n`` training sessions from the bulk of the error distribution."""
    if n <= 0:
        return []
    shuffled = list(pool)
    rng.shuffle(shuffled)
    if max_error is None or model_path is None:
        return shuffled[:n]

    # Score a candidate pool (up to 8x needed) and keep errors <= max_error.
    candidates = shuffled[: min(len(shuffled), max(n * 8, 40))]
    errors = _score_sequences([c[2] for c in candidates], model_path=model_path)
    if not errors:
        return shuffled[:n]

    accepted = [
        session
        for session, err in zip(candidates, errors, strict=True)
        if err <= max_error
    ]
    if len(accepted) >= n:
        return accepted[:n]
    # Fill remainder with lowest-error candidates if the bulk filter is tight.
    ranked = sorted(zip(candidates, errors, strict=True), key=lambda row: row[1])
    out = list(accepted)
    for session, _err in ranked:
        if session in out:
            continue
        out.append(session)
        if len(out) >= n:
            break
    return out[:n]


def _mild_anomaly_features(index: int, event_sequence: list[str]) -> dict[str, Any]:
    """Elevated features that stay under every attack-classification threshold."""
    base = _quiet_normal_features(index, event_sequence)
    base.update(
        {
            "auth_failure_rate": 0.18,
            "max_failed_login_streak": 2,
            "location_change_count": 2,
            "unique_location_count": 2,
            "resource_entropy": 1.4,
            "after_hours_event_count": 4,
            "download_size_mb_sum": 45.0,
            "mass_download_event_count": 0,
            "vpn_usage_ratio": 0.4,
            "burst_max_5min": 12.0,
            "active_duration_hours": 9.5,
            "file_access_ratio": 0.28,
            "night_event_count": 2,
            "file_access_count": 7,
        }
    )
    return base


def _attack_specs() -> list[tuple[str, tuple[str, ...], dict[str, Any]]]:
    """(label, sequence, feature overrides that fire the matching rule)."""
    return [
        (
            "Impossible Travel",
            LATERAL_MOVEMENT_SEQUENCE,
            {
                "country_change_count": 2,
                "location_change_count": 3,
                "unique_location_count": 3,
                "auth_failure_rate": 0.1,
                "max_failed_login_streak": 1,
                "vpn_usage_ratio": 0.45,
                "resource_entropy": 2.0,
                "after_hours_event_count": 2,
                "download_size_mb_sum": 25.0,
                "burst_max_5min": 14.0,
            },
        ),
        (
            "Brute Force",
            BRUTE_FORCE_SEQUENCE,
            {
                "auth_failure_rate": 0.55,
                "max_failed_login_streak": 8,
                "login_count": 3,
                "unique_device_count": 2,
                "device_entropy": 0.6,
                "resource_entropy": 1.8,
                "burst_max_5min": 20.0,
                "after_hours_event_count": 3,
            },
        ),
        (
            "Mass Download / Exfil",
            DATA_EXFILTRATION_SEQUENCE,
            {
                "download_size_mb_sum": 180.0,
                "mass_download_event_count": 2,
                "file_access_ratio": 0.42,
                "file_access_count": 10,
                "resource_entropy": 2.2,
                "after_hours_event_count": 5,
                "burst_max_5min": 16.0,
                "vpn_usage_ratio": 0.5,
            },
        ),
        (
            "Insider / Device",
            INSIDER_THREAT_SEQUENCE,
            {
                "unique_device_count": 4,
                "device_entropy": 1.25,
                "after_hours_event_count": 14,
                "active_duration_hours": 13.0,
                "file_access_ratio": 0.48,
                "night_event_count": 6,
                "download_size_mb_sum": 70.0,
                "mass_download_event_count": 0,
                "location_change_count": 2,
                "unique_location_count": 2,
                "resource_entropy": 2.1,
            },
        ),
    ]


def build_demo_feature_vectors(
    count: int = 24,
    *,
    events_path: Path | str | None = None,
    simulation_day: str = "2026-03-10",
    seed: int = 42,
    model_path: Path | str | None = None,
) -> list[DemoFeatureVector]:
    """Build a realistic demo batch aligned with Transformer training data.

    Normal sessions are sampled from ``events.csv`` and, when a trained
    artifact is available, further filtered to reconstruction errors at or
    below the calibration p80 so they land in LOW — matching the bulk of the
    training distribution rather than its long tail.
    """
    path = Path(events_path) if events_path else _DEFAULT_EVENTS
    artifact_path = (
        Path(model_path)
        if model_path
        else Path(__file__).resolve().parents[2] / "models" / "sentinelai_transformer.pt"
    )
    rng = random.Random(seed)
    pool = _load_training_sessions(path)
    n_normal, n_mild, n_attack = mix_counts(count)

    p80: float | None = None
    if artifact_path.is_file():
        try:
            from synthetic_data.behavioural_transformer.train import load_trained_artifact

            p80 = float(load_trained_artifact(artifact_path).resolved_calibration().p80)
        except Exception:  # noqa: BLE001
            p80 = None

    normals_src = _select_low_error_normals(
        pool,
        n_normal,
        rng,
        model_path=artifact_path if artifact_path.is_file() else None,
        max_error=p80,
    )
    remaining = [s for s in pool if s not in normals_src]
    rng.shuffle(remaining)
    mild_src = remaining[:n_mild]
    while len(mild_src) < n_mild:
        mild_src.append(rng.choice(pool))
    attack_base = remaining[n_mild : n_mild + n_attack]
    while len(attack_base) < n_attack:
        attack_base.append(rng.choice(pool))
    attack_specs = _attack_specs()

    vectors: list[DemoFeatureVector] = []
    emp_index = 1

    for i, (_emp, _day, events) in enumerate(normals_src):
        feats = _quiet_normal_features(i, events)
        vectors.append(
            DemoFeatureVector(
                employee_id=f"EMP-{emp_index:03d}",
                simulation_day=simulation_day,
                event_sequence=list(events),
                demo_kind="normal",
                **feats,
            )
        )
        emp_index += 1

    for i, (_emp, _day, events) in enumerate(mild_src):
        seq = _mild_anomaly_sequence(events, variant=i)
        feats = _mild_anomaly_features(i, seq)
        vectors.append(
            DemoFeatureVector(
                employee_id=f"EMP-{emp_index:03d}",
                simulation_day=simulation_day,
                event_sequence=seq,
                demo_kind="mild_anomaly",
                **feats,
            )
        )
        emp_index += 1

    for i, (_emp, _day, events) in enumerate(attack_base):
        label, attack_seq, overrides = attack_specs[i % len(attack_specs)]
        seq = _attack_session_sequence(events, attack_seq)
        feats = _quiet_normal_features(i, seq)
        feats.update(overrides)
        feats["total_events"] = len(seq)
        vectors.append(
            DemoFeatureVector(
                employee_id=f"EMP-{emp_index:03d}",
                simulation_day=simulation_day,
                event_sequence=seq,
                demo_kind="confirmed_attack",
                extra={"attack_scenario": label},
                **feats,
            )
        )
        emp_index += 1

    return vectors


def export_demo_json(
    output_path: Path | str,
    *,
    count: int = 24,
    events_path: Path | str | None = None,
    model_path: Path | str | None = None,
) -> Path:
    """Write demo payloads to JSON for the React dashboard."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    vectors = build_demo_feature_vectors(
        count, events_path=events_path, model_path=model_path
    )
    payload = [v.to_payload() for v in vectors]
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


def kind_counts(vectors: list[DemoFeatureVector]) -> dict[str, int]:
    counts: dict[str, int] = {"normal": 0, "mild_anomaly": 0, "confirmed_attack": 0}
    for vector in vectors:
        counts[vector.demo_kind] = counts.get(vector.demo_kind, 0) + 1
    return counts
