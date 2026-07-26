"""Feature vector schema for SentinelAI employee-day ML features.

Each ``FeatureVector`` aggregates one employee's timeline activity for a single
simulation day into numerical / categorical fields.

Field roles
-----------
* **Behavioural features** — used by Isolation Forest via ``ml_features()``.
* **Ground-truth / attack fields** — retained on the vector for evaluation,
  metrics, dashboards, and explainability. They are **excluded** from
  ``ml_features()`` so detectors cannot train on labels.
* **Identity / label** — row keys and optional binary label; never used as
  model inputs.

Values are raw extracted counts and ratios — no scaling or normalisation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any, Final

# ---------------------------------------------------------------------------
# Ground-truth attack fields (evaluation / metrics only — not ML inputs)
# ---------------------------------------------------------------------------

ATTACK_FEATURE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "attack_event_count",
        "attack_event_ratio",
        "unique_attack_type_count",
        "has_attack",
        "impossible_travel_count",
        "credential_theft_count",
        "privilege_escalation_count",
        "data_exfiltration_count",
        "after_hours_attack_count",
        "lateral_movement_count",
        "brute_force_count",
        "device_spoofing_count",
        "low_and_slow_count",
        "insider_drift_count",
        "max_attack_confidence",
    }
)
"""Attack-derived ground-truth columns kept for evaluation, not Isolation Forest."""

IDENTITY_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "employee_id",
        "simulation_day",
        "label",
    }
)
"""Row identity and optional supervised label — never used as ML inputs."""


# ---------------------------------------------------------------------------
# Documentation for newly added behavioural features (Phase 8 refinement)
# ---------------------------------------------------------------------------

NEW_FEATURE_DOCS: Final[dict[str, dict[str, str]]] = {
    "mean_login_hour": {
        "purpose": "Average time-of-day of LOGIN events on the simulation day.",
        "formula": "mean(hour + minute/60 + second/3600) over LOGIN events; 0 if none.",
        "expected_range": "[0, 24); 0 when no logins.",
        "anomaly_utility": (
            "Unusual mean login time (very early / late) is a strong insider "
            "and account-compromise signal."
        ),
    },
    "median_login_hour": {
        "purpose": "Median LOGIN time-of-day; robust to outlier login bursts.",
        "formula": "median of LOGIN hour-fractions; 0 if no logins.",
        "expected_range": "[0, 24); 0 when no logins.",
        "anomaly_utility": (
            "Resists skew from a single odd login; shifts still indicate "
            "changed work patterns or takeover."
        ),
    },
    "std_login_hour": {
        "purpose": "Dispersion of LOGIN times within the day.",
        "formula": "population std-dev of LOGIN hour-fractions; 0 if fewer than 2 logins.",
        "expected_range": "[0, ~12].",
        "anomaly_utility": (
            "High spread suggests fragmented or multi-timezone activity "
            "inconsistent with a normal workday."
        ),
    },
    "resource_entropy": {
        "purpose": "Diversity of resources accessed during the day.",
        "formula": "Shannon entropy H = -Σ p_i log2(p_i) over resource_id frequencies.",
        "expected_range": "[0, log2(R)] where R is distinct resources; 0 if none.",
        "anomaly_utility": (
            "Sudden high entropy can indicate reconnaissance / lateral browsing; "
            "collapse to one resource can indicate focused exfiltration."
        ),
    },
    "device_entropy": {
        "purpose": "Diversity of devices used during the day.",
        "formula": "Shannon entropy over device_id frequencies.",
        "expected_range": "[0, log2(D)] where D is distinct devices; 0 if none.",
        "anomaly_utility": (
            "Elevated device entropy may indicate credential reuse across "
            "endpoints or attacker pivoting."
        ),
    },
    "max_failed_login_streak": {
        "purpose": "Longest consecutive failed LOGIN sequence before a success/reset.",
        "formula": (
            "Scan LOGIN events in time order; increment streak on failure, "
            "reset on non-failure; report max streak."
        ),
        "expected_range": "[0, login_count].",
        "anomaly_utility": (
            "Long failure streaks are classic brute-force / password-spray "
            "indicators beyond simple failure rate."
        ),
    },
    "max_idle_gap_sec": {
        "purpose": "Longest silence between consecutive events in the day.",
        "formula": "max(Δt_i) for consecutive event timestamps; 0 if <2 events.",
        "expected_range": "[0, ~86400] seconds for a single day.",
        "anomaly_utility": (
            "Abnormally large gaps can indicate abandoned sessions followed by "
            "hijack; abnormally small max gaps with high volume suggest automation."
        ),
    },
    "median_idle_gap_sec": {
        "purpose": "Typical inter-event idle gap (robust central tendency).",
        "formula": "median of consecutive inter-event gaps in seconds; 0 if <2 events.",
        "expected_range": "[0, ~86400] seconds.",
        "anomaly_utility": (
            "Median gap shifts reveal changed work cadence (bot-like rapid "
            "clicks vs idle human pacing) without being dominated by one pause."
        ),
    },
    "country_change_count": {
        "purpose": "Number of country transitions across the ordered event stream.",
        "formula": (
            "Resolve country from metadata or location_id mapping/prefix; "
            "count consecutive events where country differs."
        ),
        "expected_range": "[0, total_events - 1].",
        "anomaly_utility": (
            "Multiple country flips within one day strongly suggest impossible "
            "travel or multi-geo account abuse."
        ),
    },
}


@dataclass(slots=True)
class FeatureVector:
    """Numerical feature vector for one employee on one simulation day.

    Identity / metadata fields identify the row; attack fields are ground truth
    for evaluation; behavioural fields feed unsupervised models via
    ``ml_features()``.
    """

    # --- Identity / metadata ---
    employee_id: str
    simulation_day: str
    label: int | None = None

    # --- Behaviour ---
    total_events: int = 0
    login_count: int = 0
    logout_count: int = 0
    application_access_count: int = 0
    resource_access_count: int = 0
    email_access_count: int = 0
    meeting_join_count: int = 0
    break_start_count: int = 0
    device_connect_count: int = 0
    unique_event_type_count: int = 0

    # --- Identity / endpoint diversity ---
    unique_device_count: int = 0
    unique_location_count: int = 0
    unique_browser_count: int = 0
    unique_os_count: int = 0
    device_entropy: float = 0.0

    # --- Resource usage ---
    unique_resource_count: int = 0
    resource_touch_count: int = 0
    sensitive_resource_count: int = 0
    resource_switch_count: int = 0
    resource_entropy: float = 0.0

    # --- Authentication ---
    auth_success_count: int = 0
    auth_failure_count: int = 0
    auth_failure_rate: float = 0.0
    max_failed_login_streak: int = 0
    vpn_connect_count: int = 0
    vpn_disconnect_count: int = 0
    login_logout_delta: int = 0

    # --- Network ---
    location_change_count: int = 0
    country_change_count: int = 0
    remote_event_count: int = 0
    unique_source_ip_count: int = 0
    cross_location_session_count: int = 0
    vpn_usage_ratio: float = 0.0

    # --- File activity ---
    file_access_count: int = 0
    download_size_mb_sum: float = 0.0
    download_size_mb_max: float = 0.0
    mass_download_event_count: int = 0
    file_access_ratio: float = 0.0

    # --- Attack indicators (ground truth — excluded from ml_features) ---
    attack_event_count: int = 0
    attack_event_ratio: float = 0.0
    unique_attack_type_count: int = 0
    has_attack: int = 0
    impossible_travel_count: int = 0
    credential_theft_count: int = 0
    privilege_escalation_count: int = 0
    data_exfiltration_count: int = 0
    after_hours_attack_count: int = 0
    lateral_movement_count: int = 0
    brute_force_count: int = 0
    device_spoofing_count: int = 0
    low_and_slow_count: int = 0
    insider_drift_count: int = 0
    max_attack_confidence: float = 0.0

    # --- Statistical behaviour ---
    events_per_hour_mean: float = 0.0
    events_per_hour_max: float = 0.0
    inter_event_mean_sec: float = 0.0
    inter_event_std_sec: float = 0.0
    max_idle_gap_sec: float = 0.0
    median_idle_gap_sec: float = 0.0
    event_type_entropy: float = 0.0
    burst_max_5min: int = 0

    # --- Temporal behaviour ---
    first_event_hour: float = 0.0
    last_event_hour: float = 0.0
    mean_login_hour: float = 0.0
    median_login_hour: float = 0.0
    std_login_hour: float = 0.0
    active_duration_hours: float = 0.0
    after_hours_event_count: int = 0
    night_event_count: int = 0
    is_weekend: int = 0
    weekday: int = 0
    unique_active_hour_count: int = 0

    # --- Session behaviour ---
    session_count: int = 0
    avg_session_duration_sec: float = 0.0
    max_session_duration_sec: float = 0.0
    avg_events_per_session: float = 0.0
    multi_device_session_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dictionary of all fields (including ground truth)."""
        return asdict(self)

    def feature_names(self) -> list[str]:
        """Return ordered feature field names (excludes identity / label).

        Includes attack ground-truth columns for backward compatibility.
        Prefer ``ml_feature_names()`` / ``ml_features()`` for model input.
        """
        skip = {"employee_id", "simulation_day", "label"}
        return [f.name for f in fields(self) if f.name not in skip]

    def to_feature_array(self) -> list[float]:
        """Return numerical feature values in ``feature_names()`` order.

        Backward-compatible: still includes attack ground-truth fields.
        For Isolation Forest, use ``ml_features()`` instead.
        """
        data = self.to_dict()
        return [float(data[name]) for name in self.feature_names()]

    def ml_feature_names(self) -> list[str]:
        """Ordered behavioural feature names suitable for Isolation Forest."""
        return [name for name in self.feature_names() if name not in ATTACK_FEATURE_NAMES]

    def ml_features(self) -> dict[str, float]:
        """Return ONLY behavioural features for unsupervised ML (Phase 9).

        Automatically excludes:

        * ``employee_id``, ``simulation_day``, ``label``
        * every attack-derived ground-truth field in ``ATTACK_FEATURE_NAMES``

        This is the official Isolation Forest input surface.
        """
        data = self.to_dict()
        return {name: float(data[name]) for name in self.ml_feature_names()}


# Canonical ordered list of all numerical feature names (incl. ground truth).
FEATURE_NAMES: tuple[str, ...] = tuple(
    f.name
    for f in fields(FeatureVector)
    if f.name not in IDENTITY_FIELD_NAMES
)

# Behavioural-only feature names for Isolation Forest / Phase 9.
ML_FEATURE_NAMES: tuple[str, ...] = tuple(
    name for name in FEATURE_NAMES if name not in ATTACK_FEATURE_NAMES
)

# Count of all extractable numerical columns (excludes identity + label).
NUM_FEATURES: int = len(FEATURE_NAMES)
"""Number of extractable feature columns including ground-truth attack fields."""

NUM_ML_FEATURES: int = len(ML_FEATURE_NAMES)
"""Number of behavioural columns returned by ``FeatureVector.ml_features()``."""
