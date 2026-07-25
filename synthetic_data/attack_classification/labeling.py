"""Attack-label resolution when no signature rule matches.

Labels shown on the SOC dashboard::

    None                 — no rule match AND anomaly below threshold
    Behavioural Anomaly  — no rule match AND anomaly at/above HIGH band
    Unknown Behaviour    — no rule match AND anomaly in MEDIUM band

Named attacks (Brute Force, Impossible Travel, …) are returned only when a
rule matches. ``Normal Activity`` is never emitted for display.
"""

from __future__ import annotations

from synthetic_data.attack_classification.schema import AttackType
from synthetic_data.risk_engine.schema import RISK_LEVEL_BOUNDS, RiskLevel

# Anomaly score upper bound of LOW (inclusive) — below/equal → "None".
_DEFAULT_NONE_MAX = float(RISK_LEVEL_BOUNDS[RiskLevel.LOW][1])  # 24
# Exclusive start of HIGH — at/above → "Behavioural Anomaly".
_DEFAULT_BEHAVIOURAL_MIN = float(RISK_LEVEL_BOUNDS[RiskLevel.HIGH][0])  # 50


def resolve_unmatched_attack_type(
    anomaly_score: float,
    *,
    none_max: float = _DEFAULT_NONE_MAX,
    behavioural_min: float = _DEFAULT_BEHAVIOURAL_MIN,
) -> AttackType:
    """Map anomaly score onto a non-signature attack label.

    Args:
        anomaly_score: Transformer / detector normalised score in ``[0, 100]``.
        none_max: Scores at or below this → ``None`` (routine).
        behavioural_min: Scores at or above this → ``Behavioural Anomaly``.
            Between ``none_max`` and ``behavioural_min`` → ``Unknown Behaviour``.
    """
    score = float(anomaly_score)
    if score <= none_max:
        return AttackType.NONE
    if score >= behavioural_min:
        return AttackType.BEHAVIOURAL_ANOMALY
    return AttackType.UNKNOWN_BEHAVIOUR
