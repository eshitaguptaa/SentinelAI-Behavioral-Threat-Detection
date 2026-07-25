"""SOC Risk Engine configuration — all fusion and decision thresholds.

No magic numbers in scoring / status code paths: import ``DEFAULT_RISK_CONFIG``
(or construct ``RiskEngineConfig``) and read fields from here.

Risk fusion (documented)::

    risk_score = clamp(
        W_anomaly    * anomaly_score
      + W_behaviour  * behaviour_score
      + W_rule       * rule_score
      + W_confidence * confidence
    )

where each component is on ``[0, 100]``:

* **anomaly_score** — Transformer (or IF) normalised reconstruction / anomaly score.
* **behaviour_score** — feature-driven behavioural suspicion from rule adjustments,
  scaled into ``[0, 100]``.
* **rule_score** — attack-classification confidence × 100 (0 when Normal Activity).
* **confidence** — model certainty from distance to the training error distribution.

Final SOC status (documented)::

    IF attack_rule_matched AND risk >= confirmed_risk_min
       AND confidence >= confirmed_confidence_min
        → Confirmed Threat
    ELSE IF risk >= investigate_risk_min
        → Under Investigation
    ELSE IF risk >= suspicious_risk_min
        → Suspicious
    ELSE
        → Normal
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RiskEngineConfig:
    """Immutable configuration for risk fusion and SOC status decisions."""

    # --- Weighted fusion (must sum to 1.0) ---
    weight_anomaly: float = 0.55
    weight_behaviour: float = 0.20
    weight_rule: float = 0.15
    weight_confidence: float = 0.10

    # --- Behaviour score: map rule-adjustment total → [0, 100] ---
    # ``apply_behavioural_rules`` returns adjustments in [0, max_behaviour_adjustment].
    max_behaviour_adjustment: float = 45.0

    # --- Status thresholds (risk & confidence on [0, 100]) ---
    confirmed_risk_min: float = 80.0
    confirmed_confidence_min: float = 80.0
    investigate_risk_min: float = 55.0
    suspicious_risk_min: float = 35.0

    # --- Confidence from reconstruction-error distance (output on [0, 100]) ---
    # Near / below the decision boundary → mid-low certainty.
    confidence_near_floor: float = 45.0
    confidence_near_ceiling: float = 60.0
    # Moderately anomalous (between p95 and p99) → mid-high.
    confidence_moderate_floor: float = 60.0
    confidence_moderate_ceiling: float = 80.0
    # Far outside the training distribution → high certainty.
    confidence_strong_floor: float = 80.0
    confidence_strong_ceiling: float = 99.0
    # Clearly normal bulk (≤ mean) sits in a calm mid band.
    confidence_normal_floor: float = 48.0
    confidence_normal_ceiling: float = 58.0

    def validate(self) -> None:
        """Raise ``ValueError`` if weights or bands are inconsistent."""
        total = (
            self.weight_anomaly
            + self.weight_behaviour
            + self.weight_rule
            + self.weight_confidence
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Risk fusion weights must sum to 1.0 (got {total})")
        if not (
            0.0
            <= self.suspicious_risk_min
            < self.investigate_risk_min
            < self.confirmed_risk_min
            <= 100.0
        ):
            raise ValueError("Status risk thresholds must be strictly increasing in [0, 100]")
        if not (0.0 <= self.confirmed_confidence_min <= 100.0):
            raise ValueError("confirmed_confidence_min must be in [0, 100]")


DEFAULT_RISK_CONFIG = RiskEngineConfig()
DEFAULT_RISK_CONFIG.validate()
