"""Score helpers for weighted SOC risk fusion.

All formulas are documented in ``config.RiskEngineConfig``.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from synthetic_data.risk_engine.config import DEFAULT_RISK_CONFIG, RiskEngineConfig
from synthetic_data.risk_engine.rules import apply_behavioural_rules
from synthetic_data.risk_engine.scoring import clamp_score

BehaviourFeatures = Mapping[str, float]


def compute_behaviour_score(
    features: BehaviourFeatures,
    *,
    config: RiskEngineConfig = DEFAULT_RISK_CONFIG,
) -> tuple[float, list[str]]:
    """Map behavioural rule adjustments onto a ``[0, 100]`` suspicion score.

    ``behaviour_score = 100 * min(adjustment / max_behaviour_adjustment, 1)``

    Returns ``(behaviour_score, rule_factor_explanations)``.
    """
    adjustment, factors = apply_behavioural_rules(features)
    scale = max(float(config.max_behaviour_adjustment), 1e-8)
    score = clamp_score(100.0 * (float(adjustment) / scale))
    return score, factors


def compute_rule_score(attack_confidence: float) -> float:
    """Attack-rule severity on ``[0, 100]`` from classifier confidence.

    Normal Activity uses confidence 0 → rule_score 0.
    """
    conf = float(attack_confidence)
    # Accept either 0–1 or 0–100 inputs from callers.
    if conf <= 1.0:
        conf *= 100.0
    return clamp_score(conf)


def fuse_risk_score(
    *,
    anomaly_score: float,
    behaviour_score: float,
    rule_score: float,
    confidence: float,
    config: RiskEngineConfig = DEFAULT_RISK_CONFIG,
) -> float:
    """Weighted fusion of anomaly, behaviour, rule, and confidence signals.

    ::

        risk = w_a * anomaly + w_b * behaviour + w_r * rule + w_c * confidence

    ``confidence`` may be passed on ``[0, 1]`` or ``[0, 100]``; values ≤ 1 are
    scaled to percent. Result is clamped to ``[0, 100]``.
    """
    conf = float(confidence)
    if conf <= 1.0:
        conf *= 100.0
    conf = clamp_score(conf)

    raw = (
        config.weight_anomaly * clamp_score(anomaly_score)
        + config.weight_behaviour * clamp_score(behaviour_score)
        + config.weight_rule * clamp_score(rule_score)
        + config.weight_confidence * conf
    )
    return clamp_score(raw)


def confidence_from_anomaly_score(
    anomaly_score: float,
    *,
    config: RiskEngineConfig = DEFAULT_RISK_CONFIG,
) -> float:
    """Fallback confidence when reconstruction error is unavailable (0–100).

    Uses the normalised anomaly score as a proxy for distance from normal:
    mid scores (near decision bands) → lower certainty; extremes → higher.
    """
    score = clamp_score(anomaly_score)
    if score <= 24.0:
        # Bulk-normal region
        t = score / 24.0
        return (
            config.confidence_normal_floor
            + (config.confidence_normal_ceiling - config.confidence_normal_floor) * t
        )
    if score <= 49.0:
        t = (score - 24.0) / 25.0
        return (
            config.confidence_near_floor
            + (config.confidence_near_ceiling - config.confidence_near_floor) * t
        )
    if score <= 74.0:
        t = (score - 49.0) / 25.0
        return (
            config.confidence_moderate_floor
            + (config.confidence_moderate_ceiling - config.confidence_moderate_floor) * t
        )
    excess = (score - 74.0) / 26.0
    return clamp_score(
        config.confidence_strong_floor
        + (config.confidence_strong_ceiling - config.confidence_strong_floor)
        * (1.0 - math.exp(-2.2 * excess))
    )


def fusion_breakdown(
    *,
    anomaly_score: float,
    behaviour_score: float,
    rule_score: float,
    confidence: float,
    risk_score: float,
    config: RiskEngineConfig = DEFAULT_RISK_CONFIG,
) -> dict[str, Any]:
    """Return a documented breakdown for explainability / debugging."""
    conf = float(confidence)
    if conf <= 1.0:
        conf *= 100.0
    return {
        "formula": (
            f"{config.weight_anomaly:.2f}*anomaly + "
            f"{config.weight_behaviour:.2f}*behaviour + "
            f"{config.weight_rule:.2f}*rule + "
            f"{config.weight_confidence:.2f}*confidence"
        ),
        "anomaly_score": clamp_score(anomaly_score),
        "behaviour_score": clamp_score(behaviour_score),
        "rule_score": clamp_score(rule_score),
        "confidence": clamp_score(conf),
        "risk_score": clamp_score(risk_score),
        "weights": {
            "anomaly": config.weight_anomaly,
            "behaviour": config.weight_behaviour,
            "rule": config.weight_rule,
            "confidence": config.weight_confidence,
        },
    }
