"""Empirical reconstruction-error calibration for Transformer anomaly scores.

Uses statistics from **normal** sessions only (mean, std, p90/p95/p99) to map
errors onto Risk Engine bands so normals cluster in LOW and only the far tail
reaches CRITICAL.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np

# Risk Engine score band edges (inclusive upper bounds for LOW/MEDIUM/HIGH).
_SCORE_LOW_MAX = 24.0
_SCORE_MED_MAX = 49.0
_SCORE_HIGH_MAX = 74.0
_SCORE_CRIT_MAX = 100.0


@dataclass(slots=True)
class ErrorCalibration:
    """Fitted reconstruction-error distribution for normal behaviour."""

    mean: float
    std: float
    p80: float
    p90: float
    p95: float
    p99: float
    error_min: float
    error_max: float
    n_samples: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ErrorCalibration:
        mean = float(payload["mean"])
        std = float(payload["std"])
        p90 = float(payload["p90"])
        p95 = float(payload["p95"])
        p99 = float(payload["p99"])
        p80 = float(payload["p80"]) if "p80" in payload else mean + 0.84 * max(std, 1e-8)
        return cls(
            mean=mean,
            std=std,
            p80=p80,
            p90=p90,
            p95=p95,
            p99=p99,
            error_min=float(payload.get("error_min", mean)),
            error_max=float(payload.get("error_max", p99)),
            n_samples=int(payload.get("n_samples", 0)),
        )

    @classmethod
    def from_errors(cls, errors: Sequence[float] | np.ndarray) -> ErrorCalibration:
        """Fit calibration from a list of normal-session reconstruction errors."""
        arr = np.asarray(list(errors), dtype=np.float64)
        if arr.size == 0:
            raise ValueError("Cannot calibrate on an empty error list")
        std = float(arr.std())
        if std < 1e-8:
            std = 1e-3
        return cls(
            mean=float(arr.mean()),
            std=std,
            p80=float(np.percentile(arr, 80)),
            p90=float(np.percentile(arr, 90)),
            p95=float(np.percentile(arr, 95)),
            p99=float(np.percentile(arr, 99)),
            error_min=float(arr.min()),
            error_max=float(arr.max()),
            n_samples=int(arr.size),
        )

    @classmethod
    def from_legacy(
        cls,
        *,
        mean: float,
        std: float,
        threshold: float,
    ) -> ErrorCalibration:
        """Approximate percentiles when only mean/std/p95 threshold are stored."""
        sigma = max(float(std), 1e-8)
        mu = float(mean)
        p95 = float(threshold) if threshold > mu else mu + 1.645 * sigma
        return cls(
            mean=mu,
            std=sigma,
            p80=mu + 0.842 * sigma,
            p90=mu + 1.282 * sigma,
            p95=p95,
            p99=mu + 2.326 * sigma,
            error_min=max(0.0, mu - 3.0 * sigma),
            error_max=mu + 4.0 * sigma,
            n_samples=0,
        )


def normalize_error(error: float, calibration: ErrorCalibration) -> float:
    """Map reconstruction error → anomalousness in ``[0, 100]``.

    Empirical percentile bands (fitted on normal sessions)::

        error ≤ p80   → LOW      (0–24)   ~80% of normals
        p80–p90       → MEDIUM   (25–49)  ~10%
        p90–p95       → HIGH     (50–74)  ~5%
        error > p95   → CRITICAL (75–100) ~5% (top 5%; widen to p90 for ~10%)

    Only the most anomalous tail reaches CRITICAL.
    """
    value = float(error)
    p80 = float(calibration.p80)
    p90 = float(calibration.p90)
    p95 = float(calibration.p95)
    floor = float(calibration.error_min)

    # Ensure strictly increasing anchors.
    if p90 <= p80:
        p90 = p80 + max(calibration.std * 0.2, 1e-4)
    if p95 <= p90:
        p95 = p90 + max(calibration.std * 0.2, 1e-4)
    if p80 <= floor:
        floor = p80 - max(calibration.std, 1e-4)

    if value <= floor:
        return 0.0
    if value <= p80:
        t = (value - floor) / max(p80 - floor, 1e-8)
        return float(np.clip(_SCORE_LOW_MAX * t, 0.0, _SCORE_LOW_MAX))
    if value <= p90:
        t = (value - p80) / max(p90 - p80, 1e-8)
        return float(25.0 + (_SCORE_MED_MAX - 25.0) * t)
    if value <= p95:
        t = (value - p90) / max(p95 - p90, 1e-8)
        return float(50.0 + (_SCORE_HIGH_MAX - 50.0) * t)
    # Above p95 → CRITICAL (top ~5% of normal mass)
    excess = (value - p95) / max(calibration.std, 1e-8)
    score = 75.0 + 25.0 * (1.0 - math.exp(-excess / 2.0))
    return float(np.clip(score, 75.0, _SCORE_CRIT_MAX))


def confidence_from_error(error: float, calibration: ErrorCalibration) -> float:
    """Model certainty from distance to the training error distribution.

    Returns a value in ``[0, 1]`` (UI shows percent). Bands follow
    ``RiskEngineConfig`` (imported lazily to avoid cycles)::

        clearly normal (≤ mean)     → ~48–58%
        near decision boundary      → ~45–60%
        moderately anomalous        → ~60–80%
        far outside (≫ p99)         → ~80–99%

    Near-threshold sessions are intentionally *less* certain than extreme
    outliers — Confirmed Threat requires high confidence.
    """
    from synthetic_data.risk_engine.config import DEFAULT_RISK_CONFIG

    cfg = DEFAULT_RISK_CONFIG
    value = float(error)
    mean = float(calibration.mean)
    p80 = float(calibration.p80)
    p95 = float(calibration.p95)
    p99 = float(calibration.p99)
    sigma = max(float(calibration.std), 1e-8)

    # Ensure ordered anchors.
    if p80 <= mean:
        p80 = mean + 0.5 * sigma
    if p95 <= p80:
        p95 = p80 + 0.5 * sigma
    if p99 <= p95:
        p99 = p95 + 0.5 * sigma

    if value <= mean:
        t = (mean - value) / max(3.0 * sigma, 1e-8)
        t = float(np.clip(t, 0.0, 1.0))
        # Deeper into the normal mass → slightly higher "routine" certainty,
        # still in the calm mid band (not threat-grade).
        conf = cfg.confidence_normal_ceiling - (
            cfg.confidence_normal_ceiling - cfg.confidence_normal_floor
        ) * (1.0 - t)
    elif value <= p80:
        t = (value - mean) / max(p80 - mean, 1e-8)
        conf = cfg.confidence_normal_ceiling + (
            cfg.confidence_near_floor - cfg.confidence_normal_ceiling
        ) * t
    elif value <= p95:
        # Near reconstruction / decision threshold → 45–60%.
        t = (value - p80) / max(p95 - p80, 1e-8)
        conf = cfg.confidence_near_floor + (
            cfg.confidence_near_ceiling - cfg.confidence_near_floor
        ) * t
    elif value <= p99:
        # Moderately anomalous → 60–80%.
        t = (value - p95) / max(p99 - p95, 1e-8)
        conf = cfg.confidence_moderate_floor + (
            cfg.confidence_moderate_ceiling - cfg.confidence_moderate_floor
        ) * t
    else:
        # Strong anomaly far outside → 80–99%.
        excess = (value - p99) / sigma
        conf = cfg.confidence_strong_floor + (
            cfg.confidence_strong_ceiling - cfg.confidence_strong_floor
        ) * math.tanh(excess / 1.8)

    return float(np.clip(conf / 100.0, 0.0, 0.99))


def risk_band(score: float) -> str:
    """Map anomaly/risk score onto LOW/MEDIUM/HIGH/CRITICAL."""
    if score <= _SCORE_LOW_MAX:
        return "LOW"
    if score <= _SCORE_MED_MAX:
        return "MEDIUM"
    if score <= _SCORE_HIGH_MAX:
        return "HIGH"
    return "CRITICAL"


def format_calibration_report(
    *,
    calibration: ErrorCalibration,
    errors: Sequence[float],
    scores: Sequence[float],
    title: str = "Anomaly calibration report",
) -> str:
    """Human-readable calibration report."""
    arr = np.asarray(list(errors), dtype=np.float64)
    bands = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for score in scores:
        bands[risk_band(float(score))] += 1
    total = max(sum(bands.values()), 1)

    lines = [
        "=" * 64,
        title,
        "=" * 64,
        "",
        "Normal reconstruction-error distribution",
        f"  n_samples : {calibration.n_samples or arr.size}",
        f"  mean      : {calibration.mean:.6f}",
        f"  std       : {calibration.std:.6f}",
        f"  min       : {calibration.error_min:.6f}",
        f"  max       : {calibration.error_max:.6f}",
        f"  p80       : {calibration.p80:.6f}",
        f"  p90       : {calibration.p90:.6f}",
        f"  p95       : {calibration.p95:.6f}",
        f"  p99       : {calibration.p99:.6f}",
        "",
        "Score thresholds (error -> risk band)",
        f"  LOW      : error <= p80 ({calibration.p80:.6f}) -> score 0-24",
        f"  MEDIUM   : p80-p90                 -> score 25-49",
        f"  HIGH     : p90-p95                 -> score 50-74",
        f"  CRITICAL : error > p95 ({calibration.p95:.6f}) -> score 75-100",
        "  (CRITICAL ~= top 5% of normal calibration mass)",
        "",
        "Sessions by anomaly band (this evaluation set)",
        f"  LOW      : {bands['LOW']:5d}  ({100.0 * bands['LOW'] / total:5.1f}%)",
        f"  MEDIUM   : {bands['MEDIUM']:5d}  ({100.0 * bands['MEDIUM'] / total:5.1f}%)",
        f"  HIGH     : {bands['HIGH']:5d}  ({100.0 * bands['HIGH'] / total:5.1f}%)",
        f"  CRITICAL : {bands['CRITICAL']:5d}  ({100.0 * bands['CRITICAL'] / total:5.1f}%)",
        "=" * 64,
    ]
    return "\n".join(lines)
