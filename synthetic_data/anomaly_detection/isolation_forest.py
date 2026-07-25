"""Isolation Forest estimator factory and default hyperparameters.

Thin wrapper around ``sklearn.ensemble.IsolationForest``. Does not perform
preprocessing or scoring — those live in sibling modules.
"""

from __future__ import annotations

from typing import Any

from sklearn.ensemble import IsolationForest

# Default Isolation Forest hyperparameters (Phase 9 specification).
DEFAULT_N_ESTIMATORS: int = 200
DEFAULT_MAX_SAMPLES: str | int | float = "auto"
DEFAULT_CONTAMINATION: str | float = "auto"
DEFAULT_BOOTSTRAP: bool = False
DEFAULT_RANDOM_STATE: int = 42
DEFAULT_N_JOBS: int = -1

DEFAULT_ISOLATION_FOREST_PARAMS: dict[str, Any] = {
    "n_estimators": DEFAULT_N_ESTIMATORS,
    "max_samples": DEFAULT_MAX_SAMPLES,
    "contamination": DEFAULT_CONTAMINATION,
    "bootstrap": DEFAULT_BOOTSTRAP,
    "random_state": DEFAULT_RANDOM_STATE,
    "n_jobs": DEFAULT_N_JOBS,
}


def build_isolation_forest(**overrides: Any) -> IsolationForest:
    """Construct an ``IsolationForest`` with Phase 9 defaults.

    Args:
        **overrides: Any sklearn ``IsolationForest`` keyword argument. User
            values replace defaults (e.g. ``random_state=7``, ``n_estimators=300``).

    Returns:
        Unfitted ``IsolationForest`` instance.
    """
    params = {**DEFAULT_ISOLATION_FOREST_PARAMS, **overrides}
    return IsolationForest(**params)


def isolation_forest_params(**overrides: Any) -> dict[str, Any]:
    """Return the effective parameter dictionary after applying overrides."""
    return {**DEFAULT_ISOLATION_FOREST_PARAMS, **overrides}
