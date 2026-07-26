"""Model loading helpers for Isolation Forest and Behavioural Transformer."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from synthetic_data.anomaly_detection import IsolationForestModel
from synthetic_data.anomaly_detection.validation import InvalidModelFileError

logger = logging.getLogger(__name__)

MODEL_PATH_ENV = "SENTINELAI_MODEL_PATH"
DETECTOR_ENV = "SENTINELAI_DETECTOR"


def load_anomaly_model(path: str | Path | None = None) -> Any | None:
    """Load Transformer or Isolation Forest from ``SENTINELAI_MODEL_PATH``.

    Detection order:
    1. Explicit ``SENTINELAI_DETECTOR=transformer|iforest``
    2. File suffix (``.pt`` / ``.pth`` → Transformer, ``.joblib`` → IF)
    3. Try Transformer, then Isolation Forest
    """
    if path is not None:
        raw = str(path).strip()
    else:
        raw = (os.environ.get(MODEL_PATH_ENV, "") or "").strip()
    if not raw:
        return None
    model_path = Path(raw)
    if not model_path.exists():
        logger.warning("Model path does not exist: %s", model_path)
        return None

    preferred = os.environ.get(DETECTOR_ENV, "").strip().lower()
    suffix = model_path.suffix.lower()

    def _load_transformer() -> Any | None:
        try:
            from synthetic_data.behavioural_transformer import TransformerAnomalyModel

            model = TransformerAnomalyModel.load(model_path)
            logger.info("Loaded Behavioural Transformer from %s", model_path)
            return model
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load Transformer from %s: %s", model_path, exc)
            return None

    def _load_iforest() -> Any | None:
        try:
            model = IsolationForestModel.load(model_path)
            logger.info("Loaded Isolation Forest from %s", model_path)
            return model
        except (InvalidModelFileError, OSError, ValueError) as exc:
            logger.warning("Failed to load Isolation Forest from %s: %s", model_path, exc)
            return None

    if preferred == "transformer" or suffix in {".pt", ".pth", ".bin"}:
        return _load_transformer()
    if preferred == "iforest" or suffix in {".joblib", ".pkl"}:
        return _load_iforest()

    return _load_transformer() or _load_iforest()
