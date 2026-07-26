"""Load the Behavioural Transformer anomaly detector for the inference API."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MODEL_PATH_ENV = "SENTINELAI_MODEL_PATH"


def load_anomaly_model(path: str | Path | None = None) -> Any | None:
    """Load a fitted Behavioural Transformer from ``SENTINELAI_MODEL_PATH``.

    Expects a ``.pt`` / ``.pth`` artifact produced by
    ``train_transformer_model.py``. Returns ``None`` when the path is unset,
    missing, or fails to load.
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

    suffix = model_path.suffix.lower()
    if suffix not in {".pt", ".pth", ".bin"}:
        logger.warning(
            "Unsupported model artifact %s (expected Behavioural Transformer .pt)",
            model_path,
        )
        return None

    try:
        from synthetic_data.behavioural_transformer import TransformerAnomalyModel

        model = TransformerAnomalyModel.load(model_path)
        logger.info("Loaded Behavioural Transformer from %s", model_path)
        return model
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load Transformer from %s: %s", model_path, exc)
        return None
