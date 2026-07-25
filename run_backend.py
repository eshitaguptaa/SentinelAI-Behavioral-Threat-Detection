#!/usr/bin/env python3
"""Start the SentinelAI FastAPI backend (no model training).

Loads environment variables from ``.env`` when present, then runs Uvicorn
against ``synthetic_data.api.app:app``.
"""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent


def main() -> None:
    """Launch the inference API."""
    load_dotenv(ROOT / ".env")

    host = os.getenv("API_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port_raw = os.getenv("API_PORT", "8000").strip() or "8000"
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise SystemExit(f"Invalid API_PORT={port_raw!r}") from exc

    model_path = os.getenv("SENTINELAI_MODEL_PATH", "").strip()
    if not model_path:
        print(
            "Warning: SENTINELAI_MODEL_PATH is unset. "
            "/predict endpoints will return 503 until a model is configured."
        )
    elif not Path(model_path).exists() and not (ROOT / model_path).exists():
        print(
            f"Warning: model file not found at {model_path!r}. "
            "Train Transformer: python train_transformer_model.py "
            "or Isolation Forest: python integration.py --prepare-model"
        )

    print(f"Starting SentinelAI API on http://{host}:{port}")
    print(f"Swagger UI: http://{host}:{port}/docs")
    uvicorn.run(
        "synthetic_data.api.app:app",
        host=host,
        port=port,
        reload=True,
    )


if __name__ == "__main__":
    main()
