"""SentinelAI FastAPI backend (Phase 12).

Exposes the Phase 8–11 inference pipeline over REST. Does not retrain models.

Public API::

    from synthetic_data.api import app

Run with::

    uvicorn synthetic_data.api.app:app --reload

Set ``SENTINELAI_MODEL_PATH`` to a Phase 9 ``save_model()`` artifact before
calling ``/predict`` or ``/predict/batch``.
"""

from synthetic_data.api.app import app, create_app

__all__ = ["app", "create_app"]
