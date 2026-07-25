#!/usr/bin/env python3
"""End-to-end SentinelAI integration demo.

Pipeline demonstrated::

    Load model
        ↓
    Create FeatureVector
        ↓
    Predict (Isolation Forest)
        ↓
    Risk Assessment
        ↓
    Explainability
        ↓
    Print JSON result

Usage::

    python integration.py
    python integration.py --prepare-model
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from synthetic_data.anomaly_detection import IsolationForestModel
from synthetic_data.explainability import explain
from synthetic_data.feature_engineering.feature_schema import FeatureVector
from synthetic_data.risk_engine import assess_risk

ROOT = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = ROOT / "models" / "sentinelai_iforest.joblib"


def build_feature_vector(
    employee_id: str,
    simulation_day: str,
    **overrides: Any,
) -> FeatureVector:
    """Construct a Phase 8 ``FeatureVector`` with deterministic defaults."""
    allowed = {f.name for f in fields(FeatureVector)}
    payload: dict[str, Any] = {
        "employee_id": employee_id,
        "simulation_day": simulation_day,
        "total_events": 36,
        "login_count": 2,
        "logout_count": 2,
        "auth_failure_rate": 0.05,
        "max_failed_login_streak": 1,
        "country_change_count": 0,
        "location_change_count": 2,
        "unique_device_count": 1,
        "unique_location_count": 1,
        "resource_entropy": 0.8,
        "device_entropy": 0.2,
        "after_hours_event_count": 2,
        "download_size_mb_sum": 12.0,
        "mass_download_event_count": 0,
        "vpn_usage_ratio": 0.2,
        "burst_max_5min": 6,
        "active_duration_hours": 8.5,
        "file_access_ratio": 0.2,
    }
    payload.update(overrides)
    return FeatureVector(**{k: v for k, v in payload.items() if k in allowed})


def demo_training_corpus() -> list[FeatureVector]:
    """Small deterministic corpus used only when preparing a demo model."""
    vectors: list[FeatureVector] = []
    for index in range(40):
        tier = index % 5
        vectors.append(
            build_feature_vector(
                employee_id=f"EMP-{index + 1:03d}",
                simulation_day="2026-03-10",
                total_events=15 + index,
                auth_failure_rate=0.02 * (index % 4) if tier < 3 else 0.45,
                max_failed_login_streak=index % 3 if tier < 3 else 7,
                country_change_count=0 if tier < 3 else 2,
                after_hours_event_count=index % 4 if tier < 3 else 14,
                download_size_mb_sum=5.0 + index if tier < 4 else 160.0,
                mass_download_event_count=0 if tier < 4 else 2,
                resource_entropy=0.5 + (index % 5) * 0.15 if tier < 3 else 2.5,
                burst_max_5min=5 + (index % 6) if tier < 3 else 28,
            )
        )
    return vectors


def prepare_model(path: Path) -> IsolationForestModel:
    """Fit and persist a demo Isolation Forest (offline preparation only)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    model = IsolationForestModel(random_state=42, n_estimators=80)
    model.fit(demo_training_corpus())
    model.save(path)
    print(f"Saved fitted model -> {path}")
    return model


def load_model(path: Path) -> IsolationForestModel:
    """Load a previously fitted model from disk."""
    if not path.exists():
        raise FileNotFoundError(
            f"Model not found: {path}\n"
            "Run: python integration.py --prepare-model"
        )
    return IsolationForestModel.load(path)


def run_pipeline(model: IsolationForestModel) -> dict[str, Any]:
    """Execute FeatureVector → Predict → Risk → Explain for one employee-day."""
    vector = build_feature_vector(
        employee_id="EMP-DEMO",
        simulation_day="2026-03-10",
        auth_failure_rate=0.58,
        max_failed_login_streak=8,
        country_change_count=3,
        after_hours_event_count=18,
        download_size_mb_sum=220.0,
        mass_download_event_count=2,
        resource_entropy=2.6,
        device_entropy=1.4,
        unique_device_count=4,
        burst_max_5min=30,
    )

    prediction = model.predict_one(vector)
    assessment = assess_risk(prediction, vector)
    explanation = explain(assessment, vector)

    return {
        "employee_id": vector.employee_id,
        "simulation_day": vector.simulation_day,
        "prediction": asdict(prediction),
        "risk_assessment": asdict(assessment),
        "explanation": asdict(explanation),
    }


def resolve_model_path() -> Path:
    """Resolve model path from env or the default demo location."""
    load_dotenv(ROOT / ".env")
    raw = os.getenv("SENTINELAI_MODEL_PATH", "").strip()
    if not raw:
        return DEFAULT_MODEL_PATH
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    return path


def main() -> None:
    """CLI entrypoint for model preparation and full-pipeline demonstration."""
    parser = argparse.ArgumentParser(description="SentinelAI integration demo")
    parser.add_argument(
        "--prepare-model",
        action="store_true",
        help="Fit and save a demo Isolation Forest, then run the pipeline",
    )
    args = parser.parse_args()

    model_path = resolve_model_path()
    if args.prepare_model or not model_path.exists():
        if not args.prepare_model and not model_path.exists():
            print(f"Model missing at {model_path}; preparing demo artifact…")
        model = prepare_model(model_path)
    else:
        model = load_model(model_path)
        print(f"Loaded model <- {model_path}")

    result = run_pipeline(model)
    print()
    print("=== SentinelAI end-to-end result ===")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
