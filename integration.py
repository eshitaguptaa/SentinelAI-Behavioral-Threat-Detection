#!/usr/bin/env python3
"""End-to-end SentinelAI integration demo (Behavioural Transformer).

Pipeline demonstrated::

    Load Transformer
        ↓
    Create FeatureVector (+ event sequence)
        ↓
    Predict (reconstruction anomaly)
        ↓
    Risk Assessment
        ↓
    Explainability
        ↓
    Print JSON result

Usage::

    python integration.py
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from synthetic_data.behavioural_transformer import TransformerAnomalyModel
from synthetic_data.behavioural_transformer.schema import SessionSequence
from synthetic_data.explainability import explain
from synthetic_data.feature_engineering.feature_schema import FeatureVector
from synthetic_data.risk_engine import assess_risk

ROOT = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = ROOT / "models" / "sentinelai_transformer.pt"


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


def demo_attack_sequence() -> list[str]:
    """Short OOD sequence that should elevate Transformer reconstruction error."""
    return [
        "DEVICE_CONNECT",
        "LOGIN",
        "FAILED_LOGIN",
        "FAILED_LOGIN",
        "FAILED_LOGIN",
        "ADMIN_LOGIN",
        "SSH_LOGIN",
        "REMOTE_DESKTOP",
        "DATABASE_ACCESS",
        "FILE_DOWNLOAD",
        "FILE_DOWNLOAD",
        "USB_INSERT",
        "FILE_DOWNLOAD",
        "LOGOUT",
    ]


def load_model(path: Path) -> TransformerAnomalyModel:
    """Load a previously fitted Behavioural Transformer from disk."""
    if not path.exists():
        raise FileNotFoundError(
            f"Model not found: {path}\n"
            "Train first: python train_transformer_model.py"
        )
    return TransformerAnomalyModel.load(path)


def run_pipeline(model: TransformerAnomalyModel) -> dict[str, Any]:
    """Execute FeatureVector → Predict → Risk → Explain for one employee-day."""
    sequence = demo_attack_sequence()
    vector = build_feature_vector(
        employee_id="EMP-DEMO",
        simulation_day="2026-03-10",
        total_events=len(sequence),
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

    session = SessionSequence(
        employee_id=vector.employee_id,
        session_id=f"DEMO::{vector.employee_id}::{vector.simulation_day}",
        simulation_day=vector.simulation_day,
        event_types=sequence,
    )
    prediction = model.predict_one_sequence(session)
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
    """Resolve model path from env or the default Transformer location."""
    load_dotenv(ROOT / ".env")
    raw = os.getenv("SENTINELAI_MODEL_PATH", "").strip()
    if not raw:
        return DEFAULT_MODEL_PATH
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    return path


def main() -> None:
    """CLI entrypoint for full-pipeline demonstration."""
    parser = argparse.ArgumentParser(description="SentinelAI integration demo")
    parser.parse_args()

    model_path = resolve_model_path()
    model = load_model(model_path)
    print(f"Loaded Behavioural Transformer <- {model_path}")

    result = run_pipeline(model)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
