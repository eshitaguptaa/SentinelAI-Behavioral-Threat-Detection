#!/usr/bin/env python3
"""Offline evaluation harness vs simulator attack labels.

Example::

    python evaluate_detection.py \\
        --model models/sentinelai_transformer.pt \\
        --events datasets/events.csv \\
        --report reports/detection_evaluation_report.txt \\
        --json reports/detection_evaluation_report.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from synthetic_data.api.model_loader import load_anomaly_model
from synthetic_data.attack_classification import classify_attack
from synthetic_data.attack_utils import load_events_from_csv
from synthetic_data.evaluation import (
    evaluate_predictions,
    format_evaluation_report,
    write_evaluation_reports,
)
from synthetic_data.feature_engineering import build_feature_vectors


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate SentinelAI detector against simulator GT labels.",
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=ROOT / "models" / "sentinelai_transformer.pt",
        help="Path to fitted Behavioural Transformer (.pt).",
    )
    parser.add_argument(
        "--events",
        type=Path,
        default=ROOT / "datasets" / "events.csv",
        help="Timeline CSV with optional injected attack metadata.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "reports" / "detection_evaluation_report.txt",
        help="Text report output path.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=ROOT / "reports" / "detection_evaluation_report.json",
        help="JSON report output path.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional cap on employee-day vectors (0 = all).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=50.0,
        help="Normalized anomaly score threshold for binary detection.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if not args.model.exists():
        print(f"Model not found: {args.model}", file=sys.stderr)
        return 1
    if not args.events.exists():
        print(f"Events CSV not found: {args.events}", file=sys.stderr)
        return 1

    print(f"Loading events from {args.events} ...")
    events = load_events_from_csv(args.events)
    print(f"Building feature vectors ({len(events)} events) ...")
    vectors = build_feature_vectors(events)
    if args.limit and args.limit > 0:
        vectors = vectors[: args.limit]
    print(f"Scoring {len(vectors)} employee-days with {args.model.name} ...")

    model = load_anomaly_model(args.model)
    if model is None:
        print(f"Failed to load model: {args.model}", file=sys.stderr)
        return 1
    if hasattr(model, "predict"):
        predictions = model.predict(vectors)
    else:
        raise SystemExit("Loaded model does not expose predict()")

    attack_types = [
        classify_attack(
            vector,
            anomaly_score=float(pred.normalized_score),
        ).attack_type
        for vector, pred in zip(vectors, predictions, strict=True)
    ]

    report = evaluate_predictions(
        vectors,
        predictions,
        predicted_attack_types=attack_types,
        alert_budgets=(1.0, 5.0),
        anomaly_threshold=float(args.threshold),
    )
    write_evaluation_reports(
        report,
        text_path=args.report,
        json_path=args.json,
    )
    print(format_evaluation_report(report))
    print(f"Wrote {args.report}")
    print(f"Wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
