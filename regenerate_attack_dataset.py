#!/usr/bin/env python3
"""Inject attack patterns into the enterprise timeline and rewrite datasets/events.csv.

Preserves attack ground-truth in ``metadata_json`` so ``evaluate_detection.py``
can score against simulator labels.

Example::

    python regenerate_attack_dataset.py
    python regenerate_attack_dataset.py --attack-ratio 0.03 --seed 42
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from synthetic_data.attack_config import AttackConfig
from synthetic_data.attack_injector import inject_attacks
from synthetic_data.attack_utils import load_events_from_csv
from synthetic_data.generators.dataset_exporter import export_events_csv
from synthetic_data.schema_brief import enrich_timeline, export_access_logs_csv


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inject labeled attacks into datasets/events.csv.",
    )
    parser.add_argument(
        "--events",
        type=Path,
        default=ROOT / "datasets" / "events.csv",
        help="Target events CSV (overwritten with injected timeline).",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=ROOT / "datasets" / "events_baseline.csv",
        help="Clean baseline CSV used as injection source.",
    )
    parser.add_argument(
        "--access-logs",
        type=Path,
        default=ROOT / "datasets" / "access_logs.csv",
        help="Hackathon-schema access log export path.",
    )
    parser.add_argument(
        "--attack-ratio",
        type=float,
        default=0.10,
        help=(
            "Fraction of eligible employees targeted. Coverage logic still "
            "guarantees one sample per attack type when workforce allows."
        ),
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--max-attacks-per-employee",
        type=int,
        default=2,
        help="Allow up to this many techniques per selected employee.",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=ROOT / "reports" / "attack_injection_summary.json",
        help="Write injection summary JSON here.",
    )
    return parser.parse_args()


def _strip_existing_attacks(events: list) -> list:
    """Remove previously injected attack events so re-runs are idempotent."""
    cleaned = []
    for event in events:
        meta = event.metadata or {}
        if meta.get("is_attack") or meta.get("attack_type"):
            continue
        cleaned.append(event)
    return cleaned


def main() -> int:
    args = _parse_args()
    events_path = args.events
    baseline_path = args.baseline

    if not events_path.exists() and not baseline_path.exists():
        print(f"No events found at {events_path} or {baseline_path}", file=sys.stderr)
        return 1

    # First run: snapshot current CSV as the clean baseline.
    if not baseline_path.exists():
        source = events_path if events_path.exists() else baseline_path
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, baseline_path)
        print(f"Saved clean baseline -> {baseline_path}")

    print(f"Loading baseline from {baseline_path} ...")
    events = load_events_from_csv(baseline_path)
    events = _strip_existing_attacks(events)
    print(f"Baseline events: {len(events)}")

    config = AttackConfig(
        attack_ratio=float(args.attack_ratio),
        random_seed=int(args.seed),
        allow_multiple_attacks_per_employee=True,
        max_attacks_per_employee=int(args.max_attacks_per_employee),
        campaign_probability=0.15,
    )
    print(
        f"Injecting attacks (ratio={config.attack_ratio}, "
        f"max_per_employee={config.max_attacks_per_employee}, seed={config.random_seed}) ..."
    )
    result = inject_attacks(events, config=config)
    summary = result.summary
    print(
        f"Injected {summary.attacks_injected}/{summary.attacks_planned} "
        f"(skipped {summary.attacks_skipped}); "
        f"events {summary.total_input_events} -> {summary.total_output_events}"
    )
    print(f"By type: {summary.by_attack_type}")

    enriched = enrich_timeline(result.modified_events)
    export_events_csv(enriched, events_path)
    print(f"Wrote {events_path}")
    export_access_logs_csv(enriched, args.access_logs)
    print(f"Wrote brief-schema access logs -> {args.access_logs}")

    args.summary.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "events_path": str(events_path),
        "baseline_path": str(baseline_path),
        "access_logs_path": str(args.access_logs),
        "attack_ratio": config.attack_ratio,
        "random_seed": config.random_seed,
        "attacks_injected": summary.attacks_injected,
        "attacks_planned": summary.attacks_planned,
        "attacks_skipped": summary.attacks_skipped,
        "eligible_employees": summary.eligible_employees,
        "selected_targets": summary.selected_targets,
        "total_input_events": summary.total_input_events,
        "total_output_events": summary.total_output_events,
        "by_attack_type": summary.by_attack_type,
        "by_severity": summary.by_severity,
        "attack_types_covered": sorted(summary.by_attack_type.keys()),
        "attack_records": [
            {
                "attack_id": record.attack_id,
                "employee_id": record.employee_id,
                "attack_type": record.attack_type.value,
                "severity": record.severity.value,
                "day": record.day.isoformat(),
                "description": record.description,
                "injected_event_count": len(record.injected_event_ids),
            }
            for record in result.attack_records
        ],
    }
    args.summary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
