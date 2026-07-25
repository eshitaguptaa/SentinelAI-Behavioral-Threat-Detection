"""Train a Behavioural Transformer on synthetic (or CSV) session sequences.

Examples::

    python train_transformer_model.py
    python train_transformer_model.py --epochs 15 --output models/sentinelai_transformer.pt
    python train_transformer_model.py --from-events datasets/events.csv
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("train_transformer")


def _load_sequences_from_events_csv(path: Path, *, limit: int | None = None):
    from synthetic_data.behavioural_transformer import SequenceBuilder

    rows: list[dict[str, object]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader):
            if limit is not None and index >= limit:
                break
            ts = row.get("timestamp") or row.get("event_time") or ""
            try:
                timestamp = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.min
            rows.append(
                {
                    "employee_id": row.get("employee_id", "UNKNOWN"),
                    "session_id": row.get("session_id") or "SESSION",
                    "event_type": row.get("event_type", "UNKNOWN"),
                    "timestamp": timestamp,
                    "event_id": row.get("event_id", str(index)),
                }
            )
    builder = SequenceBuilder()
    return builder.events_to_sessions(rows)


def _generate_synthetic_sequences(*, employees: int, days: int):
    from faker import Faker

    from synthetic_data.behavioural_transformer import SequenceBuilder
    from synthetic_data.generators.company_generator import generate_enterprise
    from synthetic_data.generators.behavior_profile_generator import (
        generate_behavior_profiles,
    )
    from synthetic_data.generators.timeline_generator import generate_workday_timelines

    fake = Faker()
    fake.seed_instance(42)
    enterprise = generate_enterprise(number_of_employees=employees, seed=42)
    profiles = generate_behavior_profiles(
        enterprise.employees,
        enterprise.resources,
        locations=enterprise.locations,
        departments_by_id={d.department_id: d.name for d in enterprise.departments},
        faker=fake,
    )
    all_events = []
    start = date.today() - timedelta(days=days)
    for offset in range(days):
        work_date = start + timedelta(days=offset)
        if work_date.weekday() >= 5:
            continue
        events = generate_workday_timelines(
            enterprise.employees,
            profiles,
            enterprise.devices,
            work_date=work_date,
            faker=fake,
        )
        all_events.extend(events)

    builder = SequenceBuilder()
    return builder.events_to_sessions(all_events)


def main() -> int:
    parser = argparse.ArgumentParser(description="Train SentinelAI Behavioural Transformer")
    parser.add_argument(
        "--output",
        default="models/sentinelai_transformer.pt",
        help="Checkpoint output path",
    )
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--employees", type=int, default=40)
    parser.add_argument("--days", type=int, default=5)
    parser.add_argument("--from-events", type=Path, default=None)
    parser.add_argument("--event-limit", type=int, default=None)
    parser.add_argument("--max-seq-len", type=int, default=64)
    args = parser.parse_args()

    if args.from_events is not None:
        logger.info("Loading sessions from %s", args.from_events)
        sequences = _load_sequences_from_events_csv(
            args.from_events, limit=args.event_limit
        )
    else:
        logger.info(
            "Generating synthetic sessions (employees=%s days=%s)",
            args.employees,
            args.days,
        )
        sequences = _generate_synthetic_sequences(
            employees=args.employees, days=args.days
        )

    if len(sequences) < 8:
        logger.error("Need more sessions to train (got %s)", len(sequences))
        return 1

    from synthetic_data.behavioural_transformer import (
        TransformerConfig,
        train_transformer,
    )

    config = TransformerConfig(
        max_epochs=args.epochs,
        batch_size=args.batch_size,
        max_seq_len=args.max_seq_len,
        patience=max(3, args.epochs // 3),
    )
    artifact = train_transformer(sequences, config=config)
    output = Path(args.output)
    artifact.save(output)
    logger.info(
        "Training complete. best_epoch=%s val_loss=%.4f threshold=%.4f → %s",
        artifact.history.best_epoch,
        artifact.history.best_val_loss,
        artifact.anomaly_threshold,
        output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
