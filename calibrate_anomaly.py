"""Recalibrate Transformer anomaly scores from normal-session reconstruction errors.

Does not change model weights / architecture. Updates percentile calibration
stored alongside the checkpoint and prints a calibration report.

Examples::

    python calibrate_anomaly.py
    python calibrate_anomaly.py --events datasets/events.csv --limit-sessions 2000
    python calibrate_anomaly.py --model models/sentinelai_transformer.pt
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("calibrate_anomaly")

# Event types that strongly suggest non-normal / attack-like sessions.
_ATTACKISH_EVENTS = frozenset(
    {
        "FAILED_LOGIN",
        "USB_INSERT",
        "USB_REMOVE",
        "SSH_LOGIN",
        "REMOTE_DESKTOP",
        "ADMIN_LOGIN",
        "PRIVILEGE_ESCALATION",
        "POLICY_CHANGE",
        "PASSWORD_CHANGE",
        "MFA_FAILURE",
    }
)


def _load_normal_sessions_from_events(
    path: Path,
    *,
    limit_sessions: int | None,
) -> list:
    from synthetic_data.behavioural_transformer import SequenceBuilder

    rows: list[dict[str, object]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader):
            ts = row.get("timestamp") or ""
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
    sequences = builder.events_to_sessions(rows)

    # Keep sessions without attack-indicative event types as "normal".
    normal = [
        seq
        for seq in sequences
        if not any(event in _ATTACKISH_EVENTS for event in seq.event_types)
        and len(seq.event_types) >= 4
    ]
    if limit_sessions is not None:
        normal = normal[:limit_sessions]
    logger.info(
        "Loaded %s total sessions; %s treated as normal for calibration",
        len(sequences),
        len(normal),
    )
    return normal


def _compute_errors(model, sequences, *, batch_size: int = 32) -> list[float]:
    from synthetic_data.behavioural_transformer.sequence_builder import SequenceBuilder

    device = torch.device("cpu")
    net = model.artifact.model.to(device)
    net.eval()
    builder = SequenceBuilder(
        config=model.artifact.config,
        vocabulary=model.artifact.vocabulary,
    )
    encoded = builder.encode(sequences)
    errors: list[float] = []
    with torch.no_grad():
        for start in range(0, len(encoded.token_ids), batch_size):
            end = start + batch_size
            token_ids = torch.tensor(
                encoded.token_ids[start:end], dtype=torch.long, device=device
            )
            attention_mask = torch.tensor(
                encoded.attention_mask[start:end], dtype=torch.long, device=device
            )
            seq_err, _ = net.reconstruction_errors(token_ids, attention_mask)
            errors.extend(float(x) for x in seq_err.cpu().tolist())
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Calibrate SentinelAI anomaly scores")
    parser.add_argument(
        "--model",
        default="models/sentinelai_transformer.pt",
        help="Path to Transformer artifact",
    )
    parser.add_argument(
        "--events",
        default="datasets/events.csv",
        help="Events CSV used to build normal sessions",
    )
    parser.add_argument("--limit-sessions", type=int, default=3000)
    parser.add_argument(
        "--report",
        default="reports/anomaly_calibration_report.txt",
        help="Where to write the calibration report",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Analyse only; do not update the model artifact",
    )
    args = parser.parse_args()

    from synthetic_data.behavioural_transformer import TransformerAnomalyModel
    from synthetic_data.behavioural_transformer.calibration import (
        ErrorCalibration,
        format_calibration_report,
        normalize_error,
    )

    model_path = Path(args.model)
    events_path = Path(args.events)
    if not model_path.exists():
        logger.error("Model not found: %s", model_path)
        return 1
    if not events_path.exists():
        logger.error("Events CSV not found: %s", events_path)
        return 1

    model = TransformerAnomalyModel.load(model_path)
    sequences = _load_normal_sessions_from_events(
        events_path, limit_sessions=args.limit_sessions
    )
    if len(sequences) < 20:
        logger.error("Need at least 20 normal sessions for calibration (got %s)", len(sequences))
        return 1

    errors = _compute_errors(model, sequences)
    calibration = ErrorCalibration.from_errors(errors)
    scores = [normalize_error(err, calibration) for err in errors]

    report = format_calibration_report(
        calibration=calibration,
        errors=errors,
        scores=scores,
        title="SentinelAI anomaly calibration report (normal sessions)",
    )
    print(report)

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report + "\n", encoding="utf-8")
    logger.info("Wrote report to %s", report_path)

    if not args.no_save:
        artifact = model.artifact
        artifact.calibration = calibration
        artifact.error_mean = calibration.mean
        artifact.error_std = calibration.std
        artifact.anomaly_threshold = calibration.p95
        artifact.save(model_path)
        logger.info(
            "Updated calibration on %s (p80=%.4f p90=%.4f p95=%.4f p99=%.4f)",
            model_path,
            calibration.p80,
            calibration.p90,
            calibration.p95,
            calibration.p99,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
