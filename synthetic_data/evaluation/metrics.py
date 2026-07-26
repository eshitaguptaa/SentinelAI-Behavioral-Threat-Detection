"""Offline evaluation against simulator ground-truth labels.

Computes detection metrics under class imbalance, anomaly-type classification
accuracy, and false-positive rate at an analyst alert budget (top-k%).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from synthetic_data.feature_engineering.feature_schema import FeatureVector


class AnomalyPredictionLike(Protocol):
    """Minimal prediction shape for offline metrics."""

    employee_id: str
    simulation_day: str
    normalized_score: float

# Injection GT field → preferred classifier display label.
_GT_FIELD_TO_LABEL: tuple[tuple[str, str], ...] = (
    ("impossible_travel_count", "Impossible Travel"),
    ("brute_force_count", "Brute Force"),
    ("credential_theft_count", "Credential Stuffing"),
    ("device_spoofing_count", "Device Spoofing"),
    ("lateral_movement_count", "Lateral Movement"),
    ("low_and_slow_count", "Low-and-Slow Exfiltration"),
    ("data_exfiltration_count", "Mass Download"),
    ("after_hours_attack_count", "Insider Activity"),
    ("privilege_escalation_count", "Lateral Movement"),
    ("insider_drift_count", "Insider Drift"),
)

# True intrusions for binary detection (exclude Insider Drift edge cases).
_INTRUSION_GT_FIELDS: tuple[str, ...] = tuple(
    name for name, _label in _GT_FIELD_TO_LABEL if name != "insider_drift_count"
)


@dataclass(slots=True)
class BinaryMetrics:
    """Binary anomaly detection metrics."""

    support_positive: int
    support_negative: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    specificity: float
    false_positive_rate: float
    prevalence: float


@dataclass(slots=True)
class AlertBudgetMetrics:
    """FPR / precision when only the top-k% scored events are alerted."""

    top_percent: float
    alert_count: int
    true_positives: int
    false_positives: int
    precision_at_k: float
    false_positive_rate_at_k: float
    recall_at_k: float


@dataclass(slots=True)
class TypeMetrics:
    """Per-type / overall classification accuracy vs GT."""

    overall_accuracy: float
    labeled_support: int
    correct: int
    per_type: dict[str, dict[str, float | int]] = field(default_factory=dict)
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)


@dataclass(slots=True)
class EvaluationReport:
    """Full offline evaluation payload."""

    n_samples: int
    binary: BinaryMetrics
    alert_budgets: list[AlertBudgetMetrics]
    attack_types: TypeMetrics
    class_imbalance_notes: list[str]
    edge_case_insider_drift: dict[str, int]


def _safe_div(num: float, den: float) -> float:
    return float(num) / float(den) if den else 0.0


def is_true_intrusion(vector: FeatureVector) -> bool:
    """True when GT marks a real intrusion (not Insider Drift alone)."""
    return any(int(getattr(vector, name, 0) or 0) > 0 for name in _INTRUSION_GT_FIELDS)


def is_insider_drift_only(vector: FeatureVector) -> bool:
    """Edge-case day used for false-positive tuning."""
    drift = int(getattr(vector, "insider_drift_count", 0) or 0)
    if drift <= 0:
        return False
    return not is_true_intrusion(vector)


def primary_gt_attack_label(vector: FeatureVector) -> str | None:
    """Dominant injected attack label for type-classification scoring."""
    best_label: str | None = None
    best_count = 0
    for field_name, label in _GT_FIELD_TO_LABEL:
        count = int(getattr(vector, field_name, 0) or 0)
        if count > best_count:
            best_count = count
            best_label = label
    return best_label


def _binary_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
) -> BinaryMetrics:
    tp = fp = tn = fn = 0
    for truth, pred in zip(y_true, y_pred, strict=True):
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 0 and pred == 1:
            fp += 1
        elif truth == 0 and pred == 0:
            tn += 1
        else:
            fn += 1
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    specificity = _safe_div(tn, tn + fp)
    fpr = _safe_div(fp, fp + tn)
    pos = tp + fn
    neg = tn + fp
    return BinaryMetrics(
        support_positive=pos,
        support_negative=neg,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        specificity=specificity,
        false_positive_rate=fpr,
        prevalence=_safe_div(pos, pos + neg),
    )


def _alert_budget_metrics(
    y_true: Sequence[int],
    scores: Sequence[float],
    *,
    top_percent: float,
) -> AlertBudgetMetrics:
    n = len(scores)
    k = max(1, int(round(n * (top_percent / 100.0))))
    order = sorted(range(n), key=lambda i: scores[i], reverse=True)
    alert_idx = set(order[:k])
    tp = sum(1 for i in alert_idx if y_true[i] == 1)
    fp = sum(1 for i in alert_idx if y_true[i] == 0)
    neg = sum(1 for y in y_true if y == 0)
    pos = sum(1 for y in y_true if y == 1)
    return AlertBudgetMetrics(
        top_percent=top_percent,
        alert_count=k,
        true_positives=tp,
        false_positives=fp,
        precision_at_k=_safe_div(tp, tp + fp),
        false_positive_rate_at_k=_safe_div(fp, neg),
        recall_at_k=_safe_div(tp, pos),
    )


def _type_metrics(
    gt_labels: Sequence[str | None],
    pred_labels: Sequence[str],
) -> TypeMetrics:
    labeled = [
        (gt, pred)
        for gt, pred in zip(gt_labels, pred_labels, strict=True)
        if gt is not None
    ]
    if not labeled:
        return TypeMetrics(overall_accuracy=0.0, labeled_support=0, correct=0)

    correct = sum(1 for gt, pred in labeled if gt == pred)
    per_type_total: Counter[str] = Counter()
    per_type_hit: Counter[str] = Counter()
    confusion: dict[str, Counter[str]] = {}
    for gt, pred in labeled:
        per_type_total[gt] += 1
        if gt == pred:
            per_type_hit[gt] += 1
        confusion.setdefault(gt, Counter())[pred] += 1

    per_type = {
        label: {
            "support": per_type_total[label],
            "correct": per_type_hit[label],
            "accuracy": _safe_div(per_type_hit[label], per_type_total[label]),
        }
        for label in sorted(per_type_total)
    }
    return TypeMetrics(
        overall_accuracy=_safe_div(correct, len(labeled)),
        labeled_support=len(labeled),
        correct=correct,
        per_type=per_type,
        confusion={gt: dict(preds) for gt, preds in confusion.items()},
    )


def evaluate_predictions(
    vectors: Sequence[FeatureVector],
    predictions: Sequence[AnomalyPredictionLike],
    *,
    predicted_attack_types: Sequence[str] | None = None,
    alert_budgets: Sequence[float] = (1.0, 5.0),
    anomaly_threshold: float = 50.0,
) -> EvaluationReport:
    """Evaluate detector + classifier outputs against FeatureVector GT."""
    if len(vectors) != len(predictions):
        raise ValueError("vectors and predictions length mismatch")

    if predicted_attack_types is None:
        from synthetic_data.attack_classification import classify_attack

        predicted_attack_types = [
            classify_attack(
                vector,
                anomaly_score=float(pred.normalized_score),
            ).attack_type
            for vector, pred in zip(vectors, predictions, strict=True)
        ]
    if len(predicted_attack_types) != len(vectors):
        raise ValueError("predicted_attack_types length mismatch")

    y_true = [1 if is_true_intrusion(v) else 0 for v in vectors]
    y_pred = [
        1 if float(p.normalized_score) >= anomaly_threshold else 0
        for p in predictions
    ]
    scores = [float(p.normalized_score) for p in predictions]

    binary = _binary_metrics(y_true, y_pred)
    budgets = [
        _alert_budget_metrics(y_true, scores, top_percent=pct)
        for pct in alert_budgets
    ]
    gt_labels = [primary_gt_attack_label(v) for v in vectors]
    types = _type_metrics(gt_labels, list(predicted_attack_types))

    drift_days = sum(1 for v in vectors if is_insider_drift_only(v))
    drift_flagged = sum(
        1
        for v, pred in zip(vectors, predictions, strict=True)
        if is_insider_drift_only(v) and float(pred.normalized_score) >= anomaly_threshold
    )

    notes = [
        (
            f"Class imbalance: prevalence={binary.prevalence:.4f} "
            f"({binary.support_positive} positives / "
            f"{binary.support_positive + binary.support_negative} samples)."
        ),
        (
            "Detection is unsupervised; rarity is handled by calibration "
            "percentiles and analyst top-k% budgets rather than class weights."
        ),
        (
            "Insider Drift days are excluded from binary positives "
            "(edge case for false-positive tuning)."
        ),
    ]

    return EvaluationReport(
        n_samples=len(vectors),
        binary=binary,
        alert_budgets=budgets,
        attack_types=types,
        class_imbalance_notes=notes,
        edge_case_insider_drift={
            "days": drift_days,
            "flagged_as_anomaly": drift_flagged,
        },
    )


def report_to_dict(report: EvaluationReport) -> dict[str, Any]:
    """Plain dict suitable for JSON serialization."""
    return {
        "n_samples": report.n_samples,
        "binary": asdict(report.binary),
        "alert_budgets": [asdict(item) for item in report.alert_budgets],
        "attack_types": asdict(report.attack_types),
        "class_imbalance_notes": list(report.class_imbalance_notes),
        "edge_case_insider_drift": dict(report.edge_case_insider_drift),
    }


def format_evaluation_report(report: EvaluationReport) -> str:
    """Human-readable evaluation summary for ``reports/``."""
    b = report.binary
    lines = [
        "SentinelAI Offline Evaluation Report",
        "=" * 40,
        f"Samples: {report.n_samples}",
        "",
        "Binary detection (score >= 50, Insider Drift excluded from positives)",
        f"  Prevalence: {b.prevalence:.4f}",
        f"  Precision:  {b.precision:.4f}",
        f"  Recall:     {b.recall:.4f}",
        f"  F1:         {b.f1:.4f}",
        f"  FPR:        {b.false_positive_rate:.4f}",
        f"  TP/FP/TN/FN: {b.true_positives}/{b.false_positives}/{b.true_negatives}/{b.false_negatives}",
        "",
        "Analyst alert budgets",
    ]
    for budget in report.alert_budgets:
        lines.append(
            f"  Top {budget.top_percent:g}%: alerts={budget.alert_count} "
            f"precision={budget.precision_at_k:.4f} "
            f"FPR={budget.false_positive_rate_at_k:.4f} "
            f"recall={budget.recall_at_k:.4f}"
        )
    lines.extend(
        [
            "",
            "Anomaly-type classification (GT-labeled days only)",
            f"  Accuracy: {report.attack_types.overall_accuracy:.4f} "
            f"({report.attack_types.correct}/{report.attack_types.labeled_support})",
        ]
    )
    for label, stats in report.attack_types.per_type.items():
        lines.append(
            f"  - {label}: acc={stats['accuracy']:.4f} "
            f"({stats['correct']}/{stats['support']})"
        )
    lines.extend(["", "Class imbalance notes"])
    for note in report.class_imbalance_notes:
        lines.append(f"  - {note}")
    drift = report.edge_case_insider_drift
    lines.extend(
        [
            "",
            "Insider Drift edge cases",
            f"  Days: {drift.get('days', 0)}",
            f"  Flagged anomalous: {drift.get('flagged_as_anomaly', 0)}",
            "",
        ]
    )
    return "\n".join(lines)


def write_evaluation_reports(
    report: EvaluationReport,
    *,
    text_path: str | Path,
    json_path: str | Path | None = None,
) -> None:
    """Persist text (+ optional JSON) evaluation artifacts."""
    text_path = Path(text_path)
    text_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.write_text(format_evaluation_report(report), encoding="utf-8")
    if json_path is not None:
        json_file = Path(json_path)
        json_file.parent.mkdir(parents=True, exist_ok=True)
        json_file.write_text(
            json.dumps(report_to_dict(report), indent=2),
            encoding="utf-8",
        )
