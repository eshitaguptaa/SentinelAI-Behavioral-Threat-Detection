"""Export demo feature vectors and audit Transformer scores on Normal Activity."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from synthetic_data.anomaly_detection.scoring import AnomalyPrediction
from synthetic_data.api.validation import build_feature_vector
from synthetic_data.attack_classification.engine import classify_attack
from synthetic_data.behavioural_transformer.inference import infer_sessions
from synthetic_data.behavioural_transformer.schema import SessionSequence
from synthetic_data.behavioural_transformer.train import load_trained_artifact
from synthetic_data.decision_status.derive import derive_final_status
from synthetic_data.demo import build_demo_feature_vectors, export_demo_json, kind_counts
from synthetic_data.risk_engine import assess_risk


def main() -> None:
    out = ROOT / "frontend" / "src" / "data" / "demoFeatureVectors.json"
    export_demo_json(out, count=24)
    vectors = build_demo_feature_vectors(24)
    print("Demo mix:", kind_counts(vectors))
    print(f"Wrote {out}")

    art = load_trained_artifact(ROOT / "models" / "sentinelai_transformer.pt")
    cal = art.resolved_calibration()
    print(
        f"\nTraining calibration: mean={cal.mean:.4f} std={cal.std:.4f} "
        f"p80={cal.p80:.4f} p95={cal.p95:.4f}"
    )
    print(
        f"{'emp':8} {'kind':16} {'err':8} {'anom':6} {'attack':22} "
        f"{'risk':6} {'level':8} status"
    )

    normal_activity_over_70 = 0
    normal_kind_scores: list[float] = []
    normal_kind_errors: list[float] = []

    for demo in vectors:
        payload = demo.to_payload()
        seq = SessionSequence(
            employee_id=demo.employee_id,
            session_id=f"demo::{demo.employee_id}",
            simulation_day=demo.simulation_day,
            event_types=demo.event_sequence,
        )
        result = infer_sessions(art, [seq])[0]
        vector = build_feature_vector(payload)
        attack = classify_attack(vector)
        pred = AnomalyPrediction(
            employee_id=demo.employee_id,
            simulation_day=demo.simulation_day,
            raw_score=result.raw_score,
            normalized_score=result.normalized_score,
            prediction=result.prediction,
            is_anomaly=result.is_anomaly,
        )
        risk = assess_risk(pred, vector)
        status = derive_final_status(risk.risk_level, attack.attack_type)
        if attack.attack_type == "Normal Activity" and result.normalized_score > 70:
            normal_activity_over_70 += 1
        if demo.demo_kind == "normal":
            normal_kind_scores.append(result.normalized_score)
            normal_kind_errors.append(result.reconstruction_error)
        print(
            f"{demo.employee_id:8} {demo.demo_kind:16} {result.reconstruction_error:8.3f} "
            f"{result.normalized_score:6.1f} {attack.attack_type:22} "
            f"{risk.risk_score:6.1f} {risk.risk_level:8} {status}"
        )

    print(f"\n'Normal Activity' with anomaly_score > 70: {normal_activity_over_70}")
    if normal_kind_errors:
        print(
            f"demo_kind=normal reconstruction errors vs training mean {cal.mean:.4f}: "
            f"min={min(normal_kind_errors):.4f} max={max(normal_kind_errors):.4f} "
            f"mean={sum(normal_kind_errors)/len(normal_kind_errors):.4f}"
        )
        print(
            f"demo_kind=normal anomaly scores: "
            f"min={min(normal_kind_scores):.1f} max={max(normal_kind_scores):.1f} "
            f"mean={sum(normal_kind_scores)/len(normal_kind_scores):.1f}"
        )
        above_p80 = sum(1 for e in normal_kind_errors if e > cal.p80)
        print(f"demo_kind=normal errors above training p80: {above_p80}/{len(normal_kind_errors)}")


if __name__ == "__main__":
    main()
