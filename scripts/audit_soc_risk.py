"""Audit fused risk / status distribution on the demo batch."""

from __future__ import annotations

import sys
from collections import Counter
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
from synthetic_data.demo import build_demo_feature_vectors
from synthetic_data.risk_engine import assess_risk
from synthetic_data.risk_engine.scoring import map_risk_level


def main() -> None:
    art = load_trained_artifact(ROOT / "models" / "sentinelai_transformer.pt")
    vectors = build_demo_feature_vectors(24)
    statuses: list[str] = []
    levels: list[str] = []
    risks: list[float] = []

    print(
        f"{'emp':8} {'kind':16} {'anom':6} {'risk':6} {'conf%':5} "
        f"{'attack':20} {'level':8} status"
    )
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
        assessment = assess_risk(
            pred,
            vector,
            attack_confidence=float(attack.attack_confidence),
            model_confidence=float(result.confidence_score),
        )
        status = derive_final_status(
            assessment.risk_score,
            attack.attack_type,
            float(result.confidence_score),
        )
        level = map_risk_level(assessment.risk_score).value
        statuses.append(status)
        levels.append(level)
        risks.append(assessment.risk_score)
        print(
            f"{demo.employee_id:8} {demo.demo_kind:16} "
            f"{result.normalized_score:6.1f} {assessment.risk_score:6.1f} "
            f"{100 * result.confidence_score:5.0f} "
            f"{attack.attack_type:20} {level:8} {status}"
        )

    print("\nStatus counts:", dict(Counter(statuses)))
    print("Risk level counts:", dict(Counter(levels)))
    print(
        "Risk scores:",
        ", ".join(f"{r:.0f}" for r in sorted(risks, reverse=True)),
    )


if __name__ == "__main__":
    main()
