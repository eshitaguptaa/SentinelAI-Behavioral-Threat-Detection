"""Audit reconstruction errors and risk for the current demo mix."""

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
from synthetic_data.risk_engine import assess_risk


def current_demo_vectors(count: int = 24) -> list[dict]:
    normal_engineering = [
        "DEVICE_CONNECT",
        "LOGIN",
        "MFA_SUCCESS",
        "EMAIL_ACCESS",
        "SLACK_ACCESS",
        "JIRA_ACCESS",
        "GITHUB_ACCESS",
        "GIT_PULL",
        "FILE_READ",
        "FILE_WRITE",
        "AWS_CONSOLE",
        "API_REQUEST",
        "SLACK_ACCESS",
        "EMAIL_ACCESS",
        "JIRA_ACCESS",
        "GITHUB_ACCESS",
        "FILE_READ",
        "TEAMS_ACCESS",
        "LOGOUT",
        "DEVICE_DISCONNECT",
    ]
    normal_finance = [
        "DEVICE_CONNECT",
        "LOGIN",
        "MFA_SUCCESS",
        "EMAIL_ACCESS",
        "EXCEL_ACCESS",
        "DATABASE_ACCESS",
        "PAYROLL_ACCESS",
        "FILE_READ",
        "FILE_WRITE",
        "TEAMS_ACCESS",
        "EMAIL_ACCESS",
        "DOCUMENT_ACCESS",
        "EXCEL_ACCESS",
        "DATABASE_ACCESS",
        "LOGOUT",
        "DEVICE_DISCONNECT",
    ]
    attack_variants = [
        [
            "DEVICE_CONNECT",
            "FAILED_LOGIN",
            "FAILED_LOGIN",
            "FAILED_LOGIN",
            "LOGIN",
            "PASSWORD_CHANGE",
            "EMAIL_ACCESS",
            "FILE_DOWNLOAD",
            "FILE_DOWNLOAD",
            "USB_INSERT",
            "LOGOUT",
            "DEVICE_DISCONNECT",
        ],
        [
            "DEVICE_CONNECT",
            "LOGIN",
            "FILE_READ",
            "FILE_READ",
            "FILE_DOWNLOAD",
            "FILE_DOWNLOAD",
            "USB_INSERT",
            "USB_REMOVE",
            "LOGOUT",
            "DEVICE_DISCONNECT",
        ],
        [
            "DEVICE_CONNECT",
            "LOGIN",
            "ADMIN_LOGIN",
            "POLICY_CHANGE",
            "DATABASE_ACCESS",
            "DATABASE_ACCESS",
            "FILE_DOWNLOAD",
            "LOGOUT",
            "DEVICE_DISCONNECT",
        ],
        [
            "DEVICE_CONNECT",
            "LOGIN",
            "SSH_LOGIN",
            "REMOTE_DESKTOP",
            "DATABASE_ACCESS",
            "AWS_CONSOLE",
            "FILE_DOWNLOAD",
            "LOGOUT",
            "DEVICE_DISCONNECT",
        ],
    ]
    vectors: list[dict] = []
    for i in range(count):
        tier = i % 5
        normal_base = normal_engineering if i % 2 == 0 else normal_finance
        event_sequence = (
            attack_variants[i % len(attack_variants)] if tier >= 2 else normal_base
        )
        is_attack = tier >= 2
        vectors.append(
            {
                "employee_id": f"EMP-{i + 1:03d}",
                "simulation_day": "2026-03-10",
                "event_sequence": event_sequence,
                "intended": "attack" if is_attack else "normal",
                "total_events": len(event_sequence),
                "login_count": 8 if (is_attack and tier == 3) else 1,
                "logout_count": 1,
                "auth_failure_rate": (
                    0.55 if tier == 4 else 0.28 if tier == 3 else 0.12 if tier == 2 else 0.02
                ),
                "max_failed_login_streak": (
                    8 if tier == 4 else 4 if tier == 3 else 2 if tier == 2 else 0
                ),
                "country_change_count": 2 if tier == 2 else 0,
                "location_change_count": (3 + (i % 3)) if is_attack else 1,
                "unique_device_count": 4 if tier == 4 else 1,
                "unique_location_count": 3 if is_attack else 1,
                "resource_entropy": 2.4 if is_attack else 0.5 + (i % 3) * 0.1,
                "device_entropy": 1.3 if tier == 4 else 0.2,
                "after_hours_event_count": 14 if tier == 4 else 3 if is_attack else 0,
                "download_size_mb_sum": (
                    180 if tier == 4 else 70 if tier == 3 else 35 if is_attack else 5 + (i % 4)
                ),
                "mass_download_event_count": 2 if tier == 4 else 0,
                "vpn_usage_ratio": 0.55 if is_attack else 0.1,
                "burst_max_5min": 18 + (i % 8) if is_attack else 4 + (i % 3),
                "active_duration_hours": 13 if tier == 4 else 7 + (i % 3),
                "file_access_ratio": 0.45 if is_attack else 0.15,
                "night_event_count": 4 if is_attack else 0,
                "application_access_count": 4 + (i % 4),
                "file_access_count": 8 if is_attack else 3,
            }
        )
    return vectors


def main() -> None:
    art = load_trained_artifact(ROOT / "models" / "sentinelai_transformer.pt")
    cal = art.resolved_calibration()
    print(
        f"Training calibration: mean={cal.mean:.4f} p80={cal.p80:.4f} "
        f"p90={cal.p90:.4f} p95={cal.p95:.4f} p99={cal.p99:.4f}"
    )
    vectors = current_demo_vectors()
    print(
        f"{'emp':8} {'int':7} {'err':8} {'anom':6} {'attack':22} "
        f"{'risk':6} {'level':8} status"
    )
    normal_labeled_high = 0
    intended_normal_scores: list[float] = []
    for v in vectors:
        seq = SessionSequence(
            employee_id=v["employee_id"],
            session_id="s",
            simulation_day=v["simulation_day"],
            event_types=v["event_sequence"],
        )
        result = infer_sessions(art, [seq])[0]
        vector = build_feature_vector(v)
        attack = classify_attack(vector)
        pred = AnomalyPrediction(
            employee_id=v["employee_id"],
            simulation_day=v["simulation_day"],
            raw_score=result.raw_score,
            normalized_score=result.normalized_score,
            prediction=result.prediction,
            is_anomaly=result.is_anomaly,
        )
        risk = assess_risk(pred, vector)
        status = derive_final_status(risk.risk_level, attack.attack_type)
        if attack.attack_type == "Normal Activity" and result.normalized_score > 70:
            normal_labeled_high += 1
        if v["intended"] == "normal":
            intended_normal_scores.append(result.normalized_score)
        print(
            f"{v['employee_id']:8} {v['intended']:7} {result.reconstruction_error:8.3f} "
            f"{result.normalized_score:6.1f} {attack.attack_type:22} "
            f"{risk.risk_score:6.1f} {risk.risk_level:8} {status}"
        )
    print(f"\nNormal Activity with anomaly_score > 70: {normal_labeled_high}")
    if intended_normal_scores:
        print(
            f"Intended-normal anomaly scores: "
            f"min={min(intended_normal_scores):.1f} "
            f"max={max(intended_normal_scores):.1f} "
            f"mean={sum(intended_normal_scores)/len(intended_normal_scores):.1f}"
        )


if __name__ == "__main__":
    main()
