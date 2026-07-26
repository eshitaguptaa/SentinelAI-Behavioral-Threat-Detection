"""Tests for kill-chain campaign correlation."""

from __future__ import annotations

from synthetic_data.campaign_correlation import (
    ScoredSession,
    correlate_campaigns,
    find_focus_case,
    sessions_from_predict_payloads,
)
from synthetic_data.campaign_correlation.demo import (
    DEMO_CAMPAIGN_EMPLOYEE,
    DEMO_CAMPAIGN_ID,
    DEMO_CAMPAIGN_VECTORS,
)


def _session(
    *,
    employee_id: str,
    day: str,
    attack_type: str,
    risk: float = 70.0,
    campaign_id: str | None = None,
    index: int | None = None,
) -> ScoredSession:
    return ScoredSession(
        employee_id=employee_id,
        simulation_day=day,
        attack_type=attack_type,
        attack_confidence=0.9,
        risk_score=risk,
        risk_level="HIGH" if risk >= 55 else "MEDIUM",
        status="Confirmed Threat" if risk >= 80 else "Under Investigation",
        matched_signals=[f"signal={attack_type}"],
        contributing_factors=[f"factor={attack_type}"],
        observations=[],
        mitre=None,
        campaign_id=campaign_id,
        result_index=index,
    )


def test_correlate_by_campaign_id() -> None:
    sessions = [
        _session(
            employee_id=DEMO_CAMPAIGN_EMPLOYEE,
            day="2026-03-08",
            attack_type="Brute Force",
            risk=82,
            campaign_id=DEMO_CAMPAIGN_ID,
            index=0,
        ),
        _session(
            employee_id=DEMO_CAMPAIGN_EMPLOYEE,
            day="2026-03-09",
            attack_type="Lateral Movement",
            risk=78,
            campaign_id=DEMO_CAMPAIGN_ID,
            index=1,
        ),
        _session(
            employee_id=DEMO_CAMPAIGN_EMPLOYEE,
            day="2026-03-10",
            attack_type="Mass Download",
            risk=91,
            campaign_id=DEMO_CAMPAIGN_ID,
            index=2,
        ),
        _session(
            employee_id="EMP-OTHER",
            day="2026-03-10",
            attack_type="Normal Activity",
            risk=12,
            index=3,
        ),
    ]

    cases = correlate_campaigns(
        sessions,
        focus_employee_id=DEMO_CAMPAIGN_EMPLOYEE,
        focus_simulation_day="2026-03-09",
    )
    focus = find_focus_case(
        cases,
        focus_employee_id=DEMO_CAMPAIGN_EMPLOYEE,
        focus_simulation_day="2026-03-09",
    )

    assert focus is not None
    assert focus.stage_count == 3
    assert focus.correlation_basis == "campaign_id"
    assert focus.campaign_id == DEMO_CAMPAIGN_ID
    assert [s.attack_type for s in focus.stages] == [
        "Brute Force",
        "Lateral Movement",
        "Mass Download",
    ]
    assert focus.focus_stage_index == 1
    assert focus.stages[1].is_focus is True
    assert focus.stages[1].mitre is not None
    assert focus.stages[1].mitre["technique_id"] == "T1021"


def test_correlate_by_entity_window_without_campaign_id() -> None:
    sessions = [
        _session(
            employee_id="EMP-77",
            day="2026-03-08",
            attack_type="Brute Force",
            risk=80,
        ),
        _session(
            employee_id="EMP-77",
            day="2026-03-09",
            attack_type="Lateral Movement",
            risk=75,
        ),
        _session(
            employee_id="EMP-77",
            day="2026-03-10",
            attack_type="Mass Download",
            risk=88,
        ),
    ]
    cases = correlate_campaigns(sessions, focus_employee_id="EMP-77")
    assert len(cases) >= 1
    focus = find_focus_case(cases, focus_employee_id="EMP-77")
    assert focus is not None
    assert focus.stage_count == 3
    assert focus.correlation_basis == "entity_window"


def test_sessions_from_predict_payloads_and_demo_vectors() -> None:
    assert len(DEMO_CAMPAIGN_VECTORS) == 3
    assert all(v["campaign_id"] == DEMO_CAMPAIGN_ID for v in DEMO_CAMPAIGN_VECTORS)

    payloads = [
        {
            "prediction": {
                "employee_id": "EMP-K01",
                "simulation_day": "2026-03-08",
                "raw_score": -0.2,
                "normalized_score": 70.0,
                "prediction": -1,
                "is_anomaly": True,
            },
            "risk_assessment": {
                "employee_id": "EMP-K01",
                "simulation_day": "2026-03-08",
                "anomaly_score": 70.0,
                "risk_score": 82.0,
                "risk_level": "HIGH",
                "contributing_factors": ["a"],
                "recommendation": "review",
            },
            "attack_classification": {
                "employee_id": "EMP-K01",
                "simulation_day": "2026-03-08",
                "attack_type": "Brute Force",
                "attack_confidence": 0.92,
                "matched_signals": ["auth_failure_rate=0.62"],
            },
            "explanation": {
                "employee_id": "EMP-K01",
                "simulation_day": "2026-03-08",
                "risk_score": 82.0,
                "risk_level": "HIGH",
                "summary": "x",
                "contributing_factors": ["transformer"],
                "observations": ["rule"],
                "recommendation": "isolate",
            },
            "status": "Confirmed Threat",
            "campaign_id": DEMO_CAMPAIGN_ID,
        }
    ]
    sessions = sessions_from_predict_payloads(payloads)
    assert len(sessions) == 1
    assert sessions[0].campaign_id == DEMO_CAMPAIGN_ID
    assert sessions[0].attack_type == "Brute Force"
