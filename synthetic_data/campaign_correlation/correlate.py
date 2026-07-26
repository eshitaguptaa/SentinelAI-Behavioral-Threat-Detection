"""Correlate scored sessions into kill-chain CampaignCase objects.

Groups by explicit ``campaign_id`` when present (demo / simulator metadata),
otherwise by same ``entity_id`` across nearby days with signature attack labels.
Does not retrain models or mutate detection scores.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Final, Mapping, Sequence

from synthetic_data.campaign_correlation.schema import CampaignCase, CampaignStage
from synthetic_data.mitre import mitre_dict

# Signature labels that can form kill-chain stages (exclude soft / none labels).
_NON_SIGNATURE: Final[frozenset[str]] = frozenset(
    {
        "None",
        "Normal Activity",
        "Behavioural Anomaly",
        "Unknown Behaviour",
        "",
    }
)

# Kill-chain phase rank — lower = earlier in the intrusion story.
_STAGE_RANK: Final[dict[str, int]] = {
    "Impossible Travel": 1,
    "Brute Force": 1,
    "Credential Stuffing": 1,
    "Device Spoofing": 1,
    "Lateral Movement": 2,
    "Suspicious VPN Usage": 2,
    "Insider Activity": 2,
    "Insider Drift": 2,
    "Mass Download": 3,
    "Low-and-Slow Exfiltration": 3,
}

_WINDOW_DAYS: Final[int] = 7

_TEMPLATE_NAMES: Final[tuple[tuple[tuple[str, ...], str, str], ...]] = (
    (
        ("Brute Force", "Lateral Movement", "Mass Download"),
        "BRUTE_FORCE_TO_EXFIL",
        "Brute Force → Lateral Movement → Mass Download",
    ),
    (
        ("Brute Force", "Lateral Movement", "Low-and-Slow Exfiltration"),
        "BRUTE_FORCE_TO_EXFIL",
        "Brute Force → Lateral Movement → Low-and-Slow Exfiltration",
    ),
    (
        ("Impossible Travel", "Lateral Movement", "Mass Download"),
        "TRAVEL_TO_EXFIL",
        "Impossible Travel → Lateral Movement → Mass Download",
    ),
    (
        ("Credential Stuffing", "Lateral Movement", "Mass Download"),
        "CREDENTIAL_TO_EXFIL",
        "Credential Stuffing → Lateral Movement → Mass Download",
    ),
    (
        ("Brute Force", "Mass Download"),
        "BRUTE_FORCE_TO_EXFIL",
        "Brute Force → Mass Download",
    ),
    (
        ("Lateral Movement", "Mass Download"),
        "LATERAL_TO_EXFIL",
        "Lateral Movement → Mass Download",
    ),
)


@dataclass(slots=True)
class ScoredSession:
    """Lightweight scored session used for correlation (API / batch results)."""

    employee_id: str
    simulation_day: str
    attack_type: str
    attack_confidence: float
    risk_score: float
    risk_level: str
    status: str
    matched_signals: list[str]
    contributing_factors: list[str]
    observations: list[str]
    mitre: dict[str, Any] | None = None
    campaign_id: str | None = None
    result_index: int | None = None


def _parse_day(value: str) -> date | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
        except ValueError:
            return None


def _is_signature(attack_type: str) -> bool:
    return (attack_type or "").strip() not in _NON_SIGNATURE


def _rank(attack_type: str) -> int:
    return _STAGE_RANK.get(attack_type, 50)


def _risk_rank(level: str) -> int:
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    return order.get((level or "").upper(), -1)


def _status_rank(status: str) -> int:
    order = {
        "Normal": 0,
        "Suspicious": 1,
        "Under Investigation": 2,
        "Confirmed Threat": 3,
    }
    return order.get(status or "", -1)


def _peak_level(stages: Sequence[CampaignStage]) -> str:
    best = max(stages, key=lambda s: (_risk_rank(s.risk_level), s.risk_score))
    return best.risk_level


def _peak_status(stages: Sequence[CampaignStage]) -> str:
    best = max(stages, key=lambda s: _status_rank(s.status))
    return best.status


def _match_template(attack_types: Sequence[str]) -> tuple[str, str]:
    seq = tuple(attack_types)
    for pattern, campaign_type, campaign_name in _TEMPLATE_NAMES:
        # Contiguous or ordered subsequence match.
        if _is_ordered_subsequence(pattern, seq) or seq == pattern:
            return campaign_type, campaign_name
        if len(seq) >= 2 and _is_ordered_subsequence(seq, pattern):
            return campaign_type, " → ".join(seq)
    if len(seq) >= 2:
        return "MULTI_STAGE", " → ".join(seq)
    label = seq[0] if seq else "Unknown"
    return "SINGLE_STAGE", f"{label} (standalone)"


def _is_ordered_subsequence(needle: Sequence[str], haystack: Sequence[str]) -> bool:
    if not needle:
        return True
    i = 0
    for item in haystack:
        if item == needle[i]:
            i += 1
            if i == len(needle):
                return True
    return False


def _stage_label(index: int, attack_type: str, total: int) -> str:
    if total <= 1:
        return attack_type
    phase = {
        1: "Initial access",
        2: "Expansion",
        3: "Objective",
    }.get(_rank(attack_type), "Stage")
    return f"Stage {index + 1}: {phase} — {attack_type}"


def _to_stage(
    session: ScoredSession,
    *,
    index: int,
    total: int,
    is_focus: bool,
) -> CampaignStage:
    mitre = session.mitre
    if mitre is None and _is_signature(session.attack_type):
        mitre = mitre_dict(session.attack_type)
    return CampaignStage(
        stage_index=index,
        stage_label=_stage_label(index, session.attack_type, total),
        employee_id=session.employee_id,
        simulation_day=session.simulation_day,
        attack_type=session.attack_type,
        attack_confidence=float(session.attack_confidence),
        risk_score=float(session.risk_score),
        risk_level=session.risk_level,
        status=session.status,
        matched_signals=list(session.matched_signals),
        contributing_factors=list(session.contributing_factors),
        observations=list(session.observations),
        mitre=dict(mitre) if mitre else None,
        is_focus=is_focus,
        result_index=session.result_index,
    )


def _build_case(
    *,
    case_id: str,
    sessions: Sequence[ScoredSession],
    correlation_basis: str,
    campaign_id: str | None,
    focus_employee_id: str | None,
    focus_day: str | None,
) -> CampaignCase:
    ordered = sorted(
        sessions,
        key=lambda s: (
            _parse_day(s.simulation_day) or date.min,
            _rank(s.attack_type),
            -float(s.risk_score),
        ),
    )
    total = len(ordered)
    stages: list[CampaignStage] = []
    focus_index: int | None = None
    for i, session in enumerate(ordered):
        is_focus = (
            focus_employee_id is not None
            and session.employee_id == focus_employee_id
            and (focus_day is None or session.simulation_day == focus_day)
        )
        if is_focus:
            focus_index = i
        stages.append(
            _to_stage(session, index=i, total=total, is_focus=is_focus)
        )

    attack_types = [s.attack_type for s in ordered]
    campaign_type, campaign_name = _match_template(attack_types)
    if campaign_id and total >= 2:
        campaign_name = " → ".join(attack_types)
        # Keep template type when recognizable; otherwise use the raw id.
        if campaign_type == "SINGLE_STAGE" or campaign_type == "MULTI_STAGE":
            campaign_type = campaign_id
    elif campaign_id and total < 2:
        campaign_type = campaign_id

    entities = sorted({s.employee_id for s in ordered})
    peak_score = max((s.risk_score for s in stages), default=0.0)
    peak_level = _peak_level(stages) if stages else "LOW"
    status = _peak_status(stages) if stages else "Normal"

    if total >= 2:
        summary = (
            f"{total}-stage kill chain for {', '.join(entities)}: {campaign_name}. "
            f"Peak risk {peak_score:.0f} ({peak_level}). Correlated via {correlation_basis}."
        )
    else:
        stage = stages[0] if stages else None
        summary = (
            f"Standalone session {stage.employee_id} / {stage.simulation_day}: "
            f"{stage.attack_type}."
            if stage
            else "Empty case."
        )

    return CampaignCase(
        case_id=case_id,
        campaign_id=campaign_id,
        campaign_name=campaign_name,
        campaign_type=campaign_type,
        correlation_basis=correlation_basis,
        summary=summary,
        entity_ids=entities,
        stage_count=total,
        peak_risk_score=float(peak_score),
        peak_risk_level=peak_level,
        status=status,
        stages=stages,
        focus_stage_index=focus_index,
    )


def _cluster_by_window(sessions: Sequence[ScoredSession]) -> list[list[ScoredSession]]:
    """Split same-entity signature sessions into day-window clusters."""
    if not sessions:
        return []
    ordered = sorted(
        sessions,
        key=lambda s: (_parse_day(s.simulation_day) or date.min, s.simulation_day),
    )
    clusters: list[list[ScoredSession]] = []
    current: list[ScoredSession] = [ordered[0]]
    current_day = _parse_day(ordered[0].simulation_day)

    for session in ordered[1:]:
        day = _parse_day(session.simulation_day)
        if (
            current_day is not None
            and day is not None
            and (day - current_day) <= timedelta(days=_WINDOW_DAYS)
        ):
            current.append(session)
            current_day = max(current_day, day)
        else:
            clusters.append(current)
            current = [session]
            current_day = day
    clusters.append(current)
    return clusters


def sessions_from_predict_payloads(
    results: Sequence[Mapping[str, Any]],
) -> list[ScoredSession]:
    """Convert API PredictResponse-like dicts into ScoredSession objects."""
    sessions: list[ScoredSession] = []
    for index, raw in enumerate(results):
        prediction = raw.get("prediction") or {}
        risk = raw.get("risk_assessment") or {}
        attack = raw.get("attack_classification") or {}
        explanation = raw.get("explanation") or {}
        mitre = raw.get("mitre")
        employee_id = str(
            prediction.get("employee_id")
            or attack.get("employee_id")
            or risk.get("employee_id")
            or ""
        )
        simulation_day = str(
            prediction.get("simulation_day")
            or attack.get("simulation_day")
            or risk.get("simulation_day")
            or ""
        )
        if not employee_id or not simulation_day:
            continue
        campaign_id = raw.get("campaign_id")
        if campaign_id is not None:
            campaign_id = str(campaign_id).strip() or None
        sessions.append(
            ScoredSession(
                employee_id=employee_id,
                simulation_day=simulation_day,
                attack_type=str(attack.get("attack_type") or "None"),
                attack_confidence=float(attack.get("attack_confidence") or 0.0),
                risk_score=float(risk.get("risk_score") or 0.0),
                risk_level=str(risk.get("risk_level") or "LOW"),
                status=str(raw.get("status") or "Normal"),
                matched_signals=[str(s) for s in (attack.get("matched_signals") or [])],
                contributing_factors=[
                    str(s) for s in (explanation.get("contributing_factors") or [])
                ],
                observations=[str(s) for s in (explanation.get("observations") or [])],
                mitre=dict(mitre) if isinstance(mitre, Mapping) else None,
                campaign_id=campaign_id,
                result_index=index,
            )
        )
    return sessions


def correlate_campaigns(
    sessions: Sequence[ScoredSession],
    *,
    focus_employee_id: str | None = None,
    focus_simulation_day: str | None = None,
) -> list[CampaignCase]:
    """Group scored sessions into campaign cases, multi-stage first.

    Correlation order:
    1. Explicit ``campaign_id`` groups (demo / simulator).
    2. Same entity + signature attacks within a 7-day window (≥2 stages).
    3. Remaining sessions as standalone cases (only returned when focused,
       or when they are the sole result for that entity/day).
    """
    if not sessions:
        return []

    cases: list[CampaignCase] = []
    consumed: set[tuple[str, str]] = set()
    case_counter = 0

    def _next_id(prefix: str) -> str:
        nonlocal case_counter
        case_counter += 1
        return f"{prefix}-{case_counter:03d}"

    # --- 1) Explicit campaign_id ---
    by_campaign: dict[str, list[ScoredSession]] = defaultdict(list)
    for session in sessions:
        if session.campaign_id:
            by_campaign[session.campaign_id].append(session)

    for campaign_id, group in sorted(by_campaign.items(), key=lambda kv: kv[0]):
        if len(group) < 1:
            continue
        for session in group:
            consumed.add((session.employee_id, session.simulation_day))
        cases.append(
            _build_case(
                case_id=_next_id("CMP"),
                sessions=group,
                correlation_basis="campaign_id",
                campaign_id=campaign_id,
                focus_employee_id=focus_employee_id,
                focus_day=focus_simulation_day,
            )
        )

    # --- 2) Entity + time-window signature chains ---
    by_entity: dict[str, list[ScoredSession]] = defaultdict(list)
    for session in sessions:
        key = (session.employee_id, session.simulation_day)
        if key in consumed:
            continue
        if _is_signature(session.attack_type):
            by_entity[session.employee_id].append(session)

    for entity_id, group in sorted(by_entity.items(), key=lambda kv: kv[0]):
        for cluster in _cluster_by_window(group):
            if len(cluster) < 2:
                continue
            for session in cluster:
                consumed.add((session.employee_id, session.simulation_day))
            cases.append(
                _build_case(
                    case_id=_next_id("ENT"),
                    sessions=cluster,
                    correlation_basis="entity_window",
                    campaign_id=None,
                    focus_employee_id=focus_employee_id,
                    focus_day=focus_simulation_day,
                )
            )

    # --- 3) Focus singleton (so Investigate always has a case) ---
    if focus_employee_id:
        focus_sessions = [
            s
            for s in sessions
            if s.employee_id == focus_employee_id
            and (focus_simulation_day is None or s.simulation_day == focus_simulation_day)
        ]
        for session in focus_sessions:
            key = (session.employee_id, session.simulation_day)
            already = any(
                any(
                    st.employee_id == session.employee_id
                    and st.simulation_day == session.simulation_day
                    for st in case.stages
                )
                for case in cases
            )
            if already:
                continue
            consumed.add(key)
            cases.append(
                _build_case(
                    case_id=_next_id("SGL"),
                    sessions=[session],
                    correlation_basis="focus_singleton",
                    campaign_id=session.campaign_id,
                    focus_employee_id=focus_employee_id,
                    focus_day=focus_simulation_day,
                )
            )

    # Prefer multi-stage cases, then higher peak risk.
    cases.sort(
        key=lambda c: (
            -(1 if c.stage_count >= 2 else 0),
            -c.peak_risk_score,
            c.case_id,
        )
    )
    return cases


def find_focus_case(
    cases: Sequence[CampaignCase],
    *,
    focus_employee_id: str | None,
    focus_simulation_day: str | None = None,
) -> CampaignCase | None:
    """Pick the best case containing the focused employee/day."""
    if not cases:
        return None
    if not focus_employee_id:
        return cases[0]

    multi = [
        c
        for c in cases
        if c.stage_count >= 2
        and any(
            s.employee_id == focus_employee_id
            and (
                focus_simulation_day is None or s.simulation_day == focus_simulation_day
            )
            for s in c.stages
        )
    ]
    if multi:
        return multi[0]

    for case in cases:
        for stage in case.stages:
            if stage.employee_id != focus_employee_id:
                continue
            if focus_simulation_day is None or stage.simulation_day == focus_simulation_day:
                return case
    return cases[0]
