"""Campaign Engine for SentinelAI.

Coordinates multi-stage cyber-attack campaigns by scheduling existing attack
modules across employees and simulation days. This module does **not** inject
timeline events — it only produces validated campaign plans for later
consumption by the Attack Injection Engine.
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Final

from synthetic_data.attack_config import DEFAULT_ATTACK_CONFIG, AttackConfig
from synthetic_data.attack_types import AttackTarget, AttackType, Severity
from synthetic_data.attack_utils import generate_attack_id
from synthetic_data.models import Employee

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CAMPAIGN_ID_PREFIX: Final[str] = "CMP"
ATTACK_ID_PREFIX: Final[str] = "ATK"

# Spacing between successive campaign stages (in days).
SPACING_SAME_DAY: Final[int] = 0
SPACING_NEXT_DAY: Final[int] = 1
SPACING_TWO_DAYS: Final[int] = 2
ALLOWED_SPACING: Final[tuple[int, ...]] = (
    SPACING_SAME_DAY,
    SPACING_NEXT_DAY,
    SPACING_TWO_DAYS,
)

SEVERITY_ATTACK_COUNTS: Final[dict[Severity, tuple[int, int]]] = {
    Severity.LOW: (2, 2),
    Severity.MEDIUM: (3, 3),
    Severity.HIGH: (4, 4),
    Severity.CRITICAL: (5, 7),
}

MIN_ATTACK_CONFIDENCE: Final[float] = 0.90
MAX_ATTACK_CONFIDENCE: Final[float] = 1.00

# Fallback fraction when campaign_probability * attack_ratio is too small.
DEFAULT_MAX_CAMPAIGN_FRACTION: Final[float] = 0.25


@dataclass(frozen=True, slots=True)
class CampaignTemplate:
    """Reusable multi-stage campaign blueprint."""

    campaign_type: str
    campaign_name: str
    attack_sequence: tuple[AttackType, ...]
    description: str


# Production campaign templates — stage order tells a realistic kill-chain story.
CAMPAIGN_TEMPLATES: Final[tuple[CampaignTemplate, ...]] = (
    CampaignTemplate(
        campaign_type="CREDENTIAL_TO_EXFIL",
        campaign_name=(
            "Credential Theft → Lateral Movement → Privilege Escalation → "
            "Data Exfiltration"
        ),
        attack_sequence=(
            AttackType.CREDENTIAL_THEFT,
            AttackType.LATERAL_MOVEMENT,
            AttackType.PRIVILEGE_ESCALATION,
            AttackType.DATA_EXFILTRATION,
        ),
        description=(
            "Initial credential compromise, internal pivoting, privilege abuse, "
            "then staged data theft."
        ),
    ),
    CampaignTemplate(
        campaign_type="BRUTE_FORCE_TO_EXFIL",
        campaign_name=(
            "Brute Force → Privilege Escalation → Lateral Movement → "
            "Data Exfiltration"
        ),
        attack_sequence=(
            AttackType.BRUTE_FORCE_LOGIN,
            AttackType.PRIVILEGE_ESCALATION,
            AttackType.LATERAL_MOVEMENT,
            AttackType.DATA_EXFILTRATION,
        ),
        description=(
            "Authentication abuse followed by elevated access, host pivoting, "
            "and exfiltration."
        ),
    ),
    CampaignTemplate(
        campaign_type="AFTER_HOURS_EXFIL",
        campaign_name=(
            "After Hours Access → Sensitive Resource Access → Data Exfiltration"
        ),
        attack_sequence=(
            AttackType.AFTER_HOURS_ACCESS,
            AttackType.PRIVILEGE_ESCALATION,
            AttackType.DATA_EXFILTRATION,
        ),
        description=(
            "Off-hours foothold, sensitive/admin resource abuse, then data "
            "exfiltration."
        ),
    ),
    CampaignTemplate(
        campaign_type="TRAVEL_TO_EXFIL",
        campaign_name="Impossible Travel → Credential Theft → Data Exfiltration",
        attack_sequence=(
            AttackType.IMPOSSIBLE_TRAVEL,
            AttackType.CREDENTIAL_THEFT,
            AttackType.DATA_EXFILTRATION,
        ),
        description=(
            "Geographically impossible access followed by credential abuse and "
            "exfiltration."
        ),
    ),
    CampaignTemplate(
        campaign_type="FULL_KILL_CHAIN",
        campaign_name=(
            "Credential Theft → Brute Force → Privilege Escalation → "
            "Lateral Movement → Data Exfiltration"
        ),
        attack_sequence=(
            AttackType.CREDENTIAL_THEFT,
            AttackType.BRUTE_FORCE_LOGIN,
            AttackType.PRIVILEGE_ESCALATION,
            AttackType.LATERAL_MOVEMENT,
            AttackType.DATA_EXFILTRATION,
        ),
        description=(
            "Extended enterprise kill chain covering identity abuse through "
            "exfiltration."
        ),
    ),
)


@dataclass(slots=True)
class ScheduledAttack:
    """One attack stage scheduled inside a campaign (no events injected)."""

    attack_id: str
    attack_type: AttackType
    day: date
    day_offset: int
    stage_index: int
    stage_label: str


@dataclass(slots=True)
class CampaignPlan:
    """Fully specified multi-stage attack campaign schedule.

    Attributes:
        campaign_id: Stable CMP-###### identifier.
        campaign_name: Human-readable campaign title.
        campaign_type: Template key (e.g. ``CREDENTIAL_TO_EXFIL``).
        employee_id: Targeted employee.
        severity: Campaign severity derived from stage count / selection.
        start_day: Calendar day of the first scheduled attack.
        end_day: Calendar day of the final scheduled attack.
        attack_sequence: Ordered attack techniques.
        attack_ids: Stable ID for each stage (ATK-compatible).
        attack_spacing: Day gaps preceding each stage after the first.
        scheduled_attacks: Concrete day assignments for each stage.
        expected_duration: Inclusive campaign length in days.
        attack_confidence: Deterministic confidence score in ``[0.90, 1.00]``.
        attack_count: Number of scheduled stages.
        description: Narrative summary for analysts / dashboards.
    """

    campaign_id: str
    campaign_name: str
    campaign_type: str
    employee_id: str
    severity: Severity
    start_day: date
    end_day: date
    attack_sequence: tuple[AttackType, ...]
    attack_ids: tuple[str, ...]
    attack_spacing: tuple[int, ...]
    scheduled_attacks: tuple[ScheduledAttack, ...]
    expected_duration: int
    attack_confidence: float
    attack_count: int
    description: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class CampaignEngine:
    """Generates deterministic multi-stage campaign schedules.

    The engine never mutates timelines. Callers convert plans into
    ``AttackTarget`` objects for the Attack Injector when ready.
    """

    config: AttackConfig = field(default_factory=AttackConfig)

    def generate(
        self,
        employees: Sequence[Employee] | Mapping[str, Employee] | Sequence[str],
        available_days: Sequence[date],
        *,
        config: AttackConfig | None = None,
        rng: random.Random | None = None,
        max_campaigns: int | None = None,
        attack_id_start: int = 1,
    ) -> list[CampaignPlan]:
        """Generate validated campaign plans for a simulation cohort."""
        return generate_campaigns(
            employees,
            available_days,
            config=config or self.config,
            rng=rng,
            max_campaigns=max_campaigns,
            attack_id_start=attack_id_start,
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_campaign_id(index: int, *, prefix: str = CAMPAIGN_ID_PREFIX) -> str:
    """Build a stable campaign identifier ``CMP-000001`` …"""
    return f"{prefix}-{index:06d}"


def generate_campaigns(
    employees: Sequence[Employee] | Mapping[str, Employee] | Sequence[str],
    available_days: Sequence[date],
    *,
    config: AttackConfig | None = None,
    rng: random.Random | None = None,
    max_campaigns: int | None = None,
    attack_id_start: int = 1,
) -> list[CampaignPlan]:
    """Create deterministic multi-stage campaign schedules.

    Args:
        employees: Employee entities, an ID→Employee map, or raw employee IDs.
        available_days: Simulation calendar days eligible for scheduling.
        config: Attack engine configuration (enabled types, ratios, seed).
        rng: Optional seeded RNG; defaults to ``config.random_seed``.
        max_campaigns: Optional hard cap on campaign count.
        attack_id_start: Starting index for ATK-###### allocation.

    Returns:
        Validated ``CampaignPlan`` objects. Invalid candidates are skipped.
    """
    effective = config or DEFAULT_ATTACK_CONFIG
    generator = rng if rng is not None else random.Random(effective.random_seed)

    employee_ids = _normalize_employee_ids(employees)
    employee_set = set(employee_ids)
    days = _normalize_days(available_days)
    if not employee_ids or not days:
        return []

    enabled_types = set(effective.resolve_enabled_types())
    templates = _compatible_templates(enabled_types)
    if not templates:
        return []

    campaign_budget = _resolve_campaign_budget(
        employee_count=len(employee_ids),
        config=effective,
        max_campaigns=max_campaigns,
    )
    if campaign_budget <= 0:
        return []

    selected_employees = _select_campaign_employees(
        employee_ids=employee_ids,
        budget=campaign_budget,
        rng=generator,
    )

    plans: list[CampaignPlan] = []
    attack_index = max(1, attack_id_start)
    campaign_index = 1

    for employee_id in selected_employees:
        if employee_id not in employee_set:
            continue

        severity = _choose_severity(effective, generator)
        template = _choose_template(templates, severity, generator)
        if template is None:
            continue

        sequence = _truncate_sequence(template.attack_sequence, severity, enabled_types)
        if len(sequence) < 2:
            continue

        spacing = _generate_spacing(len(sequence), generator)
        start_day = _choose_start_day(days, spacing, generator)
        if start_day is None:
            continue

        scheduled, attack_ids, attack_index = _schedule_attacks(
            sequence=sequence,
            spacing=spacing,
            start_day=start_day,
            available_days=days,
            attack_index=attack_index,
        )
        if scheduled is None:
            continue

        plan = _build_campaign_plan(
            campaign_id=generate_campaign_id(campaign_index),
            template=template,
            employee_id=employee_id,
            severity=severity,
            sequence=sequence,
            spacing=spacing,
            scheduled=scheduled,
            attack_ids=attack_ids,
            rng=generator,
        )
        if not _validate_campaign_plan(plan, employee_set, days, enabled_types):
            continue

        plans.append(plan)
        campaign_index += 1
        if len(plans) >= campaign_budget:
            break

    return plans


def campaign_to_attack_targets(plan: CampaignPlan) -> list[AttackTarget]:
    """Convert a campaign plan into injector-ready ``AttackTarget`` objects."""
    return [
        AttackTarget(
            employee_id=plan.employee_id,
            day=stage.day,
            attack_type=stage.attack_type,
            severity=plan.severity,
            campaign_id=plan.campaign_id,
        )
        for stage in plan.scheduled_attacks
    ]


def campaigns_to_attack_targets(plans: Sequence[CampaignPlan]) -> list[AttackTarget]:
    """Flatten many campaign plans into a chronological target list."""
    targets: list[AttackTarget] = []
    for plan in plans:
        targets.extend(campaign_to_attack_targets(plan))
    targets.sort(key=lambda item: (item.day, item.employee_id, item.attack_type.value))
    return targets


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_employee_ids(
    employees: Sequence[Employee] | Mapping[str, Employee] | Sequence[str],
) -> list[str]:
    """Extract a stable list of employee identifiers."""
    if isinstance(employees, Mapping):
        return sorted(str(employee_id) for employee_id in employees.keys())

    ids: list[str] = []
    for item in employees:
        if isinstance(item, Employee):
            ids.append(item.employee_id)
        else:
            ids.append(str(item))
    return list(dict.fromkeys(ids))


def _normalize_days(available_days: Sequence[date]) -> list[date]:
    """Return sorted unique simulation days."""
    return sorted(set(available_days))


def _compatible_templates(enabled_types: set[AttackType]) -> list[CampaignTemplate]:
    """Keep templates with enough enabled stages to form a campaign."""
    compatible: list[CampaignTemplate] = []
    for template in CAMPAIGN_TEMPLATES:
        if all(attack_type in enabled_types for attack_type in template.attack_sequence):
            compatible.append(template)
            continue
        filtered = tuple(
            attack_type
            for attack_type in template.attack_sequence
            if attack_type in enabled_types
        )
        if len(filtered) >= 2:
            compatible.append(
                CampaignTemplate(
                    campaign_type=template.campaign_type,
                    campaign_name=template.campaign_name,
                    attack_sequence=filtered,
                    description=template.description,
                )
            )
    return compatible


def _resolve_campaign_budget(
    *,
    employee_count: int,
    config: AttackConfig,
    max_campaigns: int | None,
) -> int:
    """Compute how many campaigns to attempt for this run."""
    ratio = max(0.0, float(config.attack_ratio)) * max(
        0.0, float(config.campaign_probability)
    )
    if ratio <= 0:
        ratio = DEFAULT_MAX_CAMPAIGN_FRACTION * max(0.0, float(config.attack_ratio))
    budget = int(round(employee_count * ratio))
    budget = max(0, min(employee_count, budget))
    if max_campaigns is not None:
        budget = min(budget, max(0, max_campaigns))
    return budget


def _select_campaign_employees(
    *,
    employee_ids: Sequence[str],
    budget: int,
    rng: random.Random,
) -> list[str]:
    """Deterministically sample employees that will receive campaigns."""
    if budget <= 0:
        return []
    if budget >= len(employee_ids):
        selected = list(employee_ids)
        rng.shuffle(selected)
        return selected
    return rng.sample(list(employee_ids), k=budget)


def _choose_severity(config: AttackConfig, rng: random.Random) -> Severity:
    """Sample a severity level using configured weights."""
    weights = config.normalized_severity_weights()
    severities = list(weights.keys())
    probs = [weights[severity] for severity in severities]
    return rng.choices(severities, weights=probs, k=1)[0]


def _target_stage_count(severity: Severity) -> int:
    """Return the preferred number of stages for a severity band."""
    low, _high = SEVERITY_ATTACK_COUNTS[severity]
    return low


def _choose_template(
    templates: Sequence[CampaignTemplate],
    severity: Severity,
    rng: random.Random,
) -> CampaignTemplate | None:
    """Pick a template that can satisfy the severity stage count."""
    desired = _target_stage_count(severity)
    preferred = [
        template
        for template in templates
        if len(template.attack_sequence) >= desired
    ]
    pool = preferred or list(templates)
    if not pool:
        return None
    return rng.choice(pool)


def _truncate_sequence(
    sequence: Sequence[AttackType],
    severity: Severity,
    enabled_types: set[AttackType],
) -> tuple[AttackType, ...]:
    """Fit a template sequence to severity and enabled-type constraints."""
    filtered = [attack_type for attack_type in sequence if attack_type in enabled_types]
    deduped: list[AttackType] = []
    seen: set[AttackType] = set()
    for attack_type in filtered:
        if attack_type in seen:
            continue
        seen.add(attack_type)
        deduped.append(attack_type)

    desired = _target_stage_count(severity)
    low, high = SEVERITY_ATTACK_COUNTS[severity]
    if severity == Severity.CRITICAL:
        desired = min(max(desired, low), high, len(deduped))
    else:
        desired = min(desired, len(deduped))

    if desired < low and len(deduped) >= low:
        desired = low
    return tuple(deduped[:desired])


def _generate_spacing(stage_count: int, rng: random.Random) -> tuple[int, ...]:
    """Generate day gaps between consecutive stages (length = stages - 1)."""
    if stage_count <= 1:
        return ()
    return tuple(rng.choice(ALLOWED_SPACING) for _ in range(stage_count - 1))


def _choose_start_day(
    available_days: Sequence[date],
    spacing: Sequence[int],
    rng: random.Random,
) -> date | None:
    """Pick a start day that leaves room for the full spaced campaign."""
    if not available_days:
        return None

    total_gap = sum(spacing)
    candidates: list[date] = []
    last_day = available_days[-1]
    for start in available_days:
        end = start + timedelta(days=total_gap)
        if end <= last_day:
            candidates.append(start)

    pool = candidates or list(available_days)
    return rng.choice(pool)


def _schedule_attacks(
    *,
    sequence: Sequence[AttackType],
    spacing: Sequence[int],
    start_day: date,
    available_days: Sequence[date],
    attack_index: int,
) -> tuple[tuple[ScheduledAttack, ...] | None, tuple[str, ...], int]:
    """Materialize concrete day assignments for each campaign stage."""
    day_set = set(available_days)
    sorted_days = list(available_days)
    scheduled: list[ScheduledAttack] = []
    attack_ids: list[str] = []
    cursor = start_day
    next_index = attack_index

    for stage_index, attack_type in enumerate(sequence):
        if stage_index > 0:
            gap = spacing[stage_index - 1]
            cursor = cursor + timedelta(days=gap)

        assigned_day = _snap_to_available_day(cursor, sorted_days, day_set)
        if assigned_day is None:
            return None, (), attack_index
        cursor = assigned_day

        attack_id = generate_attack_id(next_index, prefix=ATTACK_ID_PREFIX)
        next_index += 1
        attack_ids.append(attack_id)
        scheduled.append(
            ScheduledAttack(
                attack_id=attack_id,
                attack_type=attack_type,
                day=assigned_day,
                day_offset=(assigned_day - start_day).days,
                stage_index=stage_index,
                stage_label=_stage_label(attack_type, stage_index),
            )
        )

    for index in range(1, len(scheduled)):
        if scheduled[index].day < scheduled[index - 1].day:
            return None, (), attack_index

    return tuple(scheduled), tuple(attack_ids), next_index


def _snap_to_available_day(
    desired: date,
    sorted_days: Sequence[date],
    day_set: set[date],
) -> date | None:
    """Map a desired calendar day onto the nearest available simulation day."""
    if desired in day_set:
        return desired
    for day in sorted_days:
        if day >= desired:
            return day
    return sorted_days[-1] if sorted_days else None


def _stage_label(attack_type: AttackType, stage_index: int) -> str:
    """Human-readable stage label for scheduling metadata."""
    return f"Stage {stage_index + 1}: {attack_type.value.replace('_', ' ').title()}"


def _build_campaign_plan(
    *,
    campaign_id: str,
    template: CampaignTemplate,
    employee_id: str,
    severity: Severity,
    sequence: Sequence[AttackType],
    spacing: Sequence[int],
    scheduled: Sequence[ScheduledAttack],
    attack_ids: Sequence[str],
    rng: random.Random,
) -> CampaignPlan:
    """Assemble a fully populated ``CampaignPlan``."""
    start_day = scheduled[0].day
    end_day = scheduled[-1].day
    expected_duration = (end_day - start_day).days + 1
    attack_confidence = round(
        rng.uniform(MIN_ATTACK_CONFIDENCE, MAX_ATTACK_CONFIDENCE),
        2,
    )
    sequence_names = " → ".join(attack_type.value for attack_type in sequence)
    description = (
        f"{template.campaign_name}: employee {employee_id} from "
        f"{start_day.isoformat()} to {end_day.isoformat()} "
        f"({expected_duration} day(s), {len(sequence)} stages, "
        f"severity={severity.value}). Sequence: {sequence_names}. "
        f"{template.description}"
    )
    metadata = {
        "campaign_id": campaign_id,
        "campaign_name": template.campaign_name,
        "campaign_type": template.campaign_type,
        "severity": severity.value,
        "employee": employee_id,
        "start_day": start_day.isoformat(),
        "end_day": end_day.isoformat(),
        "attack_count": len(sequence),
        "attack_sequence": [attack_type.value for attack_type in sequence],
        "estimated_duration": expected_duration,
        "description": description,
        "attack_spacing": list(spacing),
        "attack_confidence": attack_confidence,
    }
    return CampaignPlan(
        campaign_id=campaign_id,
        campaign_name=template.campaign_name,
        campaign_type=template.campaign_type,
        employee_id=employee_id,
        severity=severity,
        start_day=start_day,
        end_day=end_day,
        attack_sequence=tuple(sequence),
        attack_ids=tuple(attack_ids),
        attack_spacing=tuple(spacing),
        scheduled_attacks=tuple(scheduled),
        expected_duration=expected_duration,
        attack_confidence=attack_confidence,
        attack_count=len(sequence),
        description=description,
        metadata=metadata,
    )


def _validate_campaign_plan(
    plan: CampaignPlan,
    employee_ids: set[str],
    available_days: Sequence[date],
    enabled_types: set[AttackType],
) -> bool:
    """Validate a campaign plan before returning it to callers."""
    if plan.employee_id not in employee_ids:
        return False

    day_set = set(available_days)
    if plan.start_day not in day_set or plan.end_day not in day_set:
        return False
    if plan.end_day < plan.start_day:
        return False

    if plan.attack_count != len(plan.attack_sequence):
        return False
    if plan.attack_count != len(plan.attack_ids):
        return False
    if plan.attack_count != len(plan.scheduled_attacks):
        return False
    if plan.attack_count < 2:
        return False

    if len(plan.attack_spacing) != max(0, plan.attack_count - 1):
        return False
    if any(gap not in ALLOWED_SPACING for gap in plan.attack_spacing):
        return False

    if len(set(plan.attack_ids)) != len(plan.attack_ids):
        return False
    if len(set(plan.attack_sequence)) != len(plan.attack_sequence):
        return False

    if any(attack_type not in enabled_types for attack_type in plan.attack_sequence):
        return False

    previous_day: date | None = None
    for index, stage in enumerate(plan.scheduled_attacks):
        if stage.day not in day_set:
            return False
        if stage.attack_type != plan.attack_sequence[index]:
            return False
        if stage.attack_id != plan.attack_ids[index]:
            return False
        if stage.stage_index != index:
            return False
        if previous_day is not None and stage.day < previous_day:
            return False
        previous_day = stage.day

    if plan.expected_duration != (plan.end_day - plan.start_day).days + 1:
        return False
    if not (MIN_ATTACK_CONFIDENCE <= plan.attack_confidence <= MAX_ATTACK_CONFIDENCE):
        return False

    low, high = SEVERITY_ATTACK_COUNTS[plan.severity]
    if not (low <= plan.attack_count <= high):
        if plan.attack_count < 2:
            return False
        if plan.severity == Severity.LOW and plan.attack_count != 2:
            return False
        if plan.severity == Severity.MEDIUM and plan.attack_count not in {2, 3}:
            return False
        if plan.severity == Severity.HIGH and plan.attack_count not in {3, 4}:
            return False
        if plan.severity == Severity.CRITICAL and plan.attack_count < 4:
            return False

    return True


__all__ = [
    "ALLOWED_SPACING",
    "CAMPAIGN_TEMPLATES",
    "CampaignEngine",
    "CampaignPlan",
    "CampaignTemplate",
    "ScheduledAttack",
    "campaign_to_attack_targets",
    "campaigns_to_attack_targets",
    "generate_campaign_id",
    "generate_campaigns",
]
