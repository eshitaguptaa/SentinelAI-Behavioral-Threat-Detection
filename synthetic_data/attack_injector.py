"""Attack Injection Engine orchestrator.

Loads (or accepts) timeline events, selects attack targets, dispatches to
per-technique injectors, and returns a consistent timeline plus records.

Technique implementations live under ``synthetic_data.attacks`` and are
registered automatically. Orchestration behaviour is unchanged.
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from synthetic_data.attack_config import DEFAULT_ATTACK_CONFIG, AttackConfig
from synthetic_data.attack_types import (
    AttackInjectionResult,
    AttackInjectionSummary,
    AttackRecord,
    AttackTarget,
    AttackType,
)
from synthetic_data.attack_utils import (
    choose_attack_targets,
    eligible_employee_ids,
    ensure_timeline_consistency,
    generate_attack_id,
    load_events_from_csv,
)
from synthetic_data.attacks import get_default_injectors
from synthetic_data.attacks.impossible_travel import inject as _fallback_inject
from synthetic_data.generators.event_factory import TimelineEvent
from synthetic_data.models import BehaviorProfile, Employee


class AttackTechniqueInjector(Protocol):
    """Callable contract for a single attack-technique implementation."""

    def __call__(
        self,
        events: list[TimelineEvent],
        target: AttackTarget,
        *,
        attack_id: str,
        config: AttackConfig,
        rng: random.Random,
        employees: Mapping[str, Employee] | None = None,
        profiles: Mapping[str, BehaviorProfile] | None = None,
    ) -> tuple[list[TimelineEvent], AttackRecord | None]:
        """Apply one attack technique.

        Returns:
            A tuple of ``(updated_events, attack_record_or_none)``.
            When injection is skipped / unimplemented, return the input
            events unchanged and ``None`` for the record.
        """


@dataclass(slots=True)
class AttackInjector:
    """Orchestrates attack-target selection and technique dispatch.

    Responsibilities:
        1. Load or accept timeline events
        2. Choose attack targets from configuration
        3. Call registered technique injectors
        4. Preserve chronological timeline consistency
        5. Return modified events, attack records, and a summary
    """

    config: AttackConfig = field(default_factory=AttackConfig)
    injectors: dict[AttackType, AttackTechniqueInjector] | None = None

    def __post_init__(self) -> None:
        if self.injectors is None:
            object.__setattr__(self, "injectors", get_default_injectors())

    def register_injector(
        self,
        attack_type: AttackType,
        injector: AttackTechniqueInjector,
    ) -> None:
        """Register or replace the handler for one attack technique."""
        assert self.injectors is not None
        self.injectors[attack_type] = injector

    def load_events(
        self,
        events: Sequence[TimelineEvent] | str | Path,
    ) -> list[TimelineEvent]:
        """Load events from memory or from an ``events.csv`` path."""
        if isinstance(events, (str, Path)):
            return load_events_from_csv(events)
        return list(events)

    def inject(
        self,
        events: Sequence[TimelineEvent] | str | Path,
        *,
        employees: Sequence[Employee] | Mapping[str, Employee] | None = None,
        profiles: Mapping[str, BehaviorProfile] | None = None,
        config: AttackConfig | None = None,
    ) -> AttackInjectionResult:
        """Run the attack-injection pipeline.

        Args:
            events: In-memory timeline events or path to ``events.csv``.
            employees: Optional employee directory for future injectors.
            profiles: Optional behaviour profiles for future injectors.
            config: Optional per-run config override.

        Returns:
            ``AttackInjectionResult`` with ``modified_events``,
            ``attack_records``, and ``summary``.
        """
        effective_config = config or self.config
        rng = random.Random(effective_config.random_seed)

        loaded_events = self.load_events(events)
        working_events = ensure_timeline_consistency(loaded_events)

        employee_index = _index_employees(employees)
        profile_index = dict(profiles or {})

        targets = choose_attack_targets(working_events, effective_config, rng)

        attack_records: list[AttackRecord] = []
        planned = 0
        injected = 0
        skipped = 0
        type_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        notes: list[str] = [
            "Attack techniques applied via registered injectors; "
            "ground-truth metadata retained on injected events for evaluation.",
        ]

        assert self.injectors is not None
        for index, target in enumerate(targets, start=1):
            planned += 1
            attack_id = generate_attack_id(index)
            injector = self.injectors.get(target.attack_type, _fallback_inject)

            working_events, record = injector(
                working_events,
                target,
                attack_id=attack_id,
                config=effective_config,
                rng=rng,
                employees=employee_index,
                profiles=profile_index,
            )

            if record is None:
                skipped += 1
                continue

            attack_records.append(record)
            injected += 1
            type_key = record.attack_type.value
            severity_key = record.severity.value
            type_counts[type_key] = type_counts.get(type_key, 0) + 1
            severity_counts[severity_key] = severity_counts.get(severity_key, 0) + 1

        modified_events = ensure_timeline_consistency(working_events)

        summary = AttackInjectionSummary(
            total_input_events=len(loaded_events),
            total_output_events=len(modified_events),
            eligible_employees=len(eligible_employee_ids(loaded_events, effective_config)),
            selected_targets=len({target.employee_id for target in targets}),
            attacks_planned=planned,
            attacks_injected=injected,
            attacks_skipped=skipped,
            by_attack_type=dict(sorted(type_counts.items())),
            by_severity=dict(sorted(severity_counts.items())),
            notes=notes,
        )

        return AttackInjectionResult(
            modified_events=modified_events,
            attack_records=attack_records,
            summary=summary,
        )


def inject_attacks(
    events: Sequence[TimelineEvent] | str | Path,
    *,
    employees: Sequence[Employee] | Mapping[str, Employee] | None = None,
    profiles: Mapping[str, BehaviorProfile] | None = None,
    config: AttackConfig | None = None,
) -> AttackInjectionResult:
    """Convenience entrypoint for the Attack Injection Engine."""
    engine = AttackInjector(config=config or DEFAULT_ATTACK_CONFIG)
    return engine.inject(
        events,
        employees=employees,
        profiles=profiles,
        config=config,
    )


def _index_employees(
    employees: Sequence[Employee] | Mapping[str, Employee] | None,
) -> dict[str, Employee]:
    """Normalize employee inputs to an ``employee_id -> Employee`` map."""
    if employees is None:
        return {}
    if isinstance(employees, Mapping):
        return dict(employees)
    return {employee.employee_id: employee for employee in employees}
