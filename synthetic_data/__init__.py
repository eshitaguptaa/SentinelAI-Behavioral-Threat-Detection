"""SentinelAI synthetic data package.

Provides reusable domain models, enterprise-structure generators,
behavior profiles, timeline simulation, and the Attack Injection Engine.
"""

from .attack_config import DEFAULT_ATTACK_CONFIG, AttackConfig
from .attack_injector import AttackInjector, inject_attacks
from .attack_types import (
    AttackInjectionResult,
    AttackInjectionSummary,
    AttackRecord,
    AttackTarget,
    AttackType,
    Severity,
)
from .generators import (
    SimulationResult,
    TimelineEvent,
    generate_behavior_profiles,
    generate_enterprise,
    generate_workday_timelines,
    generate_workday_timelines_with_sessions,
    simulate_enterprise_timeline,
)
from .models import (
    Attack,
    BehaviorProfile,
    Department,
    Device,
    Employee,
    Enterprise,
    Event,
    Location,
    Resource,
    Session,
)

__all__ = [
    "Attack",
    "AttackConfig",
    "AttackInjectionResult",
    "AttackInjectionSummary",
    "AttackInjector",
    "AttackRecord",
    "AttackTarget",
    "AttackType",
    "BehaviorProfile",
    "DEFAULT_ATTACK_CONFIG",
    "Department",
    "Device",
    "Employee",
    "Enterprise",
    "Event",
    "Location",
    "Resource",
    "Session",
    "Severity",
    "SimulationResult",
    "TimelineEvent",
    "generate_behavior_profiles",
    "generate_enterprise",
    "generate_workday_timelines",
    "generate_workday_timelines_with_sessions",
    "inject_attacks",
    "simulate_enterprise_timeline",
]
