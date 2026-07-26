"""Schemas for kill-chain campaign correlation (SOC case reconstruction)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CampaignStage:
    """One scored session inside a reconstructed campaign case."""

    stage_index: int
    stage_label: str
    employee_id: str
    simulation_day: str
    attack_type: str
    attack_confidence: float
    risk_score: float
    risk_level: str
    status: str
    matched_signals: list[str] = field(default_factory=list)
    contributing_factors: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    mitre: dict[str, Any] | None = None
    is_focus: bool = False
    result_index: int | None = None


@dataclass(slots=True)
class CampaignCase:
    """Correlated multi-stage attack case for analyst investigation."""

    case_id: str
    campaign_name: str
    campaign_type: str
    correlation_basis: str
    summary: str
    entity_ids: list[str]
    stage_count: int
    peak_risk_score: float
    peak_risk_level: str
    status: str
    stages: list[CampaignStage]
    campaign_id: str | None = None
    focus_stage_index: int | None = None
