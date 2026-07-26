"""Kill-chain campaign correlation for SentinelAI SOC cases."""

from synthetic_data.campaign_correlation.correlate import (
    ScoredSession,
    correlate_campaigns,
    find_focus_case,
    sessions_from_predict_payloads,
)
from synthetic_data.campaign_correlation.schema import CampaignCase, CampaignStage

__all__ = [
    "CampaignCase",
    "CampaignStage",
    "ScoredSession",
    "correlate_campaigns",
    "find_focus_case",
    "sessions_from_predict_payloads",
]
