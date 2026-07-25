"""Final status derivation for SentinelAI (post Risk + Attack Classification).

Public API::

    from synthetic_data.decision_status import derive_final_status, FinalStatus
"""

from synthetic_data.decision_status.derive import derive_final_status
from synthetic_data.decision_status.schema import (
    FinalStatus,
    VALID_FINAL_STATUSES,
    is_signature_attack,
)

__all__ = [
    "FinalStatus",
    "VALID_FINAL_STATUSES",
    "derive_final_status",
    "is_signature_attack",
]
