"""Vocabulary and sequence builder for behavioural Transformer training."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from synthetic_data.behavioural_transformer.config import TransformerConfig
from synthetic_data.behavioural_transformer.schema import EncodedBatch, SessionSequence
from synthetic_data.generators.event_catalog import ALL_EVENT_TYPES

logger = logging.getLogger(__name__)


@dataclass
class EventVocabulary:
    """Maps event-type strings ↔ integer ids with PAD/UNK/MASK specials."""

    token_to_id: dict[str, int] = field(default_factory=dict)
    id_to_token: dict[int, str] = field(default_factory=dict)
    pad_token: str = "<PAD>"
    unk_token: str = "<UNK>"
    mask_token: str = "<MASK>"

    def __post_init__(self) -> None:
        if not self.token_to_id:
            for special in (self.pad_token, self.unk_token, self.mask_token):
                self._add(special)
            for event_type in ALL_EVENT_TYPES:
                self._add(event_type)

    def _add(self, token: str) -> int:
        if token in self.token_to_id:
            return self.token_to_id[token]
        index = len(self.token_to_id)
        self.token_to_id[token] = index
        self.id_to_token[index] = token
        return index

    @property
    def pad_id(self) -> int:
        return self.token_to_id[self.pad_token]

    @property
    def unk_id(self) -> int:
        return self.token_to_id[self.unk_token]

    @property
    def size(self) -> int:
        return len(self.token_to_id)

    def encode_token(self, token: str) -> int:
        return self.token_to_id.get(token, self.unk_id)

    def decode_token(self, token_id: int) -> str:
        return self.id_to_token.get(int(token_id), self.unk_token)

    def encode_sequence(self, event_types: Sequence[str]) -> list[int]:
        return [self.encode_token(token) for token in event_types]

    def fit_extra(self, tokens: Iterable[str]) -> None:
        """Add unseen tokens discovered in training data."""
        for token in tokens:
            if token and token not in self.token_to_id:
                self._add(str(token))

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_to_id": dict(self.token_to_id),
            "pad_token": self.pad_token,
            "unk_token": self.unk_token,
            "mask_token": self.mask_token,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EventVocabulary:
        token_to_id = {str(k): int(v) for k, v in dict(payload["token_to_id"]).items()}
        id_to_token = {int(v): str(k) for k, v in token_to_id.items()}
        return cls(
            token_to_id=token_to_id,
            id_to_token=id_to_token,
            pad_token=str(payload.get("pad_token", "<PAD>")),
            unk_token=str(payload.get("unk_token", "<UNK>")),
            mask_token=str(payload.get("mask_token", "<MASK>")),
        )

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path) -> EventVocabulary:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)


class SequenceBuilder:
    """Groups raw events into ordered session sequences and encodes them."""

    def __init__(
        self,
        *,
        config: TransformerConfig | None = None,
        vocabulary: EventVocabulary | None = None,
    ) -> None:
        self.config = config or TransformerConfig()
        self.vocabulary = vocabulary or EventVocabulary(
            pad_token=self.config.pad_token,
            unk_token=self.config.unk_token,
            mask_token=self.config.mask_token,
        )

    def events_to_sessions(
        self,
        events: Sequence[Any],
        *,
        group_by_session: bool = True,
    ) -> list[SessionSequence]:
        """Convert timeline-like events into ``SessionSequence`` objects.

        Accepts objects with ``employee_id``, ``event_type``, ``timestamp``,
        ``session_id`` attributes (or mapping keys of the same names).
        """
        buckets: dict[tuple[str, str], list[Any]] = defaultdict(list)
        for event in events:
            employee_id = str(_attr(event, "employee_id", ""))
            session_id = str(_attr(event, "session_id", "") or "SESSION")
            if not group_by_session:
                day = _day_key(_attr(event, "timestamp", None))
                session_id = f"{employee_id}::{day}"
            if not employee_id:
                continue
            buckets[(employee_id, session_id)].append(event)

        sequences: list[SessionSequence] = []
        for (employee_id, session_id), group in buckets.items():
            group.sort(key=lambda item: (_timestamp(item), str(_attr(item, "event_id", ""))))
            event_types = [str(_attr(item, "event_type", self.config.unk_token)) for item in group]
            timestamps = [_iso(_attr(item, "timestamp", None)) for item in group]
            day = _day_key(_attr(group[0], "timestamp", None)) if group else "1970-01-01"
            if not event_types:
                continue
            sequences.append(
                SessionSequence(
                    employee_id=employee_id,
                    session_id=session_id,
                    simulation_day=day,
                    event_types=event_types,
                    timestamps=timestamps,
                )
            )
        sequences.sort(key=lambda seq: (seq.simulation_day, seq.employee_id, seq.session_id))
        logger.info("Built %s session sequences from %s events", len(sequences), len(events))
        return sequences

    def fit_vocabulary(self, sequences: Sequence[SessionSequence]) -> EventVocabulary:
        """Extend vocabulary with any tokens present in the corpus."""
        tokens: list[str] = []
        for sequence in sequences:
            tokens.extend(sequence.event_types)
        self.vocabulary.fit_extra(tokens)
        return self.vocabulary

    def encode(
        self,
        sequences: Sequence[SessionSequence],
        *,
        max_seq_len: int | None = None,
    ) -> EncodedBatch:
        """Pad/truncate sequences to integer ids + attention masks."""
        limit = max_seq_len or self.config.max_seq_len
        token_ids: list[list[int]] = []
        attention_mask: list[list[int]] = []
        lengths: list[int] = []
        identities: list[tuple[str, str, str]] = []

        for sequence in sequences:
            encoded = self.vocabulary.encode_sequence(sequence.event_types)
            if len(encoded) > limit:
                encoded = encoded[:limit]
            length = len(encoded)
            pad_len = limit - length
            padded = encoded + [self.vocabulary.pad_id] * pad_len
            mask = [1] * length + [0] * pad_len
            token_ids.append(padded)
            attention_mask.append(mask)
            lengths.append(length)
            identities.append(
                (sequence.employee_id, sequence.session_id, sequence.simulation_day)
            )

        return EncodedBatch(
            token_ids=token_ids,
            attention_mask=attention_mask,
            lengths=lengths,
            identities=identities,
        )

    def sequences_from_event_type_lists(
        self,
        rows: Sequence[Mapping[str, Any]],
    ) -> list[SessionSequence]:
        """Build sessions from lightweight dict rows with ``event_types`` lists."""
        sequences: list[SessionSequence] = []
        for row in rows:
            event_types = [str(item) for item in list(row.get("event_types") or [])]
            if not event_types:
                continue
            sequences.append(
                SessionSequence(
                    employee_id=str(row.get("employee_id", "UNKNOWN")),
                    session_id=str(row.get("session_id", "SESS-UNKNOWN")),
                    simulation_day=str(row.get("simulation_day", "1970-01-01")),
                    event_types=event_types,
                    timestamps=[str(t) for t in list(row.get("timestamps") or [])],
                    metadata=dict(row.get("metadata") or {}),
                )
            )
        return sequences


def synthesize_sequence_from_features(
    *,
    employee_id: str,
    simulation_day: str,
    features: Mapping[str, float],
    max_len: int = 32,
) -> SessionSequence:
    """Build a pseudo-session from day-level feature counts.

    Used when the API receives a FeatureVector without an explicit sequence so
    the Transformer path remains usable for the existing dashboard contract.
    """
    events: list[str] = ["DEVICE_CONNECT", "LOGIN"]
    login_count = int(max(0, features.get("login_count", 1)))
    failed = int(max(0, features.get("auth_failure_count", 0)))
    file_ops = int(max(0, features.get("file_access_count", 0)))
    app_ops = int(max(0, features.get("application_access_count", 0)))
    vpn = int(max(0, features.get("vpn_session_count", 0)))

    for _ in range(min(failed, 6)):
        events.append("FAILED_LOGIN")
    if vpn > 0:
        events.append("VPN_CONNECT")
    for _ in range(min(max(login_count - 1, 0), 2)):
        events.append("LOGIN")
    for _ in range(min(app_ops, 8)):
        events.append("APPLICATION_ACCESS")
    for _ in range(min(file_ops, 8)):
        events.append("FILE_READ" if file_ops % 2 == 0 else "FILE_DOWNLOAD")
    if features.get("unique_location_count", 0) >= 3:
        events.extend(["SSH_LOGIN", "REMOTE_DESKTOP"])
    if features.get("usb_event_count", 0) > 0 or features.get("sensitive_resource_access_count", 0) > 4:
        events.append("USB_INSERT")
    if vpn > 0:
        events.append("VPN_DISCONNECT")
    events.append("LOGOUT")
    events.append("DEVICE_DISCONNECT")
    if len(events) > max_len:
        events = events[: max_len - 1] + ["LOGOUT"]

    return SessionSequence(
        employee_id=employee_id,
        session_id=f"SYNTH::{employee_id}::{simulation_day}",
        simulation_day=simulation_day,
        event_types=events,
        metadata={"synthetic_from_features": True},
    )


def _attr(obj: Any, name: str, default: Any) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _timestamp(obj: Any) -> datetime:
    value = _attr(obj, "timestamp", None)
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.min
    return datetime.min


def _day_key(value: Any) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, str) and len(value) >= 10:
        return value[:10]
    return "1970-01-01"


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        return ""
    return str(value)
