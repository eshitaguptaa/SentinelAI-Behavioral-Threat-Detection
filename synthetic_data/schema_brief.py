"""Hackathon-aligned access-log schema mapping.

Maps SentinelAI ``TimelineEvent`` fields onto the suggested synthetic schema:

| Brief field           | SentinelAI source                                      |
|-----------------------|--------------------------------------------------------|
| entity_id             | employee_id (users / service accounts / edge devices)  |
| entity_type           | metadata.entity_type                                   |
| timestamp             | timestamp                                              |
| source_ip             | metadata.source_ip                                     |
| geo_location          | location_id / metadata.geo_location                    |
| resource_accessed     | resource_id / event_type                               |
| auth_method           | metadata.auth_method / authentication_type             |
| session_duration      | derived per session (seconds)                          |
| command_sequence      | metadata.command_sequence (ordered actions)            |
| device_fingerprint    | metadata.device_fingerprint (OS|MAC|browser composite) |
| label                 | normal / anomaly_type (eval only; hidden at inference) |
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from synthetic_data.generators.event_factory import TimelineEvent

ENTITY_TYPES: Final[tuple[str, ...]] = (
    "user",
    "service_account",
    "edge_device",
)

AUTH_METHODS: Final[tuple[str, ...]] = (
    "password",
    "token",
    "certificate",
    "biometric",
    "mfa",
    "sso",
)


@dataclass(slots=True)
class AccessLogRecord:
    """One row of the hackathon-suggested synthetic access-log schema."""

    entity_id: str
    entity_type: str
    timestamp: datetime
    source_ip: str
    geo_location: str
    resource_accessed: str
    auth_method: str
    session_duration: float
    command_sequence: str
    device_fingerprint: str
    label: str


def derive_entity_type(employee_id: str, *, event_type: str = "") -> str:
    """Deterministic entity-type assignment spanning the brief taxonomy."""
    upper_event = (event_type or "").upper()
    if any(token in upper_event for token in ("DEVICE_CONNECT", "USB_", "EDGE")):
        digest = int(hashlib.sha1(employee_id.encode("utf-8")).hexdigest()[:6], 16)
        if digest % 5 == 0:
            return "edge_device"
    digest = int(hashlib.sha1(f"entity:{employee_id}".encode("utf-8")).hexdigest()[:6], 16)
    if digest % 10 == 0:
        return "service_account"
    return "user"


def derive_auth_method(metadata: dict[str, Any] | None, *, event_type: str = "") -> str:
    """Map authentication cues onto brief auth_method values."""
    meta = metadata or {}
    raw = str(
        meta.get("auth_method")
        or meta.get("authentication_type")
        or ""
    ).strip().lower()
    if "cert" in raw:
        return "certificate"
    if "bio" in raw:
        return "biometric"
    if "mfa" in raw or "totp" in raw:
        return "mfa"
    if "token" in raw or "oauth" in raw or "bearer" in raw:
        return "token"
    if "sso" in raw or "saml" in raw:
        return "sso"
    if "password" in raw or "ntlm" in raw or "login" in (event_type or "").lower():
        return "password"
    if raw in AUTH_METHODS:
        return raw
    return "password"


def derive_device_fingerprint(event: TimelineEvent) -> str:
    """Build a stable fingerprint from device / OS / browser / MAC-like id."""
    meta = event.metadata or {}
    existing = str(meta.get("device_fingerprint") or "").strip()
    if existing:
        return existing
    parts = [
        event.device_id or "unknown-device",
        event.operating_system or "unknown-os",
        event.browser or "unknown-browser",
        str(meta.get("mac_address") or meta.get("attacker_device") or ""),
    ]
    return "|".join(parts)


def derive_command_sequence(event: TimelineEvent) -> list[str]:
    """Ordered privileged-action tokens for the event."""
    meta = event.metadata or {}
    existing = meta.get("command_sequence")
    if isinstance(existing, list) and existing:
        return [str(item) for item in existing]
    if isinstance(existing, str) and existing.strip():
        return [part.strip() for part in existing.split("|") if part.strip()]
    stage = str(meta.get("attack_stage_label") or "").strip()
    if stage:
        return [stage]
    return [event.event_type]


def enrich_event_metadata(event: TimelineEvent) -> TimelineEvent:
    """Ensure brief schema keys exist on ``event.metadata`` (in place)."""
    meta = dict(event.metadata or {})
    meta.setdefault(
        "entity_type",
        derive_entity_type(event.employee_id, event_type=event.event_type),
    )
    meta.setdefault("entity_id", event.employee_id)
    meta.setdefault(
        "auth_method",
        derive_auth_method(meta, event_type=event.event_type),
    )
    meta.setdefault("device_fingerprint", derive_device_fingerprint(event))
    if "command_sequence" not in meta:
        meta["command_sequence"] = derive_command_sequence(event)
    if "source_ip" not in meta:
        # Stable synthetic IP from entity + device for schema completeness.
        digest = hashlib.sha1(
            f"{event.employee_id}:{event.device_id}".encode("utf-8")
        ).hexdigest()
        meta["source_ip"] = (
            f"10.{int(digest[0:2], 16) % 250}."
            f"{int(digest[2:4], 16) % 250}."
            f"{1 + int(digest[4:6], 16) % 254}"
        )
    meta.setdefault("geo_location", event.location_id)
    event.metadata = meta
    return event


def enrich_timeline(events: Sequence[TimelineEvent]) -> list[TimelineEvent]:
    """Enrich every event with brief-schema metadata keys."""
    return [enrich_event_metadata(event) for event in events]


def _session_durations(events: Sequence[TimelineEvent]) -> dict[str, float]:
    """Map session_id → duration seconds (first→last timestamp)."""
    bounds: dict[str, list[datetime]] = {}
    for event in events:
        bounds.setdefault(event.session_id, []).append(event.timestamp)
    durations: dict[str, float] = {}
    for session_id, stamps in bounds.items():
        if len(stamps) < 2:
            durations[session_id] = 0.0
        else:
            durations[session_id] = max(
                0.0, (max(stamps) - min(stamps)).total_seconds()
            )
    return durations


def _label_for_event(event: TimelineEvent) -> str:
    meta = event.metadata or {}
    if meta.get("is_attack") or meta.get("attack_type"):
        return str(meta.get("attack_type") or "anomaly")
    if meta.get("edge_case") or meta.get("insider_drift"):
        return "INSIDER_DRIFT"
    return "normal"


def to_access_log_records(events: Sequence[TimelineEvent]) -> list[AccessLogRecord]:
    """Convert enriched timeline events into brief-schema rows."""
    enriched = enrich_timeline(list(events))
    durations = _session_durations(enriched)
    rows: list[AccessLogRecord] = []
    for event in enriched:
        meta = event.metadata or {}
        sequence = derive_command_sequence(event)
        rows.append(
            AccessLogRecord(
                entity_id=str(meta.get("entity_id") or event.employee_id),
                entity_type=str(meta.get("entity_type") or "user"),
                timestamp=event.timestamp,
                source_ip=str(meta.get("source_ip") or ""),
                geo_location=str(
                    meta.get("geo_location") or event.location_id or ""
                ),
                resource_accessed=str(
                    event.resource_id or event.event_type or ""
                ),
                auth_method=str(meta.get("auth_method") or "password"),
                session_duration=float(durations.get(event.session_id, 0.0)),
                command_sequence="|".join(sequence),
                device_fingerprint=str(
                    meta.get("device_fingerprint")
                    or derive_device_fingerprint(event)
                ),
                label=_label_for_event(event),
            )
        )
    return rows


def export_access_logs_csv(events: Sequence[TimelineEvent], path: Any) -> Any:
    """Write brief-schema ``access_logs.csv`` for hackathon documentation."""
    import csv
    from pathlib import Path

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = to_access_log_records(events)
    fieldnames = [
        "entity_id",
        "entity_type",
        "timestamp",
        "source_ip",
        "geo_location",
        "resource_accessed",
        "auth_method",
        "session_duration",
        "command_sequence",
        "device_fingerprint",
        "label",
    ]
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "entity_id": row.entity_id,
                    "entity_type": row.entity_type,
                    "timestamp": row.timestamp.isoformat(sep=" "),
                    "source_ip": row.source_ip,
                    "geo_location": row.geo_location,
                    "resource_accessed": row.resource_accessed,
                    "auth_method": row.auth_method,
                    "session_duration": f"{row.session_duration:.1f}",
                    "command_sequence": row.command_sequence,
                    "device_fingerprint": row.device_fingerprint,
                    "label": row.label,
                }
            )
    return out
