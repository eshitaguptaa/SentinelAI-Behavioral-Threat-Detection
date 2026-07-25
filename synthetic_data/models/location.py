"""Location domain model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Location:
    """Physical or logical place associated with employees and sessions.

    Attributes:
        location_id: Stable unique identifier for the location.
        city: City name.
        country: Country name or ISO country code.
        latitude: Geographic latitude in decimal degrees.
        longitude: Geographic longitude in decimal degrees.
        timezone: IANA timezone name (for example: Asia/Kolkata).
    """

    location_id: str
    city: str
    country: str
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = "UTC"
