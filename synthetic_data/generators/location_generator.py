"""Office location generator."""

from __future__ import annotations

from synthetic_data.config import NUMBER_OF_LOCATIONS, OFFICE_LOCATION_DEFINITIONS
from synthetic_data.models import Location


def _location_id(city: str) -> str:
    """Build a stable location identifier from the city name."""
    slug = city.upper().replace(" ", "_")
    return f"LOC-{slug}"


def generate_locations(
    count: int | None = None,
    definitions: list[tuple[str, str, float, float, str]] | None = None,
) -> list[Location]:
    """Create office locations from the configured catalog.

    Args:
        count: Number of locations to generate. Defaults to
            ``config.NUMBER_OF_LOCATIONS``. Never inferred from hardcoded
            employee counts.
        definitions: Optional catalog of
            ``(city, country, latitude, longitude, timezone)`` tuples.

    Returns:
        Location entities (first ``count`` entries from the catalog).

    Raises:
        ValueError: If ``count`` is non-positive or exceeds the catalog size.
    """
    source = (
        definitions if definitions is not None else list(OFFICE_LOCATION_DEFINITIONS)
    )
    n = NUMBER_OF_LOCATIONS if count is None else count

    if n <= 0:
        raise ValueError("count must be a positive integer")
    if n > len(source):
        raise ValueError(
            f"Requested {n} locations but only {len(source)} are defined in config"
        )

    locations: list[Location] = []
    for city, country, latitude, longitude, timezone in source[:n]:
        locations.append(
            Location(
                location_id=_location_id(city),
                city=city,
                country=country,
                latitude=latitude,
                longitude=longitude,
                timezone=timezone,
            )
        )
    return locations
