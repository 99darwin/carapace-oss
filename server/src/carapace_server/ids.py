"""Client-chosen identifiers that appear inside owner-signed objects."""

from __future__ import annotations

import uuid


def parse_canonical_uuid(value: str) -> uuid.UUID:
    """Parse a UUID that is already in canonical form (lowercase, hyphenated).

    Signed objects carry ids as strings and the server stores them as UUIDs.
    Accepting ``{...}``, upper case or unhyphenated spellings would make the
    stored form differ from the signed one, so only ``str(uuid)`` round trips
    are allowed.

    Raises:
        ValueError: If ``value`` is not a canonical UUID string.
    """
    parsed = uuid.UUID(value)
    if str(parsed) != value:
        raise ValueError("id must be a lowercase hyphenated UUID")
    return parsed
