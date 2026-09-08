"""Internal write-path errors — plain exceptions, no HTTP awareness."""

from __future__ import annotations


class EventIdMismatchError(ValueError):
    """Supplied event_id does not match the canonical computation."""

    def __init__(self, supplied: str, canonical: str) -> None:
        self.supplied = supplied
        self.canonical = canonical
        super().__init__(f"event_id mismatch: supplied '{supplied}' != canonical '{canonical}'")


class IdentityUnverifiedError(ValueError):
    """Human false_positive requires a verified identity."""

    def __init__(self) -> None:
        super().__init__("verified identity required for human false_positive")
