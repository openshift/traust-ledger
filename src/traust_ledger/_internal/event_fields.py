from __future__ import annotations

from traust_ledger.constants import (
    EVENT_KEY_ACTOR,
    EVENT_KEY_DISPOSITION,
    EVENT_KEY_SOURCE,
)


def event_text(event: dict[str, object], key: str, default: str = "") -> str:
    value = event.get(key)
    if value is None:
        return default
    return str(value)


def client_actor(event: dict[str, object]) -> dict[str, object]:
    raw = event.get(EVENT_KEY_ACTOR)
    if isinstance(raw, dict):
        return raw
    source = event.get(EVENT_KEY_SOURCE)
    if isinstance(source, dict):
        actor = source.get(EVENT_KEY_ACTOR)
        if isinstance(actor, dict):
            return actor
    return {}


def client_disposition(event: dict[str, object]) -> dict[str, object]:
    raw = event.get(EVENT_KEY_DISPOSITION)
    if isinstance(raw, dict):
        return raw
    return {}
