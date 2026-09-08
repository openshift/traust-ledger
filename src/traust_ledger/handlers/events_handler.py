"""Raw layer event log read model."""

from __future__ import annotations

from traust_ledger._internal.backends import Backend
from traust_ledger._internal.backends.constants import LAYER_EVENTS_KEY
from traust_ledger.config import ServiceConfig
from traust_ledger.handlers.layer_handler import load_layer
from traust_ledger.models import EventsResponse
from traust_ledger.service.errors import LayerNotFoundError


def _event_source_type(event: dict) -> str | None:
    source = event.get("source")
    if isinstance(source, dict):
        value = source.get("type")
        return value if isinstance(value, str) else None
    return None


def _filter_events(
    events: list[object],
    *,
    finding_ref: str | None,
    source_type: str | None,
) -> list[dict[str, object]]:
    filtered: list[dict[str, object]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        if finding_ref is not None and event.get("finding_ref") != finding_ref:
            continue
        if source_type is not None and _event_source_type(event) != source_type:
            continue
        filtered.append(event)
    return filtered


def query_layer_events(
    layer_id: str,
    backend: Backend,
    config: ServiceConfig,
    *,
    finding_ref: str | None = None,
    source_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> EventsResponse:
    """Return filtered, paginated raw events for a layer."""
    layer = load_layer(layer_id, backend, config)
    raw_events = layer.get(LAYER_EVENTS_KEY)
    if not isinstance(raw_events, list):
        raise LayerNotFoundError(layer_id=layer_id)
    events_list = raw_events

    filtered = _filter_events(
        events_list,
        finding_ref=finding_ref,
        source_type=source_type,
    )
    total = len(filtered)
    page = filtered[offset : offset + limit]

    return EventsResponse(events=page, total=total, layer_id=layer_id)
