from __future__ import annotations

ROUTE_EVENTS = "/v1/ledger/events"
ROUTE_LAYERS = "/v1/ledger/layers/{layer_id}"
ROUTE_HEALTHZ = "/healthz"

STATUS_HEALTHY = "healthy"

__all__ = [
    "ROUTE_EVENTS",
    "ROUTE_HEALTHZ",
    "ROUTE_LAYERS",
    "STATUS_HEALTHY",
]
