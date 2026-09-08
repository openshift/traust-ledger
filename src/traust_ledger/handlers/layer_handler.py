from __future__ import annotations

import logging

from traust_ledger._internal.backends import Backend
from traust_ledger._internal.backends.constants import LAYER_EVENTS_KEY
from traust_ledger.config import ServiceConfig
from traust_ledger.paths import layer_file_path
from traust_ledger.service.errors import LayerNotFoundError

logger = logging.getLogger(__name__)


def load_layer(layer_id: str, backend: Backend, config: ServiceConfig) -> dict[str, object]:
    path = layer_file_path(config.data_dir, layer_id)
    layer = backend.load(path)
    events = layer.get(LAYER_EVENTS_KEY)
    # A layer holding ONLY queued statements exists. Keying existence on events
    # alone made a quarantine invisible: a submission whose findings were all
    # withheld as `needs_identity` returned 200 accepted and then 404 on read,
    # so the one thing the submitter needed to see — that nothing was recorded
    # and why — was the thing they could not fetch.
    if not events and not layer.get("needs_review"):
        logger.warning("layer not found layer_id=%s", layer_id)
        raise LayerNotFoundError(layer_id=layer_id)
    event_count = len(events) if isinstance(events, list) else 0
    logger.debug("layer loaded layer_id=%s event_count=%d", layer_id, event_count)
    return layer
