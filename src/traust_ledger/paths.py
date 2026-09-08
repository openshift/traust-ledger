from __future__ import annotations

import re
from pathlib import Path

from traust_ledger.constants import LAYER_FILE_SUFFIX, LAYER_ID_PATTERN
from traust_ledger.service.errors import InvalidLayerIdError


def layer_file_path(data_dir: str, layer_id: str) -> Path:
    if not re.match(LAYER_ID_PATTERN, layer_id):
        raise ValueError(InvalidLayerIdError.message)
    return Path(data_dir) / f"{layer_id}{LAYER_FILE_SUFFIX}"
