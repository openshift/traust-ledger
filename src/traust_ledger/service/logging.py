from __future__ import annotations

import logging


def configure_logging(level: str) -> None:
    resolved = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=resolved,
        format="%(asctime)s level=%(levelname)s logger=%(name)s msg=%(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        force=True,
    )
