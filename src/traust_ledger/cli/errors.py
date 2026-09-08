"""Shared CLI error reporting."""

from __future__ import annotations

import sys

from traust_ledger.errors import ServiceError


def cli_exit_service_error(exc: ServiceError) -> int:
    """Print a domain error and exit non-zero.

    Previously typed as `fastapi.HTTPException`, which pulled the whole web
    framework onto the CLI import path: `import traust_ledger.cli.commands` failed
    with ModuleNotFoundError on any install without the `service` extra, even
    though no CLI command needs a web server. The annotation also described an
    exception that could not occur — `submit_event` and its siblings raise
    `ServiceError` subclasses, which carry the same `.detail` this function reads.
    """
    print(f"error: {exc.detail}", file=sys.stderr)
    return 1
