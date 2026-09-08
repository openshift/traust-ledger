"""ledger status — check local backend health."""

from __future__ import annotations

import argparse
import json
import sys


def cmd_status(args: argparse.Namespace) -> int:
    from traust_ledger.cli import backend_from_env

    try:
        backend, data_dir = backend_from_env()
        ids = backend.list_layer_ids()
        print(
            json.dumps(
                {
                    "status": "healthy",
                    "mode": "local",
                    "data_dir": data_dir,
                    "layers": len(ids),
                },
                indent=2,
            )
        )
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
