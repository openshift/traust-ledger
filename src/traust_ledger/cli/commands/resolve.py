"""ledger resolve — close needs_review items."""

from __future__ import annotations

import argparse
import json

from traust_ledger.cli import local_writer
from traust_ledger.cli.auth import require_cli_auth
from traust_ledger.cli.errors import cli_exit_service_error
from traust_ledger.cli.identity.actor import require_verified_actor
from traust_ledger.errors import ServiceError
from traust_ledger.handlers.resolve_handler import parse_review_item_key, resolve_review_item


def cmd_resolve(args: argparse.Namespace) -> int:
    if require_cli_auth():
        return 1
    actor = require_verified_actor()
    if actor is None:
        return 1

    try:
        parse_review_item_key(args.key)
    except ServiceError as exc:
        return cli_exit_service_error(exc)

    writer, config = local_writer()
    try:
        result = resolve_review_item(
            args.layer_id,
            args.key,
            args.decision,
            args.note or "",
            writer,
            config,
        )
    except ServiceError as exc:
        return cli_exit_service_error(exc)

    print(json.dumps(result, indent=2))
    return 0


def register_resolve_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("resolve", help="Resolve a needs_review item")
    p.add_argument("layer_id", help="Layer ID containing the item")
    p.add_argument("--key", required=True, help="Review item key (JSON array)")
    p.add_argument("--decision", required=True, choices=["confirmed", "rejected"])
    p.add_argument("--note", help="Optional note (required for rejected)")
    p.set_defaults(handler=cmd_resolve)
