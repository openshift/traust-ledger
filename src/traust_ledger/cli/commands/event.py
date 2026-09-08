from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust_ledger.cli import local_writer
from traust_ledger.cli.auth import require_cli_auth
from traust_ledger.cli.commands._fmt import print_submit_response
from traust_ledger.cli.errors import cli_exit_service_error
from traust_ledger.cli.identity.actor import require_verified_actor
from traust_ledger.errors import ServiceError
from traust_ledger.handlers.event_handler import submit_event
from traust_ledger.models import EventEnvelope


def cmd_event(args: argparse.Namespace) -> int:
    """ledger event <file> --kind <kind> — submit a raw event."""
    if require_cli_auth():
        return 1
    actor = require_verified_actor()
    if actor is None:
        return 1

    path = Path(args.file_path)
    try:
        event_data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read event: {exc}", file=sys.stderr)
        return 1

    if not isinstance(event_data, dict):
        print("error: event must be a JSON object", file=sys.stderr)
        return 1

    envelope = EventEnvelope(kind=args.kind, event=event_data)
    writer, config = local_writer()
    try:
        result = submit_event(envelope, actor, writer, config)
    except ServiceError as exc:
        return cli_exit_service_error(exc)

    print_submit_response(result.model_dump())
    return 0
