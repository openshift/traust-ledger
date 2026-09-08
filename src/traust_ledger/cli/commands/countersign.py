from __future__ import annotations

import argparse
import sys

from traust_ledger.cli import discover_layer_for_finding, local_writer
from traust_ledger.cli.auth import require_cli_auth
from traust_ledger.cli.commands._fmt import print_submit_response, utc_now_iso
from traust_ledger.cli.errors import cli_exit_service_error
from traust_ledger.cli.identity.actor import require_verified_actor
from traust_ledger.errors import ServiceError
from traust_ledger.handlers.event_handler import submit_event
from traust_ledger.models import EventEnvelope


def verdict_to_validity(verdict: str) -> str:
    if verdict == "false_positive":
        return "false_positive"
    if verdict in ("keep_open", "confirmed"):
        return "confirmed"
    raise ValueError(f"unsupported verdict for validity mapping: {verdict!r}")


def _build_event(args: argparse.Namespace) -> tuple[str, dict] | None:
    layer_id = args.layer or discover_layer_for_finding(args.finding_ref)
    if not layer_id:
        print(
            f"error: could not discover layer for finding {args.finding_ref!r}; "
            "pass --layer explicitly",
            file=sys.stderr,
        )
        return None

    event: dict = {
        "layer_id": layer_id,
        "finding_ref": args.finding_ref,
        "rationale": args.rationale,
        "recorded_at": utc_now_iso(),
    }

    if args.verdict == "severity":
        if not args.severity:
            print("error: --severity is required when verdict is severity", file=sys.stderr)
            return None
        event["severity"] = args.severity
        return "severity", event

    event["disposition"] = {"validity": verdict_to_validity(args.verdict)}
    if args.verdict == "false_positive":
        event["decision"] = "false_positive"
    else:
        event["decision"] = "keep_open"
    return "countersign", event


def cmd_countersign(args: argparse.Namespace) -> int:
    """ledger countersign <finding_ref> --verdict <verdict> --rationale <text>"""
    if require_cli_auth():
        return 1
    actor = require_verified_actor()
    if actor is None:
        return 1

    built = _build_event(args)
    if built is None:
        return 1
    kind, event = built
    envelope = EventEnvelope(kind=kind, event=event)

    writer, config = local_writer()
    try:
        result = submit_event(envelope, actor, writer, config)
    except ServiceError as exc:
        return cli_exit_service_error(exc)

    print_submit_response(result.model_dump())
    return 0
