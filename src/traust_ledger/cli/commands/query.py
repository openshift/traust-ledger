"""ledger query — read operations against layers, findings, events."""

from __future__ import annotations

import argparse
import json

from traust_ledger.cli.auth import require_cli_auth
from traust_ledger.cli.errors import cli_exit_service_error
from traust_ledger.errors import ServiceError


def cmd_query_layers(args: argparse.Namespace) -> int:
    if require_cli_auth():
        return 1
    from traust_ledger.cli import backend_from_env

    backend, _data_dir = backend_from_env()
    ids = backend.list_layer_ids()
    if args.as_json:
        print(json.dumps(ids, indent=2))
    else:
        for layer_id in ids:
            print(layer_id)
    return 0


def cmd_query_layer(args: argparse.Namespace) -> int:
    if require_cli_auth():
        return 1
    from traust_ledger.cli import backend_from_env, config_from_env
    from traust_ledger.handlers.layer_handler import load_layer

    backend, data_dir = backend_from_env()
    config = config_from_env(data_dir)
    try:
        result = load_layer(args.layer_id, backend, config)
    except ServiceError as exc:
        return cli_exit_service_error(exc)
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_query_findings(args: argparse.Namespace) -> int:
    if require_cli_auth():
        return 1
    if getattr(args, "bulk", False):
        return _query_findings_bulk(args)
    if not args.layer_id:
        print("error: layer_id required (or use --all)")
        return 1

    from traust_ledger.cli import backend_from_env, config_from_env
    from traust_ledger.handlers.findings_handler import resolve_findings

    backend, data_dir = backend_from_env()
    config = config_from_env(data_dir)
    try:
        result = resolve_findings(args.layer_id, backend, config)
    except ServiceError as exc:
        return cli_exit_service_error(exc)
    print(json.dumps(result.model_dump(), indent=2, default=str))
    return 0


def _query_findings_bulk(args: argparse.Namespace) -> int:
    from traust_ledger.cli import backend_from_env, config_from_env
    from traust_ledger.handlers.findings_handler import resolve_all_findings

    backend, data_dir = backend_from_env()
    config = config_from_env(data_dir)
    result = resolve_all_findings(
        backend,
        config,
        cursor=getattr(args, "cursor", None),
        limit=getattr(args, "limit", 100),
        since_epoch=getattr(args, "since_epoch", None),
    )
    print(json.dumps(result.model_dump(), indent=2, default=str))
    return 0


def cmd_query_events(args: argparse.Namespace) -> int:
    if require_cli_auth():
        return 1
    from traust_ledger.cli import backend_from_env, config_from_env
    from traust_ledger.handlers.events_handler import query_layer_events

    backend, data_dir = backend_from_env()
    config = config_from_env(data_dir)
    try:
        result = query_layer_events(
            args.layer_id,
            backend,
            config,
            finding_ref=getattr(args, "finding_ref", None),
            source_type=getattr(args, "source_type", None),
            limit=getattr(args, "limit", 100),
            offset=getattr(args, "offset", 0),
        )
    except ServiceError as exc:
        return cli_exit_service_error(exc)
    print(json.dumps(result.model_dump(), indent=2, default=str))
    return 0


def register_query_parser(subparsers: argparse._SubParsersAction) -> None:
    query_p = subparsers.add_parser("query", help="Query ledger data")
    query_sub = query_p.add_subparsers(dest="query_command", required=True)
    query_p.add_argument("--json", action="store_true", dest="as_json")

    layers_p = query_sub.add_parser("layers", help="List all layer IDs")
    layers_p.add_argument("--json", action="store_true", dest="as_json")
    layers_p.set_defaults(handler=cmd_query_layers)

    layer_p = query_sub.add_parser("layer", help="Raw layer data")
    layer_p.add_argument("layer_id", help="Layer ID")
    layer_p.set_defaults(handler=cmd_query_layer)

    find_p = query_sub.add_parser("findings", help="Resolved findings state")
    find_p.add_argument("layer_id", nargs="?", help="Layer ID")
    find_p.add_argument("--all", action="store_true", dest="bulk")
    find_p.add_argument("--cursor", help="Resume after this layer_id")
    find_p.add_argument("--limit", type=int, default=100)
    find_p.add_argument("--since-epoch", type=int, default=None)
    find_p.set_defaults(handler=cmd_query_findings)

    events_p = query_sub.add_parser("events", help="Event log for a layer")
    events_p.add_argument("layer_id", help="Layer ID")
    events_p.add_argument("--finding-ref", help="Filter to a specific finding")
    events_p.add_argument("--source-type", help="Filter by source type")
    events_p.add_argument("--limit", type=int, default=100)
    events_p.add_argument("--offset", type=int, default=0)
    events_p.set_defaults(handler=cmd_query_events)
