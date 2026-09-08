"""ledger verify — merkle integrity check."""

from __future__ import annotations

import argparse
import json
import sys

from traust_ledger.cli.auth import require_cli_auth
from traust_ledger.cli.errors import cli_exit_service_error
from traust_ledger.errors import ServiceError


def cmd_verify(args: argparse.Namespace) -> int:
    if require_cli_auth():
        return 1
    layer_id = getattr(args, "layer_id", None)
    check_sigs = getattr(args, "check_signatures", False)
    all_layers = getattr(args, "all", False)
    path = getattr(args, "path", None)

    if path:
        return _verify_path(path, check_sigs)
    if all_layers:
        return _verify_all(check_sigs)
    if not layer_id:
        print("error: layer_id required (or use --all / --path)", file=sys.stderr)
        return 1

    from traust_ledger.cli import backend_from_env, config_from_env
    from traust_ledger.handlers.layer_handler import load_layer
    from traust_ledger.handlers.verify_handler import verify_layer

    backend, data_dir = backend_from_env()
    config = config_from_env(data_dir)
    try:
        layer = load_layer(layer_id, backend, config)
    except ServiceError as exc:
        return cli_exit_service_error(exc)
    result = verify_layer(layer, check_signatures=check_sigs)
    print(json.dumps(result, indent=2))
    return 0


def _verify_all(check_signatures: bool) -> int:
    from traust_ledger.cli import backend_from_env, iter_layers
    from traust_ledger.handlers.verify_handler import verify_layer

    backend, data_dir = backend_from_env()
    found = False
    any_failed = False
    for layer_id, layer in iter_layers(backend, data_dir):
        found = True
        result = verify_layer(layer, check_signatures=check_signatures)
        result["layer_id"] = layer_id
        print(json.dumps(result))
        if not result.get("passed", True):
            any_failed = True
    if not found:
        print(json.dumps({"error": "no layers found"}), file=sys.stderr)
        return 1
    return 1 if any_failed else 0


def _verify_path(path: str, check_signatures: bool) -> int:
    from pathlib import Path

    from traust_ledger.handlers.verify_handler import verify_layer

    p = Path(path)
    if not p.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return 1
    try:
        layer = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    result = verify_layer(layer, check_signatures=check_signatures)
    print(json.dumps(result, indent=2))
    return 0 if result.get("passed", True) else 1


def register_verify_parser(subparsers: argparse._SubParsersAction) -> None:
    verify_p = subparsers.add_parser("verify", help="Merkle integrity check")
    verify_p.add_argument("layer_id", nargs="?", help="Layer ID (or use --all / --path)")
    verify_p.add_argument("--all", action="store_true", help="Verify all layers")
    verify_p.add_argument("--path", help="Verify a layer JSON file directly (no backend needed)")
    verify_p.add_argument("--check-signatures", action="store_true")
    verify_p.set_defaults(handler=cmd_verify)
