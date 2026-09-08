"""ledger sign — sign or verify a layer's Merkle root."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust_ledger._internal.integrity import verify_merkle_signature
from traust_ledger._internal.integrity.signing import SigningConfig, signing_env
from traust_ledger.cli.auth import require_cli_auth


def _load_layer(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read layer at {path}: {e}", file=sys.stderr)
        return None


def _build_credentials(args: argparse.Namespace) -> SigningConfig:
    """Build SigningConfig from CLI args + env — the auth credential."""
    method = args.method
    if method == "identity":
        return SigningConfig(
            method="identity",
            oidc_issuer=args.oidc_issuer or signing_env("OIDC_ISSUER"),
            oidc_client_id=args.oidc_client_id or signing_env("OIDC_CLIENT_ID"),
            expected_identity=args.expected_identity or signing_env("EXPECTED_IDENTITY"),
            oidc_token=signing_env("OIDC_TOKEN"),
            allow_interactive=signing_env("OIDC_INTERACTIVE", "0") == "1",
            ca_url=signing_env("CA_URL"),
            tlog_url=signing_env("TLOG_URL"),
        )
    return SigningConfig(
        method="keypair",
        key_path=args.key or signing_env("KEY_PATH"),
    )


def cmd_sign(args: argparse.Namespace) -> int:
    if require_cli_auth():
        return 1
    layer_path = Path(args.layer_path)
    layer = _load_layer(layer_path)
    if layer is None:
        return 1

    creds = _build_credentials(args)
    if not creds.key_path and not creds.oidc_token:
        print("error: no signing credentials configured", file=sys.stderr)
        return 1

    from traust_ledger.cli import backend_from_env, config_from_env
    from traust_ledger.handlers.sign_handler import sign_layer

    result = sign_layer(
        layer,
        config_from_env(str(layer_path.parent)),
        rekor=args.rekor,
        credentials=creds,
    )

    if result["status"] != "signed":
        print("error: signing backend not available", file=sys.stderr)
        return 1

    backend, _data_dir = backend_from_env()
    backend.store(layer_path, layer)
    print(f"Signed {layer_path.name} (method: {result['method']})")
    return 0


def cmd_verify_signature(args: argparse.Namespace) -> int:
    if require_cli_auth():
        return 1
    layer_path = Path(args.layer_path)
    layer = _load_layer(layer_path)
    if layer is None:
        return 1

    meta = layer.get("metadata") or {}
    if not meta.get("merkle_root"):
        print("error: layer has no merkle_root", file=sys.stderr)
        return 1
    if not meta.get("merkle_root_signature"):
        print(
            "error: layer has no merkle_root_signature — run `ledger sign` first", file=sys.stderr
        )
        return 1

    findings = verify_merkle_signature(layer, args.key)
    errors = [f for f in findings if f.severity.value == "error"]
    if errors:
        for f in errors:
            print(f"FAIL: {f.message}", file=sys.stderr)
        return 1

    print(f"PASS: signature verified for {layer_path.name}")
    return 0


def register_sign_parser(subparsers: argparse._SubParsersAction) -> None:
    sign_p = subparsers.add_parser("sign", help="Sign a layer's Merkle root")
    sign_p.add_argument("layer_path", help="Path to layer JSON file")
    sign_p.add_argument("--key", default=None, help="Private key path (keypair method)")
    sign_p.add_argument(
        "--method",
        choices=["keypair", "identity"],
        default="keypair",
        help="Signing method (default: keypair)",
    )
    sign_p.add_argument("--rekor", action="store_true", help="Upload to transparency log")
    sign_p.add_argument("--oidc-issuer", default=None, help="OIDC issuer URL (identity method)")
    sign_p.add_argument("--oidc-client-id", default=None, help="OIDC client ID (identity method)")
    sign_p.add_argument("--expected-identity", default=None, help="Expected certificate SAN")
    sign_p.set_defaults(handler=cmd_sign)

    vsig_p = subparsers.add_parser(
        "verify-signature", help="Verify a layer's Merkle root signature"
    )
    vsig_p.add_argument("layer_path", help="Path to layer JSON file")
    vsig_p.add_argument("--key", default=None, help="Public key path (keypair method)")
    vsig_p.set_defaults(handler=cmd_verify_signature)
