from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from traust_ledger.auth import DeviceCodeFlow, RefreshFlow
from traust_ledger.auth.discovery import discover_oidc
from traust_ledger.cli.identity.config import (
    active_host,
    clear_credentials,
    list_hosts,
    load_config,
    load_credentials,
    save_config,
    save_credentials,
)


def _peek_jwt_claims(token: str) -> dict:
    """Decode JWT payload for display only (no signature verification)."""
    import base64
    import json as _json

    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return _json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, UnicodeDecodeError):
        return {}


def cmd_auth_login(args: argparse.Namespace) -> int:
    """ledger auth login — device-code flow or token-file import."""
    config = load_config()
    server_url = os.environ.get("LEDGER_SERVER_URL") or config.get("server_url")

    if args.token_file:
        host = server_url or "local"
        access_token = Path(args.token_file).read_text(encoding="utf-8").strip()
        if server_url:
            config["active_server"] = server_url
            save_config(config)
        save_credentials({"access_token": access_token}, host=host)
        print(f"Token imported for {host}.")
        return 0

    issuer = os.environ.get("LEDGER_OIDC_ISSUER") or config.get("issuer")
    client_id = os.environ.get("LEDGER_OIDC_CLIENT_ID") or config.get("client_id")
    if not issuer or not client_id:
        print(
            "Missing OIDC issuer or client ID. "
            "Run `ledger config set --issuer URL --client-id ID` first.",
            file=sys.stderr,
        )
        return 1

    host = server_url or issuer

    flow = DeviceCodeFlow(issuer, client_id, scope=args.scope)
    response = flow.execute()

    expires_at = time.time() + response["expires_in"]
    config["active_server"] = host
    save_config(config)
    save_credentials(
        {
            "access_token": response["access_token"],
            "refresh_token": response.get("refresh_token"),
            "expires_at": expires_at,
            "issuer": issuer,
            "client_id": client_id,
        },
        host=host,
    )
    expires_dt = datetime.fromtimestamp(expires_at, tz=UTC)
    print(f"Authenticated to {host}. Token expires at {expires_dt}.")
    return 0


def cmd_auth_service_account(args: argparse.Namespace) -> int:
    """ledger auth service-account — obtain a machine token via client credentials.

    The OIDC counterpart to `ledger auth local --machine`. Use this for scheduled
    emission, where signing as whoever the job runs as attributes machine verdicts
    to a person.
    """
    from traust_ledger.auth.discovery import discover_oidc
    from traust_ledger.auth.flows import ClientCredentialsFlow

    config = load_config()
    server_url = os.environ.get("LEDGER_SERVER_URL") or config.get("server_url")
    issuer = os.environ.get("LEDGER_OIDC_ISSUER") or config.get("issuer")
    client_id = (
        getattr(args, "client_id", None)
        or os.environ.get("LEDGER_OIDC_CLIENT_ID")
        or config.get("client_id")
    )
    if not issuer or not client_id:
        print(
            "Missing OIDC issuer or client ID. "
            "Run `ledger config set --issuer URL --client-id ID` first.",
            file=sys.stderr,
        )
        return 1

    # Never on argv: a secret there is visible to every local user via ps.
    secret = None
    if getattr(args, "client_secret_file", None):
        try:
            secret = Path(args.client_secret_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            print(f"cannot read --client-secret-file: {exc}", file=sys.stderr)
            return 2
    else:
        secret = os.environ.get("LEDGER_OIDC_CLIENT_SECRET")
    if not secret:
        print(
            "No client secret. Pass --client-secret-file PATH or set LEDGER_OIDC_CLIENT_SECRET.",
            file=sys.stderr,
        )
        return 1

    metadata = discover_oidc(issuer)
    flow = ClientCredentialsFlow(metadata.token_endpoint, client_id, scope=args.scope)
    try:
        response = flow.execute(secret)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not response.get("access_token"):
        print(
            f"provider returned no access_token for {client_id}",
            file=sys.stderr,
        )
        return 1

    host = server_url or issuer
    expires_at = time.time() + response.get("expires_in", 3600)
    config["active_server"] = host
    save_config(config)
    save_credentials(
        {
            "access_token": response["access_token"],
            "expires_at": expires_at,
            "issuer": issuer,
            "client_id": client_id,
        },
        host=host,
    )

    claims = _peek_jwt_claims(response["access_token"])
    # A service account carrying an identity claim verifies as HUMAN, which is the
    # failure this command exists to prevent. Say so at acquisition; by write time
    # the attribution is already wrong and nothing looks broken.
    if claims.get("email"):
        print(
            f"WARNING: this token carries an 'email' claim ({claims['email']}), so it "
            "will verify as a HUMAN actor, not a machine. Configure the provider to "
            "omit the identity claim for this service account.",
            file=sys.stderr,
        )
    # An opaque (non-JWT) token cannot be inspected, so the kind is genuinely
    # unknown — reporting "machine" on the absence of a claim we were unable to
    # read would be a false assurance about the very thing being checked.
    if not claims:
        kind = "unknown (opaque token — could not inspect claims)"
    elif claims.get("email"):
        kind = "human (MISCONFIGURED)"
    else:
        kind = "machine"
    print(f"Service-account token acquired for {host}.")
    print(f"  Client:   {client_id}")
    print(f"  Kind:     {kind}")
    print("  Provider: oidc")
    return 0


def cmd_auth_status(args: argparse.Namespace) -> int:
    """ledger auth status — show current identity, expiry, server."""
    host = active_host()
    if host:
        print(f"Active: {host}")
    creds = load_credentials()
    if creds is None:
        print("Not authenticated. Run `ledger auth login`.")
        return 1

    print(f"Issuer: {creds.get('issuer', '—')}")
    print(f"Client ID: {creds.get('client_id', '—')}")

    expires_at = creds.get("expires_at")
    if expires_at is not None:
        expires_dt = datetime.fromtimestamp(expires_at, tz=UTC)
        expired = time.time() >= expires_at
        status = "expired" if expired else "valid"
        print(f"Expires at: {expires_dt} ({status})")
    else:
        print("Expires at: unknown")

    access_token = creds.get("access_token")
    if access_token:
        claims = _peek_jwt_claims(access_token)
        identity = claims.get("sub") or claims.get("email")
        if identity:
            print(f"Identity: {identity}")

    hosts = list_hosts()
    if len(hosts) > 1:
        print(f"\nAll hosts ({len(hosts)}):")
        for h in hosts:
            marker = " *" if h == host else ""
            print(f"  {h}{marker}")

    return 0


def cmd_auth_logout(args: argparse.Namespace) -> int:
    """ledger auth logout — remove credentials for active host (or --all)."""
    if getattr(args, "all", False):
        clear_credentials()
        print("All credentials removed.")
    else:
        host = active_host()
        if not host:
            print("No active server configured.", file=sys.stderr)
            return 1
        clear_credentials(host=host)
        print(f"Credentials removed for {host}.")
    return 0


def cmd_auth_switch(args: argparse.Namespace) -> int:
    """ledger auth switch — switch active server."""
    hosts = list_hosts()
    if not hosts:
        print("No stored credentials. Run `ledger auth login`.", file=sys.stderr)
        return 1

    target = args.host
    if target and target not in hosts:
        print(f"No credentials for {target}.", file=sys.stderr)
        print(f"Available: {', '.join(hosts)}", file=sys.stderr)
        return 1

    if not target:
        current = active_host()
        for h in hosts:
            marker = " (active)" if h == current else ""
            print(f"  {h}{marker}")
        return 0

    config = load_config()
    config["active_server"] = target
    save_config(config)
    print(f"Switched to {target}.")
    return 0


def cmd_auth_refresh(args: argparse.Namespace) -> int:
    """ledger auth refresh — exchange refresh token for a new access token."""
    creds = load_credentials()
    if creds is None:
        print("Not authenticated. Run `ledger auth login`.", file=sys.stderr)
        return 1

    rt = creds.get("refresh_token")
    if not rt:
        print("No refresh token cached. Run `ledger auth login` again.", file=sys.stderr)
        return 1

    issuer = creds.get("issuer")
    client_id = creds.get("client_id")
    if not issuer or not client_id:
        print("Missing issuer/client_id in cached credentials. Re-login.", file=sys.stderr)
        return 1

    metadata = discover_oidc(issuer)
    flow = RefreshFlow(metadata.token_endpoint, client_id)
    try:
        response = flow.execute(rt)
    except RuntimeError as exc:
        print(f"Refresh failed: {exc}", file=sys.stderr)
        print("Run `ledger auth login` to re-authenticate.", file=sys.stderr)
        return 1

    expires_at = time.time() + response.get("expires_in", 3600)
    creds["access_token"] = response["access_token"]
    if response.get("refresh_token"):
        creds["refresh_token"] = response["refresh_token"]
    creds["expires_at"] = expires_at
    save_credentials(creds)

    expires_dt = datetime.fromtimestamp(expires_at, tz=UTC)
    print(f"Token refreshed. Expires at {expires_dt}.")
    return 0


def cmd_auth_token(args: argparse.Namespace) -> int:
    """ledger auth token — print the current access token to stdout."""
    from traust_ledger.cli.identity.config import resolve_token

    token = resolve_token()
    if not token:
        print("No token available. Run `ledger auth login`.", file=sys.stderr)
        return 1
    print(token)
    return 0


def cmd_auth_local(args: argparse.Namespace) -> int:
    """ledger auth local — create a locally-signed identity token."""
    config = load_config()
    identity: str | None = getattr(args, "identity", None)

    if not identity:
        identity = config.get("local_identity")

    if not identity:
        print(
            "No identity configured.\n"
            "  Run: ledger auth local --identity you@example.com\n"
            "  Or:  ledger auth login  (for OIDC)",
            file=sys.stderr,
        )
        return 1

    asked_machine = bool(getattr(args, "machine", False))
    asked_human = bool(getattr(args, "human", False))
    if asked_machine and asked_human:
        print("error: --machine and --human are mutually exclusive", file=sys.stderr)
        return 2

    # **The remembered kind must be inherited, not re-defaulted.** `identity` is
    # restored from config above when no --identity is given, so reading the kind
    # from the flag alone made a bare `ledger auth local` — the documented refresh,
    # which even prints "refreshed" — silently downgrade a machine identity to a
    # human one and lower-case the version string it names. That reintroduces the
    # exact misattribution this mode exists to prevent, at the moment an operator
    # is least likely to look. Downgrading is now something you have to ask for.
    remembered_kind = config.get("local_identity_kind")
    reusing_remembered = (
        getattr(args, "identity", None) is None
        or identity.strip().lower() == str(config.get("local_identity") or "").lower()
    )
    machine = asked_machine or (
        not asked_human and reusing_remembered and remembered_kind == "machine"
    )

    # A machine name is not an address: lower-casing "triage/0.32.0-57f1EF1" would
    # silently rewrite the version it names, so only human identities are folded.
    identity = identity.strip() if machine else identity.strip().lower()
    prior_identity = config.get("local_identity")

    from traust_ledger.auth.local import ensure_local_keypair, mint_local_token
    from traust_ledger.cli.identity.config import config_dir

    key = ensure_local_keypair(config_dir())
    token = mint_local_token(identity, key, machine=machine)

    config["local_identity"] = identity
    config["local_identity_kind"] = "machine" if machine else "human"
    config["active_server"] = "local"
    save_config(config)

    expires_at = time.time() + 7 * 24 * 3600
    save_credentials(
        {
            "access_token": token,
            "expires_at": expires_at,
            "issuer": "local",
        },
        host="local",
    )

    expires_dt = datetime.fromtimestamp(expires_at, tz=UTC)
    verb = "refreshed" if prior_identity == identity else "created"
    print(f"Local token {verb}.")
    print(f"  Identity: {identity}")
    print(f"  Kind:     {'machine' if machine else 'human'}")
    print("  Provider: local")
    print("  Verified: yes (local)")
    print(f"  Expires:  {expires_dt}")
    return 0


def cmd_config_set(args: argparse.Namespace) -> int:
    """ledger config set --server URL --issuer URL --client-id ID"""
    config = load_config()
    if args.server is not None:
        config["server_url"] = args.server
    if args.issuer is not None:
        config["issuer"] = args.issuer
    if args.client_id is not None:
        config["client_id"] = args.client_id
    save_config(config)
    return 0


def register_auth_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register 'auth' and 'config' subcommands on the main parser."""
    auth_parser = subparsers.add_parser("auth", help="Manage authentication")
    auth_sub = auth_parser.add_subparsers(dest="auth_command", required=True)

    local_p = auth_sub.add_parser("local", help="Create a locally-signed identity token")
    local_p.add_argument("--identity", help="Email or identity string (remembered for next time)")
    local_p.add_argument(
        "--machine",
        action="store_true",
        help="mint a MACHINE actor (azp claim, no email) rather than a human one. "
        "Use for automation that records verdicts it did not personally make — "
        "e.g. --machine --identity triage/0.32.0. Remembered: re-running "
        "`ledger auth local` keeps the machine kind.",
    )
    local_p.add_argument(
        "--human",
        action="store_true",
        help="mint a HUMAN actor, overriding a remembered machine identity",
    )
    local_p.set_defaults(handler=cmd_auth_local)

    login_p = auth_sub.add_parser("login", help="Authenticate via device-code flow")
    login_p.add_argument(
        "--token-file",
        help="Import token from file instead of device-code flow",
    )
    login_p.add_argument("--scope", default="openid", help="OAuth scope (default: openid)")
    login_p.set_defaults(handler=cmd_auth_login)

    sa_p = auth_sub.add_parser(
        "service-account",
        help="Obtain a MACHINE token via the OAuth2 client-credentials grant",
    )
    sa_p.add_argument("--client-id", help="service-account client id (default: configured)")
    sa_p.add_argument(
        "--client-secret-file",
        help="file holding the client secret (env: LEDGER_OIDC_CLIENT_SECRET). "
        "Never passed on argv, which is ps-visible to every local user.",
    )
    sa_p.add_argument("--scope", default="openid", help="OAuth scope (default: openid)")
    sa_p.set_defaults(handler=cmd_auth_service_account)

    status_p = auth_sub.add_parser("status", help="Show authentication status")
    status_p.set_defaults(handler=cmd_auth_status)

    logout_p = auth_sub.add_parser("logout", help="Remove cached credentials")
    logout_p.add_argument("--all", action="store_true", help="Remove credentials for all hosts")
    logout_p.set_defaults(handler=cmd_auth_logout)

    refresh_p = auth_sub.add_parser("refresh", help="Refresh stored authentication credentials")
    refresh_p.set_defaults(handler=cmd_auth_refresh)

    token_p = auth_sub.add_parser("token", help="Print the current access token")
    token_p.set_defaults(handler=cmd_auth_token)

    switch_p = auth_sub.add_parser("switch", help="Switch active ledger host")
    switch_p.add_argument("host", nargs="?", help="Server URL to switch to (omit to list)")
    switch_p.set_defaults(handler=cmd_auth_switch)

    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_sub = config_parser.add_subparsers(dest="config_command", required=True)

    set_p = config_sub.add_parser("set", help="Set configuration values")
    set_p.add_argument("--server", help="Ledger service URL")
    set_p.add_argument("--issuer", help="OIDC issuer URL")
    set_p.add_argument("--client-id", help="OIDC client ID")
    set_p.set_defaults(handler=cmd_config_set)
