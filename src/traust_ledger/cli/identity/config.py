from __future__ import annotations

import json
import os
import time
from pathlib import Path

_CONFIG_DIR_NAME = "traust-ledger"
_CONFIG_FILE = "config.json"
_CREDENTIALS_FILE = "credentials.json"


def config_dir() -> Path:
    path = Path.home() / ".config" / _CONFIG_DIR_NAME
    if not path.exists():
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def _atomic_write(path: Path, content: str, *, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        tmp.replace(path)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def _read_json_file(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def load_config() -> dict:
    data = _read_json_file(config_dir() / _CONFIG_FILE)
    return data or {}


def save_config(data: dict) -> None:
    content = json.dumps(data, indent=2) + "\n"
    _atomic_write(config_dir() / _CONFIG_FILE, content, mode=0o644)


def active_host() -> str | None:
    """Return the active server URL (host key for credentials)."""
    config = load_config()
    return (
        os.environ.get("LEDGER_SERVER_URL")
        or config.get("active_server")
        or config.get("server_url")
    )


def load_all_credentials() -> dict:
    """Load the full host-keyed credentials store."""
    return _read_json_file(config_dir() / _CREDENTIALS_FILE) or {}


def load_credentials() -> dict | None:
    """Load credentials for the active host."""
    host = active_host()
    if not host:
        return None
    all_creds = load_all_credentials()
    return all_creds.get(host)


def save_credentials(data: dict, host: str | None = None) -> None:
    """Save credentials for a host. Defaults to active host."""
    host = host or active_host()
    if not host:
        raise RuntimeError("No active server configured")
    all_creds = load_all_credentials()
    all_creds[host] = data
    content = json.dumps(all_creds, indent=2) + "\n"
    _atomic_write(config_dir() / _CREDENTIALS_FILE, content, mode=0o600)


def clear_credentials(host: str | None = None) -> None:
    """Remove credentials for a host (or all if host is None)."""
    if host is None:
        (config_dir() / _CREDENTIALS_FILE).unlink(missing_ok=True)
        return
    all_creds = load_all_credentials()
    all_creds.pop(host, None)
    if all_creds:
        content = json.dumps(all_creds, indent=2) + "\n"
        _atomic_write(config_dir() / _CREDENTIALS_FILE, content, mode=0o600)
    else:
        (config_dir() / _CREDENTIALS_FILE).unlink(missing_ok=True)


def list_hosts() -> list[str]:
    """Return all hosts with stored credentials."""
    return list(load_all_credentials().keys())


def resolve_token() -> str | None:
    token_path = os.environ.get("LEDGER_TOKEN_PATH")
    if token_path:
        try:
            return Path(token_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError(
                f"LEDGER_TOKEN_PATH={token_path} is set but unreadable: {exc}"
            ) from exc

    static_token = os.environ.get("LEDGER_TOKEN")
    if static_token:
        return static_token

    creds = load_credentials()
    if creds is not None:
        access_token = creds.get("access_token")
        if access_token:
            expires_at = creds.get("expires_at")
            if expires_at is None or time.time() < expires_at:
                return access_token

    return _auto_mint_local_token()


def _auto_mint_local_token() -> str | None:
    """Auto-mint a local JWT when LEDGER_LOCAL_IDENTITY is set.

    Kind is inherited, never re-defaulted. This is the fallback `resolve_token`
    reaches when a stored credential is missing **or expired**, so minting human
    unconditionally meant a machine identity flipped to human seven days in —
    mid-campaign, silently, with the actor on every subsequent event naming a
    person instead of the automation. Set `LEDGER_LOCAL_MACHINE=1` to force it,
    or it follows the kind `ledger auth local --machine` remembered for this
    identity.
    """
    identity = (os.environ.get("LEDGER_LOCAL_IDENTITY") or "").strip()
    if not identity:
        return None
    from traust_ledger.auth.local import ensure_local_keypair, mint_local_token

    forced = (os.environ.get("LEDGER_LOCAL_MACHINE") or "").strip().lower()
    machine = forced in {"1", "true", "yes"}
    if not machine:
        config = load_config()
        remembered = str(config.get("local_identity") or "")
        machine = (
            config.get("local_identity_kind") == "machine"
            and remembered.lower() == identity.lower()
        )

    key = ensure_local_keypair(config_dir())
    return mint_local_token(identity, key, machine=machine)
