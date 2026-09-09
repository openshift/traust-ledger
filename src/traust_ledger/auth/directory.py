"""Employee-directory cross-check — optional, deployment-supplied, applied
after identity verification on every path (REST resolver and in-process
``LedgerClient``).

Identity verification answers *who is this token for*. A directory answers
a narrower question the ledger cannot: *is that person still a current
member of the organisation*. The ledger ships no directory implementation;
a deployment supplies one as a **command** and the SDK runs it:

    LEDGER_DIRECTORY_COMMAND="python3 /opt/your-org/bin/validate_employee.py"

The command is invoked as ``<command> <identity>`` and must print one
machine-readable line:

    RESULT uid=<identity> status=<active|contingent|terminated|not_found|...>

Any status other than ``active`` refuses the actor. A command that is
configured but cannot run, times out, exits non-zero, or prints no
RESULT line is ``unavailable`` — also a refusal (a directory that cannot
answer is not an answer). No command configured → no cross-check, the
token stands alone; this is the default and what an adopter without a
corporate directory gets.

Why a command and not an import string: deployment extensions are scripts
and config, not installable packages; the RESULT-line contract already
existed as the countersign gate's machine-readable output.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Protocol

from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.constants.domain import ACTOR_KIND_HUMAN
from traust_ledger.errors import AuthError, InvalidAuthError

logger = logging.getLogger(__name__)

DIRECTORY_COMMAND_ENV = "LEDGER_DIRECTORY_COMMAND"
DIRECTORY_TIMEOUT_ENV = "LEDGER_DIRECTORY_TIMEOUT"
STATUS_ACTIVE = "active"
STATUS_UNAVAILABLE = "unavailable"

RESULT_LINE = re.compile(
    r"^RESULT uid=(?P<uid>\S+) status=(?P<status>\S+)(?: auth=(?P<auth>\S+))?$",
    re.MULTILINE,
)

__all__ = [
    "DIRECTORY_COMMAND_ENV",
    "RESULT_LINE",
    "DirectoryRefusedError",
    "DirectoryUnavailableError",
    "EmployeeDirectory",
    "ScriptDirectory",
    "apply_directory",
    "load_directory",
]


class EmployeeDirectory(Protocol):
    """Cross-checks an identity string against an employee directory."""

    def is_active(self, identity: str) -> str:
        """Return a status string: 'active', 'terminated', 'contingent',
        'not_found', 'unavailable', …. Only 'active' passes."""
        ...


class DirectoryUnavailableError(AuthError):
    """A directory is configured but cannot be run at all."""

    message = "employee directory command is configured but unusable: {detail}"


class DirectoryRefusedError(InvalidAuthError):
    """The directory answered, and the answer was not 'active'."""

    message = "directory cross-check refused {identity!r}: status={status}"


class ScriptDirectory:
    """``EmployeeDirectory`` backed by an external command (see module doc)."""

    def __init__(self, command: list[str], *, timeout: float = 60.0) -> None:
        if not command:
            raise ValueError("directory command must not be empty")
        self._command = list(command)
        self._timeout = timeout

    @property
    def command(self) -> list[str]:
        return list(self._command)

    def is_active(self, identity: str) -> str:
        identity = (identity or "").strip()
        if not identity or any(c.isspace() for c in identity):
            return "not_found"
        try:
            proc = subprocess.run(
                [*self._command, identity],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("directory command failed to run: %s", exc)
            return STATUS_UNAVAILABLE
        if proc.returncode != 0:
            logger.warning("directory command exited %d for %s", proc.returncode, identity)
            return STATUS_UNAVAILABLE
        for m in RESULT_LINE.finditer(proc.stdout or ""):
            if m.group("uid") == identity:
                return m.group("status")
        logger.warning("directory command printed no RESULT line for %s", identity)
        return STATUS_UNAVAILABLE


def load_directory(env: dict[str, str] | None = None) -> EmployeeDirectory | None:
    """The deployment's directory from ``LEDGER_DIRECTORY_COMMAND``, or None.

    Fail closed on misconfiguration: a value that is set but whose program
    cannot be found raises ``DirectoryUnavailableError`` rather than
    silently running without the cross-check the deployment asked for.
    """
    env = os.environ if env is None else env
    raw = (env.get(DIRECTORY_COMMAND_ENV) or "").strip()
    if not raw:
        return None
    try:
        argv = shlex.split(raw)
    except ValueError as exc:
        raise DirectoryUnavailableError(detail=f"cannot parse {raw!r}: {exc}") from exc
    if not argv:
        return None
    prog = argv[0]
    if not (shutil.which(prog) or Path(prog).is_file()):
        raise DirectoryUnavailableError(detail=f"program not found: {prog!r}")
    # A script path given as the sole element runs via its shebang; a script
    # named after an interpreter argument is checked too so a typo fails now,
    # not at the first countersign.
    if len(argv) > 1 and argv[1].endswith(".py") and not Path(argv[1]).is_file():
        raise DirectoryUnavailableError(detail=f"script not found: {argv[1]!r}")
    timeout_raw = (env.get(DIRECTORY_TIMEOUT_ENV) or "").strip()
    timeout = float(timeout_raw) if timeout_raw else 60.0
    return ScriptDirectory(argv, timeout=timeout)


def apply_directory(actor: LayerActor, directory: EmployeeDirectory | None) -> LayerActor:
    """Cross-check a verified human actor; stamp ``employee_status`` or refuse.

    Machine actors and actors without an identity string pass through
    unchanged — the directory is about people. ``None`` directory → no-op.
    """
    if directory is None or actor.kind != ACTOR_KIND_HUMAN:
        return actor
    identity = actor.identity or ""
    if not identity:
        return actor
    status = directory.is_active(identity)
    if status != STATUS_ACTIVE:
        logger.warning("directory cross-check failed for %s status=%s", identity, status)
        raise DirectoryRefusedError(identity=identity, status=status)
    return actor.model_copy(update={"employee_status": status})
