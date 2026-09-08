"""Actor resolver — composes an IdentityPort with an optional EmployeeDirectory."""

from __future__ import annotations

import logging

from fastapi import Request
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth.directory import DirectoryRefusedError, apply_directory
from traust_ledger.service.errors import InvalidAuthError
from traust_ledger.service.identity.ports import EmployeeDirectory, IdentityPort

logger = logging.getLogger(__name__)


class ActorResolver:
    """Resolve request credentials to a LayerActor.

    Constructed once at app startup with the appropriate adapters,
    then called per-request from the FastAPI dependency.
    """

    def __init__(
        self,
        verifier: IdentityPort,
        directory: EmployeeDirectory | None = None,
    ) -> None:
        self._verifier = verifier
        self._directory = directory

    def resolve(self, request: Request) -> LayerActor:
        actor = self._verifier.verify(request)

        try:
            actor = apply_directory(actor, self._directory)
        except DirectoryRefusedError as exc:
            raise InvalidAuthError() from exc

        logger.debug(
            "actor resolved kind=%s identity=%s verified=%s provider=%s employee_status=%s",
            actor.kind,
            actor.identity or "<none>",
            actor.identity_verified,
            actor.identity_provider,
            actor.employee_status,
        )
        return actor
