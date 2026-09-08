"""DI ports (protocols) for the identity domain.

Adapters implement these; the resolver and tests depend only on the
protocol shape, never on concrete LDAP/OIDC libraries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self

from fastapi import Request
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth.directory import EmployeeDirectory  # noqa: F401 — re-export

if TYPE_CHECKING:
    from traust_ledger.config import ServiceConfig


class IdentityPort(Protocol):
    """Validates request credentials and returns decoded identity claims."""

    def verify(self, request: Request) -> LayerActor:
        """Return a LayerActor or raise MissingAuthError / InvalidAuthError."""
        ...

    @classmethod
    def from_config(cls, config: ServiceConfig) -> Self:
        """Construct an adapter from service configuration."""
        ...
