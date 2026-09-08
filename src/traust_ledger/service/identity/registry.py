"""Provider registry — config-driven identity adapter selection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from traust_ledger.service.identity.ports import IdentityPort

if TYPE_CHECKING:
    from traust_ledger.config import ServiceConfig

PROVIDERS: dict[str, type[IdentityPort]] = {}
_providers_loaded = False


def register(name: str):
    """Decorator to register an identity provider adapter."""

    def decorator(cls: type[IdentityPort]) -> type[IdentityPort]:
        PROVIDERS[name] = cls
        return cls

    return decorator


def _ensure_providers_registered() -> None:
    global _providers_loaded
    if _providers_loaded:
        return
    import traust_ledger.service.identity.oidc  # noqa: F401

    _providers_loaded = True


def build_provider(config: ServiceConfig) -> IdentityPort:
    """Instantiate the configured identity provider."""
    _ensure_providers_registered()
    provider_name = config.identity_provider
    cls = PROVIDERS.get(provider_name)
    if cls is None:
        available = ", ".join(sorted(PROVIDERS.keys()))
        raise RuntimeError(f"Unknown identity provider: {provider_name!r}. Available: {available}")
    return cls.from_config(config)
