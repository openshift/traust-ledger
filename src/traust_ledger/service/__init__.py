from __future__ import annotations


def create_app():  # type: ignore[no-untyped-def]
    """Lazy import to avoid pulling FastAPI into non-service consumers."""
    from traust_ledger.service.app import create_app as _create_app

    return _create_app()


__all__ = ["create_app"]
