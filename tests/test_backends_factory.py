"""Backend factory error paths."""

from __future__ import annotations

import pytest

from traust_ledger._internal.backends import create_backend
from traust_ledger._internal.backends.constants import (
    DATABASE_URL_REQUIRED_MSG,
    UNKNOWN_BACKEND_MSG,
)


def test_create_backend_unknown_type() -> None:
    with pytest.raises(ValueError, match=UNKNOWN_BACKEND_MSG.format(backend_type="nope")):
        create_backend("nope")


def test_create_backend_db_requires_url() -> None:
    with pytest.raises(ValueError, match=DATABASE_URL_REQUIRED_MSG):
        create_backend("db")
