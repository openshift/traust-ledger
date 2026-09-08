"""SQLAlchemy-based layer storage backend."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import TypeVar

from sqlalchemy import Column, DateTime, MetaData, String, Table, insert, select, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.sql import func
from sqlalchemy.types import JSON

from .constants import (
    DATA_COLUMN,
    EMPTY_LAYER,
    LAYER_ID_COLUMN,
    LAYERS_TABLE_NAME,
    UPDATED_AT_COLUMN,
)

T = TypeVar("T")

metadata = MetaData()

layers_table = Table(
    LAYERS_TABLE_NAME,
    metadata,
    Column(LAYER_ID_COLUMN, String, primary_key=True),
    Column(DATA_COLUMN, JSON, nullable=False),
    Column(UPDATED_AT_COLUMN, DateTime, server_default=func.now(), onupdate=func.now()),
)


# ── Upsert strategies ────────────────────────────────────────────


def _upsert_on_conflict(
    conn: Connection,
    layer_id: str,
    data: dict,
    dialect_insert: Callable,
) -> None:
    """Atomic upsert for dialects supporting INSERT ... ON CONFLICT DO UPDATE."""
    stmt = (
        dialect_insert(layers_table)
        .values(layer_id=layer_id, data=data)
        .on_conflict_do_update(
            index_elements=[layers_table.c.layer_id],
            set_={"data": data, "updated_at": func.now()},
        )
    )
    conn.execute(stmt)


def _upsert_generic(conn: Connection, layer_id: str, data: dict) -> None:
    """Select-then-write fallback. Safe inside a transaction — callers
    (store/mutate) always wrap in engine.begin()."""
    existing = conn.execute(
        select(layers_table.c.layer_id).where(layers_table.c.layer_id == layer_id)
    ).first()
    if existing is not None:
        conn.execute(
            update(layers_table).where(layers_table.c.layer_id == layer_id).values(data=data)
        )
    else:
        conn.execute(insert(layers_table).values(layer_id=layer_id, data=data))


def _resolve_upsert(dialect_name: str) -> Callable[..., None]:
    """Return the best upsert callable for the dialect.

    Postgres and SQLite get atomic ON CONFLICT; everything else gets the
    generic transactional fallback. To add a new dialect, add an entry
    to _DIALECT_INSERTS with its dialect-specific insert function.
    """
    if dialect_name in _DIALECT_INSERTS:
        dialect_insert = _DIALECT_INSERTS[dialect_name]()

        def _do(conn: Connection, layer_id: str, data: dict) -> None:
            _upsert_on_conflict(conn, layer_id, data, dialect_insert)

        return _do
    return _upsert_generic


def _pg_insert() -> Callable:
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    return pg_insert


def _sqlite_insert() -> Callable:
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    return sqlite_insert


_DIALECT_INSERTS: dict[str, Callable[[], Callable]] = {
    "postgresql": _pg_insert,
    "sqlite": _sqlite_insert,
}


# ── Backend ───────────────────────────────────────────────────────


def _layer_id(path: Path) -> str:
    """The key is the layer id, not the path it happens to be stored under.

    This used to be ``str(path)``, which put a filesystem path in the primary key
    while ``list_layer_ids()`` returned that same column — so the db backend handed
    out ids the rest of the stack rejects. ``iter_layers()`` feeds each id straight
    back to ``layer_file_path()``, which validates against ``LAYER_ID_PATTERN``, so
    every id came back with slashes and dots and raised "layer_id contains invalid
    characters". Net effect: `materialize` and `verify` could not run against
    ``LAAS_BACKEND_TYPE=db`` at all. The file backend keys on the stem; both now do.
    """
    return path.stem


class DbBackend:
    """SQLAlchemy-based layer storage. Append-only at the application layer."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._upsert_fn = _resolve_upsert(engine.dialect.name)

    @classmethod
    def create_tables(cls, engine: Engine) -> None:
        metadata.create_all(engine)

    def list_layer_ids(self) -> list[str]:
        """Return all stored layer IDs from the database."""
        with self._engine.connect() as conn:
            rows = conn.execute(select(layers_table.c.layer_id)).fetchall()
            return sorted(row.layer_id for row in rows)

    def load(self, path: Path) -> dict:
        layer_id = _layer_id(path)
        with self._engine.connect() as conn:
            row = conn.execute(
                select(layers_table.c.data).where(layers_table.c.layer_id == layer_id)
            ).first()
            if row is None:
                return dict(EMPTY_LAYER)
            return deepcopy(row.data)

    def store(self, path: Path, data: dict) -> None:
        layer_id = _layer_id(path)
        with self._engine.begin() as conn:
            self._upsert(conn, layer_id, data)

    def mutate(self, path: Path, mutator: Callable[[dict], T]) -> T:
        layer_id = _layer_id(path)
        with self._engine.begin() as conn:
            stmt = (
                select(layers_table.c.data)
                .where(layers_table.c.layer_id == layer_id)
                .with_for_update()
            )
            row = conn.execute(stmt).first()
            data = deepcopy(row.data) if row is not None else dict(EMPTY_LAYER)
            result = mutator(data)
            self._upsert(conn, layer_id, data)
            return result

    def _upsert(self, conn: Connection, layer_id: str, data: dict) -> None:
        self._upsert_fn(conn, layer_id, data)
