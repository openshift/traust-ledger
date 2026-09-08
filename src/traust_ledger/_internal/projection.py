"""Materialized findings projection — schema and write operations.

The projection table is the portable artifact downstream dashboards bind to.
Schema is defined here; the CLI and any future builders import it.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.sql import func
from sqlalchemy.types import JSON, Boolean

from traust_ledger.models import FindingDisposition

projection_metadata = MetaData()

findings_table = Table(
    "materialized_findings",
    projection_metadata,
    Column("layer_id", String, nullable=False),
    Column("finding_ref", String, nullable=False),
    Column("fingerprint", String, nullable=True),
    Column("orphan", Boolean, nullable=True, default=False),
    Column("validity", String, nullable=False),
    Column("resolution", String, nullable=False),
    Column("assurance", String),
    Column("event_count", Integer, nullable=False),
    Column("conflict", Boolean, default=False),
    Column("fp_overridden", Boolean, default=False),
    Column("fp_reassertion_blocked", Boolean, default=False),
    Column("severity_override", JSON),
    Column("last_updated", String),
    Column("merkle_root", String),
    Column("merkle_epoch", Integer),
    Column("materialized_at", DateTime, server_default=func.now()),
    PrimaryKeyConstraint("layer_id", "finding_ref"),
)


def ensure_schema(engine: Engine) -> None:
    projection_metadata.create_all(engine)


def build_row(
    layer_id: str,
    f: FindingDisposition,
    merkle_root: str | None,
    merkle_epoch: int | None,
    now: datetime,
) -> dict:
    d = f.disposition
    return {
        "layer_id": layer_id,
        "finding_ref": f.finding_ref,
        # 6e: populated from the events, not synthesised. Both stay nullable —
        # see FindingDisposition for why an unknown must not become a False.
        "fingerprint": f.fingerprint,
        "orphan": f.orphan,
        "validity": str(d.validity),
        "resolution": str(d.resolution),
        "assurance": str(d.assurance) if d.assurance else None,
        "event_count": f.event_count,
        "conflict": d.conflict or False,
        "fp_overridden": d.fp_overridden or False,
        "fp_reassertion_blocked": d.fp_reassertion_blocked or False,
        "severity_override": (d.severity_override.model_dump() if d.severity_override else None),
        "last_updated": d.last_updated,
        "merkle_root": merkle_root,
        "merkle_epoch": merkle_epoch,
        "materialized_at": now,
    }


def upsert_layer(
    conn: Connection, layer_id: str, rows: list[dict], *, prune_empty: bool = False
) -> None:
    """Upsert findings for one layer: prune stale refs, insert or update current.

    An EMPTY `rows` list does not prune by default. Previously it deleted every
    row for the layer, so a layer that failed to parse, was momentarily empty, or
    was skipped by a narrowed run silently erased its projection instead of
    leaving the last good state — and the caller could not tell "this layer now
    has no findings" apart from "this layer could not be read". Deleting a
    layer's whole projection is a deliberate act; pass ``prune_empty=True`` to
    ask for it.

    A non-empty `rows` still prunes refs that are no longer present, which is
    the case that keeps the projection honest after a re-baseline.
    """
    current_refs = {r["finding_ref"] for r in rows}
    if not current_refs and not prune_empty:
        return
    conn.execute(
        delete(findings_table).where(
            findings_table.c.layer_id == layer_id,
            ~findings_table.c.finding_ref.in_(current_refs)
            if current_refs
            else findings_table.c.finding_ref.isnot(None),
        )
    )
    for row in rows:
        existing = conn.execute(
            select(findings_table.c.finding_ref).where(
                findings_table.c.layer_id == row["layer_id"],
                findings_table.c.finding_ref == row["finding_ref"],
            )
        ).first()
        if existing:
            conn.execute(
                update(findings_table)
                .where(
                    findings_table.c.layer_id == row["layer_id"],
                    findings_table.c.finding_ref == row["finding_ref"],
                )
                .values(**row)
            )
        else:
            conn.execute(insert(findings_table).values(**row))


def print_ddl() -> None:
    """Print the projection table DDL (SQLite dialect) to stdout."""
    from sqlalchemy import create_mock_engine

    buf: list[str] = []

    def dump(sql, *_args, **_kwargs):
        compiled = sql.compile(dialect=engine.dialect)
        buf.append(str(compiled).strip() + ";")

    engine = create_mock_engine("sqlite://", dump)
    projection_metadata.create_all(engine, checkfirst=False)
    print("\n".join(buf))
