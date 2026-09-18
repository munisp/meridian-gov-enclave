"""Durable document store for tcc (HARDENING H1).

Selection: TCC_DATABASE_URL (else DATABASE_URL) set -> Postgres via
psycopg[binary] (profile=prod); unset or unreachable -> in-memory dicts
(profile=dev), preserving previous behaviour. Mirrors the etr/filings
pattern: a generic (collection, id, doc jsonb) table with idempotent DDL.
Tax clearance certificates and SLA state are statutory records (NTAA 2025
s.72) — restart must not lose them (schema audit P0).
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

log = logging.getLogger("tcc.store")

_PG_DDL = """
CREATE TABLE IF NOT EXISTS tcc_docs(
    collection TEXT NOT NULL,
    id TEXT NOT NULL,
    doc JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (collection, id));
"""

_UPSERT = ("INSERT INTO tcc_docs(collection, id, doc, updated_at) "
           "VALUES(%s,%s,%s,now()) ON CONFLICT (collection, id) DO UPDATE "
           "SET doc=EXCLUDED.doc, updated_at=now()")

# Append-only insert: succeeds iff (collection, id) is not already present.
# The (collection, id) PRIMARY KEY makes this atomic on Postgres — a losing
# concurrent insert reports rowcount 0 instead of overwriting.
_INSERT_IF_ABSENT = ("INSERT INTO tcc_docs(collection, id, doc, updated_at) "
                     "VALUES(%s,%s,%s,now()) ON CONFLICT DO NOTHING")

# Atomic compare-and-swap: update only when the stored doc's ``field`` is
# not ``disallowed``. On Postgres this is a single conditional UPDATE (the
# predicate is evaluated against the row as locked by the statement), so a
# concurrent double transition yields rowcount 1 for exactly one caller.
_UPDATE_WHERE_NE = ("UPDATE tcc_docs SET doc=%s, updated_at=now() "
                    "WHERE collection=%s AND id=%s "
                    "AND doc->>'{field}' IS DISTINCT FROM %s")


class _MemBackend:
    kind = "memory"

    def __init__(self) -> None:
        self._d: dict[tuple[str, str], dict] = {}

    def put(self, coll: str, rid: str, doc: dict) -> None:
        self._d[(coll, rid)] = dict(doc)

    def get(self, coll: str, rid: str) -> dict | None:
        d = self._d.get((coll, rid))
        return dict(d) if d is not None else None

    def scan(self, coll: str) -> list[dict]:
        return [dict(v) for (c, _), v in self._d.items() if c == coll]

    def put_if_absent(self, coll: str, rid: str, doc: dict) -> bool:
        if (coll, rid) in self._d:
            return False
        self._d[(coll, rid)] = dict(doc)
        return True

    def update_where_ne(self, coll: str, rid: str, doc: dict,
                        field: str, disallowed: str) -> bool:
        cur = self._d.get((coll, rid))
        if cur is None or cur.get(field) == disallowed:
            return False
        self._d[(coll, rid)] = dict(doc)
        return True


class _PostgresBackend:
    kind = "postgres"

    def __init__(self, dsn: str) -> None:
        import psycopg  # psycopg[binary], imported lazily so dev needs nothing

        self.conn = psycopg.connect(dsn, autocommit=True)
        with self.conn.cursor() as cur:
            cur.execute(_PG_DDL)
        log.info("profile=prod component=store (postgres)")

    def put(self, coll: str, rid: str, doc: dict) -> None:
        with self.conn.cursor() as cur:
            cur.execute(_UPSERT, (coll, rid, json.dumps(doc)))

    def get(self, coll: str, rid: str) -> dict | None:
        with self.conn.cursor() as cur:
            cur.execute("SELECT doc FROM tcc_docs WHERE collection=%s AND id=%s",
                        (coll, rid))
            row = cur.fetchone()
        return dict(row[0]) if row else None

    def scan(self, coll: str) -> list[dict]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT doc FROM tcc_docs WHERE collection=%s "
                        "ORDER BY updated_at, id", (coll,))
            rows = cur.fetchall()
        return [dict(r[0]) for r in rows]

    def put_if_absent(self, coll: str, rid: str, doc: dict) -> bool:
        with self.conn.cursor() as cur:
            cur.execute(_INSERT_IF_ABSENT, (coll, rid, json.dumps(doc)))
            return cur.rowcount == 1

    def update_where_ne(self, coll: str, rid: str, doc: dict,
                        field: str, disallowed: str) -> bool:
        with self.conn.cursor() as cur:
            cur.execute(_UPDATE_WHERE_NE.format(field=field),
                        (json.dumps(doc), coll, rid, disallowed))
            return cur.rowcount == 1


class DocStore:
    """(collection, id) -> JSON document store; same interface on in-memory
    (dev) and Postgres (prod, TCC_DATABASE_URL/DATABASE_URL)."""

    def __init__(self, dsn: str | None = None) -> None:
        self._lock = threading.Lock()
        dsn = dsn if dsn is not None else (
            os.environ.get("TCC_DATABASE_URL") or os.environ.get("DATABASE_URL", ""))
        if dsn:
            try:
                self._b: Any = _PostgresBackend(dsn)
                return
            except Exception as e:  # pragma: no cover - needs real pg
                log.warning("postgres unavailable (%s); falling back to in-memory", e)
        self._b = _MemBackend()
        log.info("profile=dev component=store (in-memory)")

    @property
    def backend(self) -> str:
        return self._b.kind

    def put(self, collection: str, rid: str, doc: dict) -> None:
        with self._lock:
            self._b.put(collection, rid, dict(doc))

    def get(self, collection: str, rid: str) -> dict | None:
        return self._b.get(collection, rid)

    def scan(self, collection: str) -> list[dict]:
        return self._b.scan(collection)

    def put_if_absent(self, collection: str, rid: str, doc: dict) -> bool:
        """Append-only insert; False when (collection, rid) already exists.
        Atomic on both backends (PK conflict on Postgres, store lock in
        memory) — a record created this way is never overwritten."""
        with self._lock:
            return self._b.put_if_absent(collection, rid, dict(doc))

    def update_where_ne(self, collection: str, rid: str, doc: dict,
                        field: str, disallowed: str) -> bool:
        """Compare-and-swap: replace the doc only if its current ``field``
        value is not ``disallowed`` (a missing field counts as allowed).
        False when the record is absent or already in the disallowed state.
        Atomic: one conditional UPDATE on Postgres; the store lock spans
        check+write on the in-memory backend."""
        if not field.isidentifier():
            raise ValueError(f"unsafe field name {field!r}")
        with self._lock:
            return self._b.update_where_ne(collection, rid, dict(doc),
                                           field, disallowed)
