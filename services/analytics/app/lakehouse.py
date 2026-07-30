"""Lakehouse-lite: bronze/silver/gold zones as partitioned parquet via DuckDB.

Dev stand-in for Iceberg/Trino (SPEC section 5, T4). The `Lakehouse` abstract
interface is what all callers use; an Iceberg/Trino-backed implementation can be
swapped in via the `LAKEHOUSE_IMPL` env var without touching call sites.

Layout on disk:
    <data_root>/lakehouse/<zone>/<dataset>/dt=<YYYY-MM-DD>/part-<ulid>.parquet

Zones:
  bronze — raw ingest payloads (enclave-internal; may contain raw TIN)
  silver — conformed/validated records (enclave-internal; may contain raw TIN)
  gold   — derived products; pseudonymised (pseudo_tin only), k-anonymity checked
"""
from __future__ import annotations

import abc
import datetime as dt
import os
import threading
from typing import Any

import duckdb

from .util import new_ulid, today

ZONES = ("bronze", "silver", "gold")


class Lakehouse(abc.ABC):
    """Zone/dataset/partition storage interface (swap point for Iceberg/Trino)."""

    @abc.abstractmethod
    def write(self, zone: str, dataset: str, records: list[dict[str, Any]],
              partition: str | None = None) -> dict[str, Any]:
        """Append records to a daily partition. Returns write receipt."""

    @abc.abstractmethod
    def read(self, zone: str, dataset: str, where: str | None = None,
             columns: list[str] | None = None, limit: int = 10000) -> list[dict[str, Any]]:
        """Read records from a dataset (all partitions unless filtered)."""

    @abc.abstractmethod
    def sql(self, query: str) -> list[dict[str, Any]]:
        """Arbitrary DuckDB SQL over the lakehouse (power users / features)."""

    @abc.abstractmethod
    def datasets(self, zone: str | None = None) -> list[dict[str, Any]]:
        """List datasets with partition and row counts."""

    @abc.abstractmethod
    def dataset_path(self, zone: str, dataset: str) -> str:
        """Filesystem glob root for a dataset (for SQL FROM clauses)."""


class DuckDBLakehouse(Lakehouse):
    """Parquet-on-filesystem implementation queried through DuckDB."""

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self._lock = threading.Lock()
        self._con = duckdb.connect(":memory:")  # parquet support is built-in

    # -- internal helpers -------------------------------------------------
    def _ds_dir(self, zone: str, dataset: str) -> str:
        if zone not in ZONES:
            raise ValueError(f"invalid zone {zone!r}; expected one of {ZONES}")
        safe = dataset.replace("/", "_").replace("..", "_")
        return os.path.join(self.root, zone, safe)

    def dataset_path(self, zone: str, dataset: str) -> str:
        return os.path.join(self._ds_dir(zone, dataset), "dt=*", "*.parquet")

    def _glob(self, zone: str, dataset: str) -> str:
        return self.dataset_path(zone, dataset).replace("\\", "/")

    # -- Lakehouse API -----------------------------------------------------
    def write(self, zone: str, dataset: str, records: list[dict[str, Any]],
              partition: str | None = None) -> dict[str, Any]:
        if not records:
            return {"dataset": dataset, "zone": zone, "partition": partition,
                    "rows": 0, "files": []}
        partition = partition or today()
        part_dir = os.path.join(self._ds_dir(zone, dataset), f"dt={partition}")
        os.makedirs(part_dir, exist_ok=True)
        fname = f"part-{new_ulid()}.parquet"
        fpath = os.path.join(part_dir, fname).replace("\\", "/").replace("'", "''")
        # Normalise records: every row gets identical column set (union of keys).
        # Nested dicts/lists are JSON-encoded (bronze raw payloads stay queryable
        # via DuckDB json functions). Money is integer kobo (BIGINT).
        import json as _json

        cols: list[str] = []
        for r in records:
            for k in r.keys():
                if k not in cols:
                    cols.append(k)

        def _type_of(c: str) -> str:
            sample = next((r.get(c) for r in records if r.get(c) is not None), None)
            if isinstance(sample, bool):
                return "BOOLEAN"
            if isinstance(sample, int):
                return "BIGINT"
            if isinstance(sample, float):
                return "DOUBLE"
            return "VARCHAR"

        def _val(v: Any):
            if v is None or isinstance(v, (bool, int, float, str)):
                return v
            if isinstance(v, (dt.date, dt.datetime)):
                return v.isoformat()
            return _json.dumps(v, default=str)  # nested dates etc. -> ISO strings

        tmp = f"_batch_{new_ulid().lower()}"
        col_defs = ", ".join(f'"{c}" {_type_of(c)}' for c in cols)
        placeholders = ", ".join(["?"] * len(cols))
        rows = [[_val(r.get(c)) for c in cols] for r in records]
        with self._lock:
            cur = self._con.cursor()  # thread-local cursor (DuckDB concurrency rule)
            try:
                cur.execute(f'CREATE TEMP TABLE "{tmp}" ({col_defs})')
                cur.executemany(f'INSERT INTO "{tmp}" VALUES ({placeholders})', rows)
                cur.execute(f"COPY \"{tmp}\" TO '{fpath}' (FORMAT PARQUET, COMPRESSION ZSTD)")
            finally:
                cur.execute(f'DROP TABLE IF EXISTS "{tmp}"')
                cur.close()
        return {"dataset": dataset, "zone": zone, "partition": partition,
                "rows": len(records), "files": [fpath]}

    def read(self, zone: str, dataset: str, where: str | None = None,
             columns: list[str] | None = None, limit: int = 10000) -> list[dict[str, Any]]:
        glob = self._glob(zone, dataset)
        if not _glob_has_files(self._ds_dir(zone, dataset)):
            return []
        col_sql = ", ".join(f'"{c}"' for c in columns) if columns else "*"
        q = f"SELECT {col_sql} FROM read_parquet('{glob}', hive_partitioning=true)"
        if where:
            q += f" WHERE {where}"
        q += f" LIMIT {int(limit)}"
        return self.sql(q)

    def sql(self, query: str) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._con.cursor()  # thread-local cursor
            try:
                cur.execute(query)
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
            finally:
                cur.close()

    def datasets(self, zone: str | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        zones = [zone] if zone else list(ZONES)
        for z in zones:
            zdir = os.path.join(self.root, z)
            if not os.path.isdir(zdir):
                continue
            for ds in sorted(os.listdir(zdir)):
                dpath = os.path.join(zdir, ds)
                if not os.path.isdir(dpath):
                    continue
                parts, files, rows = [], 0, None
                for entry in sorted(os.listdir(dpath)):
                    if entry.startswith("dt="):
                        parts.append(entry[3:])
                        pdir = os.path.join(dpath, entry)
                        files += sum(1 for f in os.listdir(pdir) if f.endswith(".parquet"))
                if files:
                    glob = self._glob(z, ds)
                    rows = self.sql(
                        f"SELECT count(*) AS n FROM read_parquet('{glob}', hive_partitioning=true)")[0]["n"]
                out.append({"zone": z, "dataset": ds, "partitions": parts,
                            "files": files, "rows": rows})
        return out


def _glob_has_files(ds_dir: str) -> bool:
    if not os.path.isdir(ds_dir):
        return False
    for entry in os.listdir(ds_dir):
        pdir = os.path.join(ds_dir, entry)
        if os.path.isdir(pdir) and any(f.endswith(".parquet") for f in os.listdir(pdir)):
            return True
    return False


def get_lakehouse(root: str) -> Lakehouse:
    impl = os.environ.get("LAKEHOUSE_IMPL", "duckdb")
    if impl != "duckdb":
        raise RuntimeError(f"LAKEHOUSE_IMPL={impl!r} not available in dev; use 'duckdb' "
                           "(Iceberg/Trino adapters plug in behind the Lakehouse interface)")
    return DuckDBLakehouse(root)
