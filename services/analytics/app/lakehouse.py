"""Lakehouse: bronze/silver/gold zones behind ONE shared interface (audit I4).

The `Lakehouse` abstract interface is the same contract as core-platform
`ml/data/lakehouse.py` (write/read/sql/datasets/dataset_path, identical
signatures and on-disk conventions); both repos converge on it.

Backend selection (get_lakehouse):
  ICEBERG_REST_URI set   -> IcebergLakehouse: REAL Apache Iceberg tables via
                            the REST catalog on MinIO (pyiceberg, optional
                            import-guarded dependency). Tables: <zone>.<dataset>,
                            one Iceberg snapshot per write.
  otherwise              -> DuckDBLakehouse (dev fallback): hive-partitioned
                            parquet PLUS a local catalog.json manifest
                            (tables, schema versions, snapshots) so Trino/Spark
                            can attach and schema evolution is explicit.

Layout on disk (dev fallback):
    <data_root>/lakehouse/<zone>/<dataset>/dt=<YYYY-MM-DD>/part-<ulid>.parquet
    <data_root>/lakehouse/catalog.json

Zones:
  bronze — raw ingest payloads (enclave-internal; may contain raw TIN)
  silver — conformed/validated records (enclave-internal; may contain raw TIN)
  gold   — derived products; pseudonymised (pseudo_tin only), k-anonymity checked
"""
from __future__ import annotations

import abc
import datetime as dt
import json
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
    """Parquet-on-filesystem implementation queried through DuckDB.

    Every write also records a snapshot in <root>/catalog.json (tables,
    schema versions, snapshots) — the dev-stand-in Iceberg manifest so
    Trino/Spark can attach and schema evolution is tracked (audit I4).
    """

    CATALOG_FILE = "catalog.json"

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self._lock = threading.Lock()
        self._con = duckdb.connect(":memory:")  # parquet support is built-in
        self._catalog = self._load_catalog()

    # -- catalog manifest (dev stand-in for the Iceberg catalog) -----------
    def _catalog_path(self) -> str:
        return os.path.join(self.root, self.CATALOG_FILE)

    def _load_catalog(self) -> dict:
        try:
            with open(self._catalog_path(), encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {"format": "meridian-parquet-catalog/1", "tables": {}}

    def _save_catalog(self) -> None:
        tmp = self._catalog_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._catalog, fh, indent=2, sort_keys=True)
        os.replace(tmp, self._catalog_path())

    def catalog(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._catalog))

    def _record_snapshot(self, zone: str, dataset: str, columns: list[str],
                         snapshot: dict) -> None:
        key = f"{zone}.{dataset}"
        tbl = self._catalog.setdefault("tables", {}).setdefault(key, {
            "zone": zone, "dataset": dataset, "schema_version": 0,
            "columns": columns, "snapshots": []})
        if tbl["columns"] != columns:
            tbl["schema_version"] += 1  # additive evolution bumps the version
            tbl["columns"] = list(dict.fromkeys([*tbl["columns"], *columns]))
        tbl["snapshots"].append(snapshot)

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
            self._record_snapshot(zone, dataset, cols, {
                "id": new_ulid(), "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
                "partition": partition, "files": [fpath], "rows": len(records)})
            self._save_catalog()
        return {"dataset": dataset, "zone": zone, "partition": partition,
                "rows": len(records), "files": [fpath]}

    def read(self, zone: str, dataset: str, where: str | None = None,
             columns: list[str] | None = None, limit: int = 10000) -> list[dict[str, Any]]:
        glob = self._glob(zone, dataset)
        if not _glob_has_files(self._ds_dir(zone, dataset)):
            return []
        col_sql = ", ".join(f'"{c}"' for c in columns) if columns else "*"
        q = f"SELECT {col_sql} FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)"
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
                        f"SELECT count(*) AS n FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)")[0]["n"]
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


class IcebergLakehouse(Lakehouse):
    """Prod backend: REAL Apache Iceberg tables via the REST catalog on MinIO.

    pyiceberg is an optional dependency (import-guarded): this class only
    loads when ICEBERG_REST_URI is set (infra compose ships iceberg-rest).
    Tables are named `<zone>.<dataset>`; every write = one Iceberg snapshot.
    sql() is served by Trino attached to the same catalog, not here.
    """

    def __init__(self, rest_uri: str | None = None, warehouse: str | None = None):
        try:
            from pyiceberg.catalog import load_catalog
        except ImportError as exc:
            raise RuntimeError(
                "ICEBERG_REST_URI is set but pyiceberg is not installed; "
                "pip install 'pyiceberg[pyarrow]' or unset ICEBERG_REST_URI "
                "for the DuckDB/parquet dev fallback") from exc
        self.rest_uri = rest_uri or os.environ["ICEBERG_REST_URI"]
        self.catalog = load_catalog("rest", **{
            "uri": self.rest_uri,
            "warehouse": warehouse or os.environ.get(
                "ICEBERG_WAREHOUSE", "s3://meridian-warehouse/"),
            "s3.endpoint": os.environ.get(
                "MINIO_ENDPOINT_URL", f"http://{os.environ.get('MINIO_ENDPOINT', 'localhost:9000')}"),
            "s3.access-key-id": os.environ.get("MINIO_ACCESS_KEY", "minio"),
            "s3.secret-access-key": os.environ.get("MINIO_SECRET_KEY", "minio123"),
        })

    def _ident(self, zone: str, dataset: str) -> str:
        if zone not in ZONES:
            raise ValueError(f"invalid zone {zone!r}; expected one of {ZONES}")
        return f"{zone}.{dataset.replace('/', '_').replace('..', '_')}"

    def write(self, zone, dataset, records, partition=None):
        if not records:
            return {"dataset": dataset, "zone": zone, "partition": partition,
                    "rows": 0, "files": []}
        import pyarrow as pa
        partition = partition or today()
        rows = [dict(r, dt=partition) for r in records]
        cols: list[str] = []
        for r in rows:
            for k in r:
                if k not in cols:
                    cols.append(k)
        data = {c: [r.get(c) if isinstance(r.get(c), (bool, int, float, str, type(None)))
                    else json.dumps(r.get(c), default=str) for r in rows] for c in cols}
        table = pa.table(data)
        try:
            self.catalog.create_namespace(zone)
        except Exception:  # noqa: BLE001 - already exists
            pass
        ident = self._ident(zone, dataset)
        try:
            tbl = self.catalog.load_table(ident)
        except Exception:  # noqa: BLE001 - not found
            tbl = self.catalog.create_table(ident, schema=table.schema)
        tbl.append(table)  # one Iceberg snapshot per write
        return {"dataset": dataset, "zone": zone, "partition": partition,
                "rows": len(rows), "files": [], "iceberg_table": ident}

    def read(self, zone, dataset, where=None, columns=None, limit=10000):
        tbl = self.catalog.load_table(self._ident(zone, dataset))
        scan = tbl.scan(limit=limit)
        if columns:
            scan = scan.select(*columns)
        if where:
            scan = scan.row_filter(where)
        return scan.to_arrow().to_pylist()

    def sql(self, query):
        raise RuntimeError(
            "sql() over Iceberg tables is served by Trino attached to the "
            "REST catalog (ICEBERG_REST_URI); use Trino's endpoint")

    def datasets(self, zone=None):
        out = []
        for z in ([zone] if zone else list(ZONES)):
            try:
                tables = self.catalog.list_tables(z)
            except Exception:  # noqa: BLE001 - namespace absent
                continue
            for ns, name in tables:
                tbl = self.catalog.load_table(f"{ns}.{name}")
                out.append({"zone": z, "dataset": name,
                            "snapshots": len(tbl.snapshots()),
                            "partitions": None, "files": None, "rows": None})
        return out

    def dataset_path(self, zone, dataset):
        return self.catalog.load_table(self._ident(zone, dataset)).location()


def get_lakehouse(root: str) -> Lakehouse:
    """ICEBERG_REST_URI set -> real Iceberg REST catalog (pyiceberg,
    import-guarded); otherwise the DuckDB parquet+catalog.json dev fallback."""
    if os.environ.get("ICEBERG_REST_URI"):
        return IcebergLakehouse()
    impl = os.environ.get("LAKEHOUSE_IMPL", "duckdb")
    if impl != "duckdb":
        raise RuntimeError(f"LAKEHOUSE_IMPL={impl!r} not available in dev; use 'duckdb' "
                           "or set ICEBERG_REST_URI for the real Iceberg backend")
    return DuckDBLakehouse(root)
