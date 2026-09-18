"""R4-9b: the tcc_revocations_cert_uniq partial UNIQUE index enforces one
revocation audit record per certificate at the DATABASE layer — the
cross-replica backstop behind the conditional-UPDATE CAS.

Two layers of tests:
  1. construction-proof (always runs): a backend that enforces the same
     unique-per-cert semantics as the index; a concurrent double-revoke
     yields exactly one success and one 'certificate already revoked'
     conflict (-> HTTP 409), and the audit scan returns one record.
  2. live Postgres (TCC_TEST_DATABASE_URL): the real index exists with the
     right predicate, the DDL re-applies idempotently, and a concurrent
     double-revoke over TWO DocStore connections (two replicas) still gives
     exactly one 200-equivalent / one 409-equivalent.
"""
from __future__ import annotations

import os
import threading

import pytest

from app import core, store


class _CertUniqueBackend:
    """In-memory backend that additionally enforces the semantics of
    tcc_revocations_cert_uniq: at most one tcc_revocations doc per
    certificate_id (what the partial UNIQUE index does on Postgres)."""

    kind = "memory"

    def __init__(self) -> None:
        self._m = store._MemBackend()
        self._lock = threading.Lock()

    def put(self, coll, rid, doc):
        self._m.put(coll, rid, doc)

    def get(self, coll, rid):
        return self._m.get(coll, rid)

    def scan(self, coll):
        return self._m.scan(coll)

    def put_if_absent(self, coll, rid, doc):
        with self._lock:
            if coll == "tcc_revocations" and "certificate_id" in doc:
                for existing in self._m.scan("tcc_revocations"):
                    if existing.get("certificate_id") == doc["certificate_id"]:
                        return False  # unique-index conflict
            return self._m.put_if_absent(coll, rid, doc)

    def update_where_ne(self, coll, rid, doc, field, disallowed):
        return self._m.update_where_ne(coll, rid, doc, field, disallowed)


def _cert(cid: str, tin: str = "12345678-0001") -> dict:
    return {"certificate_id": cid, "tin": tin, "as_of": "2026-01-01",
            "issued_at": "2026-01-02T00:00:00Z", "years": []}


def _docs_with(backend) -> store.DocStore:
    docs = store.DocStore(dsn="")
    docs._b = backend
    return docs


def test_cert_unique_backstop_maps_to_conflict():
    """Simulated index: a second audit-record insert for the same cert is
    rejected and surfaced as 'certificate already revoked' (409), not a
    generic audit-write failure (500)."""
    ts = core.TccStore(_docs_with(_CertUniqueBackend()))
    ts.register_cert(_cert("CERT-U"))
    ts.revoke_cert("CERT-U", reason="fraud discovered", revoked_by="admin",
                   now="2026-02-01T00:00:00Z")

    # Bypass the CAS (as a cross-replica race past it would): force a second
    # audit insert for the same cert and expect the 409 mapping.
    cert = ts.cert("CERT-U")
    cert2 = dict(cert)
    cert2["status"] = "active"  # pretend CAS passed on another replica
    docs = ts._docs
    docs._b._m._d[("tcc_certs", "CERT-U")] = cert2  # unwind CAS marker
    with pytest.raises(core.TccError, match="already revoked"):
        ts.revoke_cert("CERT-U", reason="fraud discovered twice",
                       revoked_by="admin", now="2026-02-02T00:00:00Z")

    trail = [e for e in ts.revocations() if e["certificate_id"] == "CERT-U"]
    assert len(trail) == 1  # scan sees exactly one record for the cert


def test_concurrent_double_revoke_with_unique_backstop():
    """N concurrent revokes over the cert-unique backend: exactly one ok,
    N-1 conflicts, exactly one trail record."""
    ts = core.TccStore(_docs_with(_CertUniqueBackend()))
    ts.register_cert(_cert("CERT-C"))
    out: list[str] = []

    def worker(i: int) -> None:
        try:
            ts.revoke_cert("CERT-C", reason=f"fraud discovered {i}",
                           revoked_by="admin", now=f"2026-02-0{i+1}T00:00:00Z")
            out.append("ok")
        except core.TccError:
            out.append("conflict")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert out.count("ok") == 1
    assert out.count("conflict") == 7
    trail = [e for e in ts.revocations() if e["certificate_id"] == "CERT-C"]
    assert len(trail) == 1


# ---------------------------------------------------------------------------
# Live Postgres (skipped unless TCC_TEST_DATABASE_URL is set)
# ---------------------------------------------------------------------------

def _pg_dsn() -> str:
    dsn = os.environ.get("TCC_TEST_DATABASE_URL", "")
    if not dsn:
        pytest.skip("TCC_TEST_DATABASE_URL unset: skipping live-Postgres R4-9b test")
    return dsn


def _wipe(dsn: str) -> None:
    import psycopg
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS tcc_docs")


def test_pg_unique_index_exists_and_idempotent():
    dsn = _pg_dsn()
    _wipe(dsn)
    docs = store.DocStore(dsn=dsn)
    assert docs.backend == "postgres"
    import psycopg
    with psycopg.connect(dsn) as conn:
        row = conn.execute(
            "SELECT indexdef FROM pg_indexes "
            "WHERE indexname = 'tcc_revocations_cert_uniq'").fetchone()
    assert row is not None, "tcc_revocations_cert_uniq index missing"
    indexdef = row[0].decode() if isinstance(row[0], bytes) else row[0]
    assert "certificate_id" in indexdef
    assert "tcc_revocations" in indexdef
    # idempotent: a second startup re-applying the DDL must not fail
    store.DocStore(dsn=dsn)


def test_pg_concurrent_double_revoke_two_replicas():
    """Two DocStore instances (two replicas) over one Postgres: a concurrent
    double-revoke yields exactly one success and one conflict, one trail
    record, and the cert ends revoked."""
    dsn = _pg_dsn()
    _wipe(dsn)
    ts1 = core.TccStore(store.DocStore(dsn=dsn))
    ts2 = core.TccStore(store.DocStore(dsn=dsn))
    ts1.register_cert(_cert("CERT-PG"))
    out: list[str] = []

    def worker(ts, i: int) -> None:
        try:
            ts.revoke_cert("CERT-PG", reason=f"fraud discovered {i}",
                           revoked_by="admin", now=f"2026-02-0{i+1}T00:00:00Z")
            out.append("ok")
        except core.TccError:
            out.append("conflict")

    threads = [threading.Thread(target=worker, args=(ts, i))
               for i, ts in enumerate([ts1, ts2] * 4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert out.count("ok") == 1, out
    assert out.count("conflict") == 7, out
    trail = [e for e in ts1.revocations() if e["certificate_id"] == "CERT-PG"]
    assert len(trail) == 1
    assert ts1.cert("CERT-PG")["status"] == "revoked"


def test_pg_revocation_scan_handles_constraint_and_legacy():
    """The audit scan must keep serving per-cert records alongside the
    legacy single-document trail (which the partial index excludes)."""
    dsn = _pg_dsn()
    _wipe(dsn)
    ts = core.TccStore(store.DocStore(dsn=dsn))
    # legacy trail document (no certificate_id key) coexists with the index
    ts._docs.put("tcc_revocations", "audit",
                 {"entries": [{"certificate_id": "CERT-OLD",
                               "revoked_at": "2025-12-01T00:00:00Z"}]})
    ts.register_cert(_cert("CERT-NEW"))
    ts.revoke_cert("CERT-NEW", reason="fraud discovered", revoked_by="admin",
                   now="2026-02-01T00:00:00Z")
    trail = ts.revocations()
    ids = {e["certificate_id"] for e in trail}
    assert ids == {"CERT-OLD", "CERT-NEW"}
    assert ts.revocation_for("CERT-NEW") is not None
    assert ts.revocation_for("CERT-MISSING") is None
