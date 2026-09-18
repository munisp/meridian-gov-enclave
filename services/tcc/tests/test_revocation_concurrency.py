"""R4 repair: revocation audit trail must be append-only (no lost updates
under concurrency) and the revoke state transition must be atomic
(exactly one 200 / one 409 on a concurrent double-revoke), on both the
in-memory (dev) and Postgres-shaped (conditional UPDATE / INSERT ...
ON CONFLICT DO NOTHING) backends.
"""
from __future__ import annotations

import threading
import time

import pytest

from app import core, store


class _SlowBackend:
    """In-memory backend with realistic per-op latency (simulates the
    Postgres get/put round-trip the V2 verifier used to win the lost-
    update race)."""

    kind = "memory"

    def __init__(self, delay: float = 0.05) -> None:
        self._m = store._MemBackend()
        self._delay = delay

    def _zz(self) -> None:
        time.sleep(self._delay)

    def put(self, coll, rid, doc):
        self._zz()
        self._m.put(coll, rid, doc)

    def get(self, coll, rid):
        self._zz()
        return self._m.get(coll, rid)

    def scan(self, coll):
        return self._m.scan(coll)

    def put_if_absent(self, coll, rid, doc):
        return self._m.put_if_absent(coll, rid, doc)

    def update_where_ne(self, coll, rid, doc, field, disallowed):
        return self._m.update_where_ne(coll, rid, doc, field, disallowed)


def _docs(delay: float = 0.05) -> store.DocStore:
    docs = store.DocStore(dsn="")
    docs._b = _SlowBackend(delay)
    return docs


def _cert(cid: str, tin: str = "12345678-0001") -> dict:
    return {"certificate_id": cid, "tin": tin, "as_of": "2026-01-01",
            "issued_at": "2026-01-02T00:00:00Z", "years": []}


def _revoke_many(ts: core.TccStore, cid: str, n: int, out: list) -> None:
    def worker(i: int) -> None:
        try:
            ts.revoke_cert(cid, reason=f"fraud discovered {i}",
                           revoked_by="admin", now=f"2026-02-0{i+1}T00:00:00Z")
            out.append("ok")
        except core.TccError:
            out.append("conflict")
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def test_concurrent_revokes_of_different_certs_keep_both_trail_entries():
    """V2 proof: 2 concurrent revokes, 1 trail entry (lost update). The
    append-only trail must retain one durable entry PER revocation."""
    ts = core.TccStore(_docs())
    ts.register_cert(_cert("CERT-A"))
    ts.register_cert(_cert("CERT-B"))
    out: list = []

    def rev(cid, now):
        try:
            ts.revoke_cert(cid, reason="fraud discovered", revoked_by="admin",
                           now=now)
            out.append("ok")
        except core.TccError:
            out.append("conflict")

    threads = [threading.Thread(target=rev, args=("CERT-A", "2026-02-01T00:00:00Z")),
               threading.Thread(target=rev, args=("CERT-B", "2026-02-01T00:00:01Z"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert out == ["ok", "ok"]
    trail = ts.revocations()
    assert {e["certificate_id"] for e in trail} == {"CERT-A", "CERT-B"}
    assert len(trail) == 2  # no lost update


def test_concurrent_double_revoke_same_cert_exactly_one_wins():
    """Atomic transition: N concurrent revokes of ONE cert -> exactly one
    success, N-1 conflicts, and exactly one trail entry."""
    ts = core.TccStore(_docs())
    ts.register_cert(_cert("CERT-X"))
    out: list = []
    _revoke_many(ts, "CERT-X", 8, out)
    assert out.count("ok") == 1
    assert out.count("conflict") == 7
    trail = [e for e in ts.revocations() if e["certificate_id"] == "CERT-X"]
    assert len(trail) == 1
    assert ts.cert("CERT-X")["status"] == "revoked"


def test_trail_is_durable_across_restart_and_append_only():
    """A new DocStore/TccStore over the SAME durable backend (restart)
    still serves the trail; trail records are never overwritten."""
    docs = _docs(delay=0.0)
    ts = core.TccStore(docs)
    ts.register_cert(_cert("CERT-D1"))
    ts.register_cert(_cert("CERT-D2"))
    ts.revoke_cert("CERT-D1", reason="issued in error", revoked_by="admin",
                   now="2026-02-01T00:00:00Z")
    ts.revoke_cert("CERT-D2", reason="fraud discovered", revoked_by="admin",
                   now="2026-02-02T00:00:00Z")

    # "restart": brand-new store facade over the same backend
    docs2 = store.DocStore(dsn="")
    docs2._b = docs._b
    ts2 = core.TccStore(docs2)
    trail = ts2.revocations()
    assert {e["certificate_id"] for e in trail} == {"CERT-D1", "CERT-D2"}
    assert all(e["reason"] and e["revoked_by"] and e["revoked_at"]
               for e in trail)


def test_legacy_single_doc_trail_is_still_served():
    """Deployments that already have the old {entries:[...]} audit doc keep
    those entries visible after the upgrade."""
    docs = _docs(delay=0.0)
    docs.put("tcc_revocations", "audit",
             {"entries": [{"certificate_id": "CERT-OLD", "tin": "t",
                           "reason": "legacy", "revoked_by": "admin",
                           "revoked_at": "2026-01-15T00:00:00Z"}]})
    ts = core.TccStore(docs)
    ts.register_cert(_cert("CERT-NEW"))
    ts.revoke_cert("CERT-NEW", reason="fraud discovered", revoked_by="admin",
                   now="2026-02-01T00:00:00Z")
    ids = {e["certificate_id"] for e in ts.revocations()}
    assert ids == {"CERT-OLD", "CERT-NEW"}


@pytest.mark.parametrize("field", ["status; DROP TABLE tcc_docs", "a'b"])
def test_update_where_ne_rejects_unsafe_field(field):
    docs = store.DocStore(dsn="")
    with pytest.raises(ValueError):
        docs.update_where_ne("tcc_certs", "x", {}, field, "revoked")
