"""Persistence-layer tests: a new TccStore on the same DocStore sees prior
applications/certificates (restart durability, audit P0). Runs against the
in-memory backend; Postgres is selected by TCC_DATABASE_URL/DATABASE_URL."""
from __future__ import annotations

import os

os.environ.setdefault("AUTH_MODE", "dev")

from app import core, store  # noqa: E402

NOW = "2026-01-05T09:00:00Z"


def _apply(s: core.TccStore, key="idem-1", app_id="app-1"):
    rec, created = s.apply("12345678-0001", NOW, key, app_id)
    return rec, created


def test_application_survives_reinstantiation():
    docs = store.DocStore(dsn="")
    s1 = core.TccStore(docs)
    rec, created = _apply(s1)
    assert created
    s2 = core.TccStore(docs)  # simulate restart
    assert s2.get("app-1")["status"] == "pending"
    replay, created2 = _apply(s2)
    assert not created2 and replay["application_id"] == rec["application_id"]


def test_decision_and_cert_survive_reinstantiation():
    docs = store.DocStore(dsn="")
    s1 = core.TccStore(docs)
    _apply(s1)
    s1.decide("app-1", now="2026-01-06T09:00:00Z", sla_days=14,
              eligible=True, reasons=[], certificate_id="cert-1",
              ledger_mode="sim")
    s1.register_cert({"certificate_id": "cert-1", "application_id": "app-1",
                      "tin": "12345678-0001"})
    s2 = core.TccStore(docs)
    got = s2.get("app-1")
    assert got["status"] == "issued" and got["certificate_id"] == "cert-1"
    assert s2.cert("cert-1")["tin"] == "12345678-0001"


def test_sla_breaches_read_from_store():
    docs = store.DocStore(dsn="")
    s1 = core.TccStore(docs)
    _apply(s1)
    s2 = core.TccStore(docs)
    breaches = s2.sla_breaches("2026-02-01T09:00:00Z", 14)
    assert len(breaches) == 1
    assert breaches[0]["application_id"] == "app-1"
