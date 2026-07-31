"""TCC service tests: auth, eligibility, issue/verify, denial-with-reasons,
SLA breach, prod fail-closed."""
from __future__ import annotations

import datetime as dt
import os

os.environ["AUTH_MODE"] = "dev"
os.environ.pop("TCC_LEDGER_URL", None)
os.environ.pop("TCC_SIGNING_KEY_PEM", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import core, ledger  # noqa: E402
from app.main import app, sim_ledger, store  # noqa: E402

client = TestClient(app)
H = {"X-Dev-Role": "operator"}

TIN_OK = "12345678-0001"
TIN_DEBT = "87654321-0001"


def _years(outstanding: int = 0, complete: bool = True, n: int = 3):
    return [{"year": 2023 + i, "total_income_kobo": 50_000_000_00,
             "tax_payable_kobo": 10_000_000_00,
             "tax_paid_kobo": 10_000_000_00 - (outstanding if i == 2 else 0),
             "tax_outstanding_kobo": outstanding if i == 2 else 0,
             "filings_complete": complete} for i in range(n)]


sim_ledger.seed(TIN_OK, _years())
sim_ledger.seed(TIN_DEBT, _years(outstanding=2_500_000_00))


def _apply(tin, key="k1"):
    r = client.post("/v1/tcc/applications", json={"tin": tin,
                                                  "idempotency_key": key}, headers=H)
    assert r.status_code == 201
    return r.json()


def test_health_and_auth():
    assert client.get("/healthz").json()["service"] == "tcc"
    r = client.post("/v1/tcc/applications", json={"tin": "x", "idempotency_key": "z"})
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")


def test_issue_signed_verifiable_certificate():
    rec = _apply(TIN_OK, "k-issue")
    assert rec["status"] == "pending"
    # idempotent replay
    again = client.post("/v1/tcc/applications",
                        json={"tin": TIN_OK, "idempotency_key": "k-issue"}, headers=H)
    assert again.json()["application_id"] == rec["application_id"]
    dec = client.post(f"/v1/tcc/applications/{rec['application_id']}/decide", headers=H)
    assert dec.status_code == 200
    body = dec.json()
    assert body["status"] == "issued"
    assert body["ledger_mode"] == "sim"
    cert = client.get(f"/v1/tcc/{body['certificate_id']}", headers=H).json()
    assert cert["statute"] == "NTAA 2025 s.72"
    assert cert["key_mode"] == "dev-ephemeral"
    assert cert["qr_verification"].startswith("NRSTCC1|")
    assert len(cert["years"]) == 3
    # public verification (no auth header)
    v = client.get(f"/v1/tcc/verify/{body['certificate_id']}")
    assert v.status_code == 200 and v.json()["valid"] is True
    # tampered certificate fails verification
    store.cert(body["certificate_id"])["years"][0]["tax_paid_kobo"] = 1
    assert client.get(f"/v1/tcc/verify/{body['certificate_id']}").json()["valid"] is False
    # double decision rejected
    assert client.post(f"/v1/tcc/applications/{rec['application_id']}/decide",
                       headers=H).status_code == 409


def test_denial_with_reasons():
    rec = _apply(TIN_DEBT, "k-deny")
    dec = client.post(f"/v1/tcc/applications/{rec['application_id']}/decide", headers=H)
    body = dec.json()
    assert body["status"] == "denied"
    assert body["certificate_id"] is None
    assert any("outstanding liability" in r for r in body["denial_reasons"])


def test_eligibility_reasons_unit():
    ok, reasons = core.evaluate_eligibility(_years(), 3)
    assert ok and reasons == []
    ok, reasons = core.evaluate_eligibility(_years(n=2), 3)
    assert not ok and any("2 of required 3" in r for r in reasons)
    ok, reasons = core.evaluate_eligibility(_years(complete=False), 3)
    assert not ok and any("filings incomplete" in r for r in reasons)


def test_sla_breach_alert():
    rec = _apply(TIN_OK, "k-sla")
    # age the application 15 days
    store.get(rec["application_id"])["applied_at"] = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=15)
    ).isoformat().replace("+00:00", "Z")
    r = client.get("/v1/tcc/sla/breaches", headers=H)
    breaches = r.json()["breaches"]
    assert any(b["application_id"] == rec["application_id"] for b in breaches)
    assert r.json()["sla_days"] == 14
    # deciding late flags the breach on the record
    dec = client.post(f"/v1/tcc/applications/{rec['application_id']}/decide", headers=H)
    assert dec.json()["sla_breached"] is True
    # decided applications no longer breach-list
    r2 = client.get("/v1/tcc/sla/breaches", headers=H)
    assert not any(b["application_id"] == rec["application_id"]
                   for b in r2.json()["breaches"])


def test_prod_fail_closed_without_ledger():
    try:
        ledger.get_positions("TIN", 3, ledger_url="", sim=ledger.SimLedger(),
                             prod=True)
        assert False, "expected LedgerUnavailable"
    except ledger.LedgerUnavailable:
        pass


def test_unknown_ids_404_problem_json():
    r = client.get("/v1/tcc/applications/NOPE", headers=H)
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/problem+json")
    assert client.get("/v1/tcc/verify/NOPE").status_code == 404
