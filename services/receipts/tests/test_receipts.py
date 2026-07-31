"""Receipts service tests: issuance, content model, RRR, signature +
QR verification, WORM integrity, idempotency, events, RFC7807."""
from __future__ import annotations

import json
import os
import shutil

os.environ["AUTH_MODE"] = "dev"
os.environ["RECEIPTS_WORM_ROOT"] = "/tmp/receipts-test-worm"
os.environ.pop("RECEIPTS_SIGNING_KEY_PEM", None)
os.environ.pop("EVENT_BUS_URL", None)

shutil.rmtree("/tmp/receipts-test-worm", ignore_errors=True)

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app, outbox, worm  # noqa: E402

client = TestClient(app)
H = {"X-Dev-Role": "operator"}

BODY = {"tin": "12345678-0001", "payer_name": "Ada Lovelace",
        "amount_kobo": 450_000_00, "tax_type": "VAT", "period": "2026-02",
        "payment_channel": "remita", "idempotency_key": "pay-1"}


def test_health_ready_auth():
    assert client.get("/healthz").json()["service"] == "receipts"
    r = client.get("/readyz")
    assert r.json()["worm"] == "ok" and r.json()["event_bus"] == "sim-outbox"
    unauth = client.post("/v1/receipts", json=BODY)
    assert unauth.status_code == 401
    assert unauth.headers["content-type"].startswith("application/problem+json")


def test_issue_receipt_content_and_verify():
    r = client.post("/v1/receipts", json=BODY, headers=H)
    assert r.status_code == 201
    rec = r.json()
    assert rec["rrr"].startswith("RRR-")
    assert rec["amount_kobo"] == 450_000_00
    assert rec["tax_type"] == "VAT" and rec["period"] == "2026-02"
    assert rec["payment_channel"] == "remita"
    assert rec["qr_verification"].startswith("NRSRCT1|")
    assert rec["key_mode"] == "dev-ephemeral"
    assert rec["event_mode"] == "sim"
    assert rec["worm_record_hash"]
    # public verification
    v = client.get(f"/v1/receipts/verify/{rec['receipt_id']}")
    assert v.status_code == 200
    assert v.json()["valid"] is True
    assert v.json()["worm_chain_valid"] is True
    # idempotent replay returns the same receipt
    r2 = client.post("/v1/receipts", json=BODY, headers=H)
    assert r2.json()["receipt_id"] == rec["receipt_id"]
    # issuance event recorded
    ev = outbox[-1]
    assert ev["type"] == "nrs.receipts.issued.v1"
    assert ev["data"]["rrr"] == rec["rrr"]
    assert ev["data"]["worm_record_hash"] == rec["worm_record_hash"]


def test_unique_rrr_across_receipts():
    b1 = dict(BODY, idempotency_key="pay-a", period="2026-03")
    b2 = dict(BODY, idempotency_key="pay-b", period="2026-04")
    r1 = client.post("/v1/receipts", json=b1, headers=H).json()
    r2 = client.post("/v1/receipts", json=b2, headers=H).json()
    assert r1["rrr"] != r2["rrr"]


def test_validation_problem_json():
    for bad in [dict(BODY, amount_kobo=0, idempotency_key="x1"),
                dict(BODY, tax_type="LEVY", idempotency_key="x2"),
                dict(BODY, period="2026-13", idempotency_key="x3"),
                dict(BODY, payment_channel="hawk", idempotency_key="x4")]:
        r = client.post("/v1/receipts", json=bad, headers=H)
        assert r.status_code == 422, bad
        assert r.headers["content-type"].startswith("application/problem+json")


def test_worm_tamper_detection():
    r = client.post("/v1/receipts", json=dict(BODY, idempotency_key="pay-t"),
                    headers=H).json()
    assert worm.verify_chain()
    # tamper: rewrite the WORM file flipping an amount
    path = os.path.join("/tmp/receipts-test-worm", "receipts.jsonl")
    lines = open(path).read().splitlines()
    rec = json.loads(lines[-1])
    rec["payload"]["amount_kobo"] = 1
    lines[-1] = json.dumps(rec, sort_keys=True)
    open(path, "w").write("\n".join(lines) + "\n")
    assert not worm.verify_chain()
    v = client.get(f"/v1/receipts/verify/{r['receipt_id']}").json()
    assert v["worm_chain_valid"] is False
    # restore pristine WORM for other tests
    shutil.rmtree("/tmp/receipts-test-worm", ignore_errors=True)
    os.makedirs("/tmp/receipts-test-worm", exist_ok=True)
    assert client.get("/readyz").json()["worm"] == "ok"


def test_unknown_receipt_404():
    r = client.get("/v1/receipts/verify/RCT-NOPE")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/problem+json")
