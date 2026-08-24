"""R3 verifier regression (gov #29): one payment_ref could mint unlimited
receipts via distinct idempotency keys (verifier reproduced two 201s, two
RRRs). The payment binding verified existence/amount but never that the
payment was already receipted.

Post-fix: the first successful issuance durably consumes the payment_ref
(PaymentConsumptionStore); a later issuance for the same payment_ref under
ANY idempotency key returns the existing receipt (200), never a second 201.
The binding is restart-safe (durable JSONL).
"""
from __future__ import annotations

import os
import shutil

os.environ["AUTH_MODE"] = "dev"
os.environ["RECEIPTS_WORM_ROOT"] = "/tmp/receipts-test-worm"
os.environ.pop("RECEIPTS_SIGNING_KEY_PEM", None)
os.environ.pop("EVENT_BUS_URL", None)

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)
H = {"X-Dev-Role": "operator"}


def _body(key: str, payment_ref: str) -> dict:
    return {"tin": "12345678-0001", "payer_name": "Ada Lovelace",
            "amount_kobo": 450_000_00, "tax_type": "VAT", "period": "2026-02",
            "payment_channel": "remita", "idempotency_key": key,
            "payment_ref": payment_ref}


def test_same_payment_ref_two_idempotency_keys_one_receipt():
    ref = "PAY-R3-DUP"
    r1 = client.post("/v1/receipts", json=_body("r3-key-1", ref), headers=H)
    assert r1.status_code == 201, r1.text
    # distinct idempotency key, SAME payment_ref -> must not mint again
    r2 = client.post("/v1/receipts", json=_body("r3-key-2", ref), headers=H)
    assert r2.status_code == 200, r2.text
    assert r2.json()["receipt_id"] == r1.json()["receipt_id"]
    assert r2.json()["rrr"] == r1.json()["rrr"]
    assert r2.json()["duplicate_payment_ref"] is True


def test_consumption_survives_restart():
    ref = "PAY-R3-RESTART"
    r1 = client.post("/v1/receipts", json=_body("r3-key-3", ref), headers=H)
    assert r1.status_code == 201, r1.text
    # simulate process restart: rebuild the consumption store from disk
    from app import main as main_mod
    from app.worm import PaymentConsumptionStore
    main_mod.consumption_store = PaymentConsumptionStore(
        main_mod.settings.worm_root)
    try:
        r2 = client.post("/v1/receipts", json=_body("r3-key-4", ref),
                         headers=H)
        assert r2.status_code == 200, r2.text
        assert r2.json()["receipt_id"] == r1.json()["receipt_id"]
    finally:
        main_mod.consumption_store = PaymentConsumptionStore(
            main_mod.settings.worm_root)


def test_distinct_payment_refs_still_issue():
    r1 = client.post("/v1/receipts", json=_body("r3-key-5", "PAY-R3-A"),
                     headers=H)
    r2 = client.post("/v1/receipts", json=_body("r3-key-6", "PAY-R3-B"),
                     headers=H)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["receipt_id"] != r2.json()["receipt_id"]
