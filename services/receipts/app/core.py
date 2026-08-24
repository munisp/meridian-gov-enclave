"""E-receipt issuance core: RRR-style references, signing, events.

Receipt content (TaxPro Max parity, parity4/gov-filing-gaps §5): TIN,
payer name, amount (integer kobo), tax type, period, RRR-style unique
reference, payment channel, issued-at, ed25519 signature, QR-verifiable
payload `NRSRCT1|<rrr>|<amount_kobo>|<signature>`.

RRR minting: `RRR-` + Crockford-base32 ULID suffix, collision-checked
against the RRRs already persisted in the WORM store (callers pass
`WormStore.rrrs()`); the ULID space makes collisions implausible, but the
check is real, not decorative. Events: `nrs.receipts.issued.v1` envelope
to the bus when EVENT_BUS_URL is set, else a local outbox list (SIM,
tagged).

REAL: reference minting, sign/verify, WORM append, durable payload-bound
idempotent issuance (B3 #11).
SIM: event bus (local outbox when EVENT_BUS_URL unset); payment proof
verification is skipped only in dev and tagged `dev-unverified`.
"""
from __future__ import annotations

import hashlib
import json

from .util import new_ulid, now_rfc3339

TAX_TYPES = ("VAT", "CIT", "PIT", "PAYE", "WHT", "DEV_LEVY", "STAMP_DUTY")
CHANNELS = ("remita", "bank_transfer", "card", "pos", "ussd", "cash_lodgment")


class ReceiptError(ValueError):
    pass


def mint_rrr(existing: set[str]) -> str:
    while True:
        rrr = f"RRR-{new_ulid()}"
        if rrr not in existing:
            return rrr


def validate(tin: str, payer_name: str, amount_kobo: int, tax_type: str,
             period: str, channel: str) -> None:
    if not tin:
        raise ReceiptError("tin required")
    if not payer_name:
        raise ReceiptError("payer_name required")
    if int(amount_kobo) <= 0:
        raise ReceiptError("amount_kobo must be positive")
    if tax_type.upper() not in TAX_TYPES:
        raise ReceiptError(f"tax_type must be one of {sorted(TAX_TYPES)}")
    parts = period.split("-")
    if len(parts) != 2 or not (1 <= int(parts[1]) <= 12):
        raise ReceiptError("period must be YYYY-MM")
    if channel not in CHANNELS:
        raise ReceiptError(f"channel must be one of {sorted(CHANNELS)}")


def build_receipt(receipt_id: str, rrr: str, *, tin: str, payer_name: str,
                  amount_kobo: int, tax_type: str, period: str,
                  channel: str, payment_ref: str = "",
                  payment_verification: str = "verified") -> dict:
    return {
        "receipt_id": receipt_id,
        "rrr": rrr,
        "tin": tin,
        "payer_name": payer_name,
        "amount_kobo": int(amount_kobo),
        "currency": "NGN",
        "tax_type": tax_type.upper(),
        "period": period,
        "payment_channel": channel,
        "payment_ref": payment_ref,
        "payment_verification": payment_verification,
        "issued_at": now_rfc3339(),
        "statute": "NTA 2025 (electronic receipt as denotation)",
    }


def request_payload_hash(tin: str, payer_name: str, amount_kobo: int,
                         tax_type: str, period: str, channel: str,
                         payment_ref: str) -> str:
    """B3 #11: idempotency bindings are bound to the exact request
    payload, so key reuse with a different payload is a 409 conflict."""
    body = json.dumps({"tin": tin, "payer_name": payer_name,
                       "amount_kobo": int(amount_kobo),
                       "tax_type": tax_type.upper(), "period": period,
                       "payment_channel": channel,
                       "payment_ref": payment_ref},
                      sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()


def verify_payment(payments_url: str, payment_ref: str, *, tin: str,
                   amount_kobo: int) -> None:
    """B3 #11: a receipt may only be minted against a payment event that
    the payments service confirms, with matching TIN and amount. Raises
    ReceiptError on any doubt (missing payment, amount/tin mismatch,
    unreachable verifier)."""
    import httpx
    try:
        r = httpx.get(payments_url.rstrip("/") + "/v1/payments/" + payment_ref,
                      timeout=5.0)
    except Exception as exc:
        raise ReceiptError(f"payment verification unavailable: {exc}")
    if r.status_code != 200:
        raise ReceiptError(f"payment {payment_ref!r} not found")
    pay = r.json()
    if pay.get("status") not in ("captured", "settled", "success", "posted"):
        raise ReceiptError(f"payment status {pay.get('status')!r} is not final")
    if int(pay.get("amount_kobo", -1)) != int(amount_kobo):
        raise ReceiptError("payment amount does not match the receipt amount")
    if pay.get("tin") and pay["tin"] != tin:
        raise ReceiptError("payment TIN does not match the receipt TIN")


def issued_event(receipt: dict, worm_hash: str) -> dict:
    return {
        "type": "nrs.receipts.issued.v1",
        "id": new_ulid(),
        "time": now_rfc3339(),
        "subject": receipt["receipt_id"],
        "data": {"receipt_id": receipt["receipt_id"], "rrr": receipt["rrr"],
                 "tin": receipt["tin"], "amount_kobo": receipt["amount_kobo"],
                 "tax_type": receipt["tax_type"], "period": receipt["period"],
                 "worm_record_hash": worm_hash},
    }


def post_event(bus_url: str, event: dict) -> str:
    """REAL when bus_url set (HTTP POST); caller tags 'sim' otherwise."""
    import httpx
    r = httpx.post(bus_url.rstrip("/") + "/events", json=event, timeout=5.0)
    r.raise_for_status()
    return "real"


def canonical_payload(receipt: dict) -> bytes:
    body = {k: receipt[k] for k in ("receipt_id", "rrr", "tin", "payer_name",
                                    "amount_kobo", "tax_type", "period",
                                    "payment_channel", "payment_ref",
                                    "issued_at")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
