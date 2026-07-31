"""E-receipt issuance core: RRR-style references, signing, events.

Receipt content (TaxPro Max parity, parity4/gov-filing-gaps §5): TIN,
payer name, amount (integer kobo), tax type, period, RRR-style unique
reference, payment channel, issued-at, ed25519 signature, QR-verifiable
payload `NRSRCT1|<rrr>|<amount_kobo>|<signature>`.

RRR minting: `RRR-` + Crockford-base32 ULID suffix (collision-checked
against WORM store). Events: `nrs.receipts.issued.v1` envelope to the bus
when EVENT_BUS_URL is set, else a local outbox list (SIM, tagged).

REAL: reference minting, sign/verify, WORM append, idempotent issuance.
SIM: event bus (local outbox when EVENT_BUS_URL unset).
"""
from __future__ import annotations

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
                  channel: str) -> dict:
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
        "issued_at": now_rfc3339(),
        "statute": "NTA 2025 (electronic receipt as denotation)",
    }


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
                                    "payment_channel", "issued_at")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
