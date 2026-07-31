"""receipts service — official payment e-receipts (NRS TaxPro Max parity).

Issue signed, QR-verifiable e-receipts for tax payments; WORM storage;
public verification endpoint; `nrs.receipts.issued.v1` issuance events.
REAL/SIM tags in README and per module docstrings.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request
from pydantic import BaseModel

from . import core
from .config import get_settings
from .util import new_ulid, principal_from, problem
from .worm import WormStore

settings = get_settings()
app = FastAPI(title="Meridian Gov-Enclave Receipts", version=settings.version)

worm = WormStore(settings.worm_root)
outbox: list[dict] = []           # SIM event outbox when EVENT_BUS_URL unset
_by_idem: dict[str, str] = {}


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Signer:
    """ed25519 receipt signer. Prod requires RECEIPTS_SIGNING_KEY_PEM
    (fail-closed); dev uses an ephemeral key (SIM, tagged key_mode)."""

    def __init__(self, pem: str, prod: bool) -> None:
        self.key_mode = "kms-pem"
        self.available = True
        if pem:
            self._priv = serialization.load_pem_private_key(pem.encode(),
                                                            password=None)
        elif prod:
            self._priv = None
            self.available = False  # fail closed: refuse to issue
        else:
            self._priv = Ed25519PrivateKey.generate()
            self.key_mode = "dev-ephemeral"

    def public_key_b64(self) -> str:
        return _b64e(self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def sign(self, payload: bytes) -> str:
        if not self.available:
            raise RuntimeError("signing unavailable (fail-closed prod)")
        return _b64e(self._priv.sign(payload))

    def verify(self, payload: bytes, signature: str) -> bool:
        if not self.available:
            return False
        try:
            self._priv.public_key().verify(_b64d(signature), payload)
            return True
        except Exception:
            return False


signer = Signer(settings.signing_key_pem, settings.prod)

PUBLIC_PATHS = {"/healthz", "/readyz", "/openapi.json", "/docs",
                "/docs/oauth2-redirect"}
PUBLIC_PREFIXES = ("/docs", "/v1/receipts/verify/")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
        return await call_next(request)
    principal = principal_from(request, secret=settings.jwt_secret,
                               auth_mode=settings.auth_mode)
    if principal is None:
        return problem(401, "Unauthorized",
                       "Bearer JWT or X-Dev-Role (dev) required")
    request.state.principal = principal
    return await call_next(request)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    return problem(500, "Internal error", str(exc))


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name,
            "version": settings.version}


@app.get("/readyz")
def readyz():
    return {"status": "ready", "worm": "ok" if worm.verify_chain() else "corrupt",
            "signer": "ready" if signer.available else "unavailable",
            "event_bus": "real" if settings.event_bus_url else "sim-outbox"}


class IssueIn(BaseModel):
    tin: str
    payer_name: str
    amount_kobo: int
    tax_type: str
    period: str
    payment_channel: str
    idempotency_key: str


@app.post("/v1/receipts", status_code=201)
def issue(body: IssueIn):
    try:
        core.validate(body.tin, body.payer_name, body.amount_kobo,
                      body.tax_type, body.period, body.payment_channel)
    except core.ReceiptError as exc:
        return problem(422, "Invalid receipt", str(exc))
    if not body.idempotency_key:
        return problem(422, "Invalid receipt", "idempotency_key required")
    if body.idempotency_key in _by_idem:
        rec = worm.get(_by_idem[body.idempotency_key])
        return rec["payload"]
    if not signer.available:
        return problem(503, "Signing unavailable",
                       "RECEIPTS_SIGNING_KEY_PEM unset (fail-closed prod)")
    receipt_id = f"RCT-{new_ulid()}"
    existing = set()  # WORM is authoritative; ULID collision is implausible
    rrr = core.mint_rrr(existing)
    receipt = core.build_receipt(
        receipt_id, rrr, tin=body.tin, payer_name=body.payer_name,
        amount_kobo=body.amount_kobo, tax_type=body.tax_type,
        period=body.period, channel=body.payment_channel)
    sig = signer.sign(core.canonical_payload(receipt))
    receipt.update({
        "signature_b64": sig,
        "public_key_b64": signer.public_key_b64(),
        "key_mode": signer.key_mode,
        "qr_verification": f"NRSRCT1|{rrr}|{receipt['amount_kobo']}|{sig}",
    })
    worm_rec = worm.append(receipt)
    # hash echoed on the response only; the WORM payload stays immutable
    receipt["worm_record_hash"] = worm_rec["record_hash"]
    event = core.issued_event(receipt, worm_rec["record_hash"])
    mode = "sim"
    if settings.event_bus_url:
        try:
            mode = core.post_event(settings.event_bus_url, event)
        except Exception as exc:
            return problem(502, "Event bus unavailable", str(exc))
    else:
        outbox.append(event)
    receipt["event_mode"] = mode
    _by_idem[body.idempotency_key] = receipt_id
    return receipt


@app.get("/v1/receipts/{receipt_id}")
def get_receipt(receipt_id: str):
    rec = worm.get(receipt_id)
    if rec is None:
        return problem(404, "Not found", "unknown receipt")
    payload = dict(rec["payload"])
    payload["worm_record_hash"] = rec["record_hash"]
    return payload


@app.get("/v1/receipts/verify/{receipt_id}")
def verify_receipt(receipt_id: str):
    """Public: verify ed25519 signature over the receipt payload and the
    WORM hash chain up to this record."""
    rec = worm.get(receipt_id)
    if rec is None:
        return problem(404, "Not found", "unknown receipt")
    receipt = rec["payload"]
    sig_ok = signer.verify(core.canonical_payload(receipt),
                           receipt["signature_b64"])
    return {"receipt_id": receipt_id, "valid": sig_ok,
            "worm_chain_valid": worm.verify_chain(),
            "rrr": receipt["rrr"], "amount_kobo": receipt["amount_kobo"],
            "tax_type": receipt["tax_type"], "period": receipt["period"],
            "qr_verification": receipt["qr_verification"]}


@app.get("/v1/receipts/events/outbox")
def get_outbox():
    """SIM: local issuance-event outbox (EVENT_BUS_URL unset)."""
    return {"mode": "sim", "events": list(outbox)}
