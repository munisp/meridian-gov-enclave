# receipts — official payment e-receipts (NRS TaxPro Max parity)

Python FastAPI (analytics-style conventions). Issues signed, QR-verifiable
e-receipts for tax payments: TIN, payer name, amount (integer kobo), tax
type, period, RRR-style unique reference, payment channel. WORM storage;
public verification; `nrs.receipts.issued.v1` issuance events.

## Honesty tags

| Component | Tag |
|---|---|
| Receipt content model, RRR minting, validation, idempotent issuance | REAL |
| ed25519 sign/verify, QR payload (`NRSRCT1|<rrr>|<amount>|<sig>`) | REAL |
| WORM append-only JSONL with SHA-256 hash chain + tamper detection (`RECEIPTS_WORM_ROOT`; prod must sit on object-locked storage) | REAL |
| Event bus via `EVENT_BUS_URL` (`nrs.receipts.issued.v1` HTTP POST) | REAL |
| Local event outbox when `EVENT_BUS_URL` unset (`event_mode: "sim"`) | SIM |
| Dev ephemeral signing key (`key_mode: "dev-ephemeral"`); prod requires `RECEIPTS_SIGNING_KEY_PEM` (fail-closed, 503) | SIM (dev only) |

## Endpoints

- `POST /v1/receipts` (idempotent by `idempotency_key`) → signed receipt
- `GET /v1/receipts/{id}` → receipt + WORM record hash
- `GET /v1/receipts/verify/{id}` — **public**: signature + WORM chain check
- `GET /v1/receipts/events/outbox` — SIM outbox when no bus is configured

Errors are RFC 7807. Auth per SPEC §1.3 (dev HS256 / X-Dev-Role; keycloak
mode fails closed at this tier).

## Tests

`pip install -r requirements.txt && python -m pytest tests -q`
