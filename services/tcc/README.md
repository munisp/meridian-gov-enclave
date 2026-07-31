# tcc — Tax Clearance Certificate issuance (NTAA 2025 s.72)

Python FastAPI (analytics-style conventions). Issues verifiable TCCs:
eligibility = **no outstanding liabilities** (rev360/ledger adapter) +
**3-year disclosure coverage**; statutory **2-week SLA** with breach
alerts; **denial-with-reasons** path; ed25519-signed certificate with
QR-verifiable ID and a public `GET /v1/tcc/verify/{id}`.

## Honesty tags

| Component | Tag |
|---|---|
| Eligibility logic, SLA clock, denial-with-reasons, disclosure model | REAL |
| ed25519 sign/verify, QR payload (`NRSTCC1|...`), public verification | REAL |
| Ledger adapter via `TCC_LEDGER_URL` (fail-closed prod, 503 if unset) | REAL |
| Dev in-memory sim ledger (`SimLedger.seed`, `ledger_mode: "sim"`) | SIM |
| Dev ephemeral signing key (`key_mode: "dev-ephemeral"`); prod requires `TCC_SIGNING_KEY_PEM` | SIM (dev only) |
| SLA breach alert payload (no notification bus wired) | SIM |

## Endpoints

- `POST /v1/tcc/applications` (idempotent by `idempotency_key`) → pending
- `POST /v1/tcc/applications/{id}/decide` → issue certificate or deny with reasons (late decisions flagged `sla_breached`)
- `GET /v1/tcc/applications/{id}`, `GET /v1/tcc/{certificate_id}`
- `GET /v1/tcc/verify/{certificate_id}` — **public**, recomputes signature
- `GET /v1/tcc/sla/breaches` — pending applications past the 14-day s.72 SLA

Errors are RFC 7807. Auth per SPEC §1.3 (dev HS256 / X-Dev-Role; keycloak
mode fails closed at this tier).

## Tests

`pip install -r requirements.txt && python -m pytest tests -q`
