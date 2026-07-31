# meridian-gov-enclave

Sovereign-zone services for the **Meridian TaxTech platform** (Nigerian NRS unified
tax platform). This repo is deliberately separate (sovereignty boundary): it holds
the government enclave services, the audited cross-zone API gateway, and the
government consoles. Contract: `SPEC.md` §5 (this repo pins core contracts v1).

## Architecture

```
            Market Zone / external rails
                      │  (sole north-south path)
        ┌─────────────▼──────────────┐
        │  services/enclave-gateway  │  F1–F8 audited flows, schema validate →
        │  (Go, :8400)               │  scope check → synchronous WORM receipt
        │  F9/F10 FORBIDDEN          │  → dispatch. F9/F10 denied by construction.
        └─────────────┬──────────────┘
                      │ enclave-internal (F6 EOI)
   ┌──────────────────┼─────────────────────┬───────────────────┐
   ▼                  ▼                     ▼                   ▼
services/analytics  services/jrb         services/ombud   services/hermes
(Python, :8401)     (Go, :8402)          (Go, :8403)      (Python, :8405)
T4+T15 lakehouse    T11 authority        T13i case        agentic copilots
+ scoring + NSW     registry, EOI,       registry,        (SPEC D) + core:
customs products    adapters, NTAA       deposits (500),  tin-graph, ledger,
                    attribution feeds    evidence packs   audit-evidence,
                                                          reg-watch consumed
                                                          via HTTP when URLs
                                                          set; local fallbacks
                                                          otherwise)
                      │
        services/hermes (Python FastAPI, :8405): SPEC D agentic copilots
        (taxpayer / auditor / ops / policy / onboarding), ollama tool-use,
        guardrailed + hash-chained audit to hermes.toolcalls.v1
        consoles/gov-console (React 18 + TS + Vite + Tailwind, :8404)
        NRS console · JRB console · state-IRS portal view · Ombud registry
```

### services/analytics (T4 + T15, Python FastAPI)

- **Lakehouse-lite**: bronze/silver/gold zones as date-partitioned parquet via
  DuckDB (`app/lakehouse.py`). Interface is named `Lakehouse` so an Iceberg/Trino
  implementation can be swapped in (`LAKEHOUSE_IMPL` env). Gold zone stores
  `pseudo_tin` only (HMAC-SHA256 with `TIN_HMAC_KEY`, SPEC §1.3).
- **Ingest**: `POST /ingest/mbs/taxview`, `POST /ingest/filings-mou`,
  `POST /ingest/cac/registry`, `POST /ingest/import-vat/declarations`,
  `POST /ingest/nsw/declarations` (T15: validated bronze → silver
  `customs_declarations` with importer-TIN reconciliation vs core tin-graph API
  (local fallback) → gold `import_vat_landing_cost` product, VAT 7.5%).
- **Features**: `fv_filing_divergence_30d`, `fv_import_mismatch_ytd`,
  `fv_graph_risk_90d` (`POST /v1/features/materialise`).
- **Scoring**: transparent additive rule+score model (`app/scoring.py`); every
  score has a mandatory explanation payload (`GET /v1/scores/{ptin}/explanation`)
  with per-rule points, narrative, evidence, model + rule-pack versions.
- **Disclosure control**: `rp-disclosure-control` (embedded fallback pack)
  k-anonymity (k=5) + dominance rule enforced on aggregate outputs
  (`GET /v1/aggregates/risk-by-band` — small cells suppressed).
- **Workflows** (in-proc dev runner, Temporal-shaped): `wf-daily-scoring`,
  `wf-entity-resolution`, `wf-feature-filing-divergence|import-mismatch|graph-risk`.
- **Case feed**: `GET /v1/cases/feed` in the `nrs.cases.feed.v1` envelope shape
  (SPEC §1.1).

### services/jrb (T11, Go)

- `authority_registry` CRUD seeded with NRS, JRB secretariat, 36 states + FCT.
- Authority onboarding: dev = PEM cert upload + SHA-256 fingerprint; prod = mTLS
  both directions + OIDC (notes recorded on the authority record).
- **EOI** with four-party visibility enforced in the store (requester +
  responder + secretariat; ANY fourth party hard-denied — proven in tests).
- Per-state adapter framework (`StateAdapter`) with `lagos_lirs` and `fct_irs`
  reference adapters (simulated) + generic fallback covering all states.
- **Attribution feed builder**: NTAA 30% place-of-consumption from
  `rp-attribution-formula` (embedded fallback pack), residual 70% split
  equality/derivation; ed25519-signed output; gateway F7 verifies before serving.
- `wf-jrb-onboard|route|reconcile|eoi|joint-audit|cert-rotate|single-filing|attribution-publish`.
- Cross-zone sends **only** via enclave-gateway F6 with WORM receipt capture
  (`GatewayClient`); local simulated receipt when gateway unset (tagged).

### services/ombud (T13 institutional, Go)

- Case registry: intake → `received → acknowledged → under_review → hearing →
  decided → closed` (sequential), deadlines from `rp-procedure-ombud`
  (ack 7d, decide 90d).
- **Deposit tracker**: 20% of disputed amount (`rp-deposit-20pct`) as a hold on
  ledger 500 via the core ledger API (`LEDGER_URL`) or the dev in-memory
  TigerBeetle-semantics client (codes 5 settle / 6 hold / 7 release).
- **Evidence packs**: canonical case file → WORM (core audit-evidence API or
  tamper-evident local fallback with chained manifest).
- Packs loaded with embedded fallback: `rp-procedure-ombud`, `rp-procedure-tat`,
  `rp-ntaa-penalties`, `rp-deposit-20pct`.
- Roles `registry | clerk | member` (dev: `X-Ombud-Role`); members decide;
  privilege-filtered search (dev index; privileged docs hidden from
  non-privileged roles).
- **Activation gate** on Ombud rules: reg-watch API (`REG_WATCH_URL`) or local
  gate file fallback; decisions/deposits refused (503) while gate is off.

### services/enclave-gateway (Go) — THE audited gateway

- Endpoints: `POST /flows/f1/ubl-preclearance-invoices`, `/f2/b2c-reports`,
  `/f3/carf-messages`, `/f4/etr-gir-filings`, `/f5/presumptive-remittances`;
  `GET /flows/f7/attribution-feeds/{state}` (ed25519 signature verified before
  serving); `GET /flows/f8/wht-credit-recon?pseudo_tin=` (pseudonymised only,
  every read logged to `read-audit.log`); `GET /v1/receipts` (admin).
- Pipeline per accepted message: schema validate (embedded dev subsets of the
  relevant rp-*) → Permify-style scope check → **synchronous WORM evidence
  receipt BEFORE the enclave consumer sees the message** → dispatch to consumer
  API (local spool fallback).
- F6 EOI is enclave-internal (shared token in dev; mTLS in prod profile).
- **F9/F10 forbidden by construction**: no routes exist; deny middleware rejects
  any `/flows/f9|f10*` path with 403; a test proves no receipt is ever issued.

### consoles/gov-console (React 18 + TS + Vite + Tailwind)

NRS console (scoring dashboard with explanation drill-down, case feed, NSW
declarations), JRB console (authorities, EOI inbox with visibility banner,
attribution feeds), state-IRS portal view (filings + attribution), Ombud
registry console (cases, deposits, evidence packs). Dev JWT minted in the
browser (HS256, `MERIDIAN_DEV_JWT_SECRET`). Low-saturation warm-neutral design
(sand/clay/moss), no gradients.


## Dev run

```bash
# analytics (Python 3.12)
cd services/analytics
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8401          # or: python -m app.main
pytest tests/ -q

# Go services (Go 1.23+, toolchain at $HOME/sdk/go/bin/go)
cd services/enclave-gateway && go build ./... && go test ./... && go run .   # :8400
cd services/jrb             && go build ./... && go test ./... && go run .   # :8402
cd services/ombud           && go build ./... && go test ./... && go run .   # :8403

# console (Node 20)
cd consoles/gov-console
npm install && npm run build
npm run dev                                # :8404, proxies /api/* to services
```

Auth in dev: `X-Dev-Role: admin|operator|auditor` header or HS256 JWT with
`MERIDIAN_DEV_JWT_SECRET` (SPEC §1.3). `docker-compose.yml` runs all four
services + console build.

## Simulated vs real (honesty tags)

| Component | Status |
|---|---|
| Lakehouse (DuckDB parquet) | REAL dev stand-in; Iceberg/Trino swap point behind `Lakehouse` interface |
| Scoring engine + explanations | REAL (deterministic rule+score, audit trail per score) |
| k-anonymity / dominance suppression | REAL (rp-disclosure-control embedded fallback) |
| tin-graph reconciliation | REAL interface; local file-backed fallback when `TIN_GRAPH_URL` unset |
| WORM evidence (gateway + ombud) | REAL interface; local fallback is append-only + sha256 chained manifest (**simulated immutability**; prod uses object-lock via core audit-evidence) |
| Ledger 500 deposit holds | REAL interface; dev in-memory TigerBeetle semantics (**simulated**; real when `LEDGER_URL` set) |
| State IRS adapters (lagos_lirs, fct_irs) | **SIMULATED** reference adapters behind `StateAdapter` |
| Attribution feed math + ed25519 signing | REAL (dev keypair persisted; prod HSM ceremony) |
| EOI four-party visibility | REAL (store-level enforcement, tested) |
| F9/F10 denial | REAL (no code path + deny middleware + test) |
| Reg-watch gate (ombud) | REAL interface; local gate file fallback (**simulated** reg-watch) |
| mTLS | Documented prod profile; dev uses JWT + cert fingerprint onboarding |
| Workflow runners | REAL in-proc runners (Temporal dev fallback per SPEC §1.1) |

## Production hardening (HARDENING.md)

Every real integration is env-selected; the dev fallback keeps working with
zero config. Startup never fails because a prod var is missing; each selection
logs `profile=dev|prod component=<name>`.

### Environment variables (H1 contract)

| Var | Services | Purpose | Dev default |
|---|---|---|---|
| `AUTH_MODE` | all | `dev` (HS256 + `X-Dev-Role`) or `keycloak` (RS256 JWKS) | dev |
| `KEYCLOAK_ISSUER` | all | OIDC issuer, e.g. `https://keycloak:8443/realms/meridian` | unset |
| `KEYCLOAK_AUDIENCE` | all | expected `aud`; enclave-gateway defaults to `meridian-services` (s2s client-credentials) | unset |
| `KEYCLOAK_JWKS_URL` | all | JWKS endpoint; derived from issuer when unset | derived |
| `MERIDIAN_DEV_JWT_SECRET` | all | dev-mode HMAC secret | `meridian-dev-secret` |
| `DATABASE_URL` | jrb, ombud | `postgres://user:pass@host:5432/db` (pgx/v5, JSONB docs matching the JSON-file schemas, idempotent auto-migrate) | unset → JSON files |
| `KAFKA_BROKERS` | jrb, ombud | comma list (Redpanda); franz-go producer/consumer (`packages/eventx`) | unset → embedded outbox bus |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | enclave-gateway | server TLS | unset → plain HTTP |
| `GATEWAY_MTLS_CA_FILE` | enclave-gateway | CA pool for client-cert verification | unset |
| `GATEWAY_REQUIRE_CLIENT_CERT` | enclave-gateway | `true` → require-and-verify client certs (sovereign↔market mTLS) | false |
| `VITE_AUTH_MODE` | gov-console | `keycloak` enables oidc-client-ts PKCE login | `dev` (dev-token) |
| `VITE_KEYCLOAK_ISSUER` / `VITE_KEYCLOAK_CLIENT_ID` | gov-console | Keycloak realm URL / public client (`gov-console`) | unset / `gov-console` |

### Prod profile

- **Auth (H2)**: `packages/authx` — RS256 against Keycloak JWKS (5-min cache,
  refresh on unknown kid), iss/exp/aud enforced, `realm_access.roles` → roles.
  Python analytics mirrors it with PyJWT[crypto] + PyJWKClient. Dev mode is
  unchanged (HS256 + `X-Dev-Role`).
- **mTLS (H5)**: enclave-gateway with `TLS_CERT_FILE`/`TLS_KEY_FILE` +
  `GATEWAY_REQUIRE_CLIENT_CERT=true` requires and verifies client certificates;
  the verified cert CN (or JWT sub) is stamped as `X-Meridian-Caller` before
  forwarding to enclave consumers. F9/F10 remain forbidden by construction
  (middleware test proves no route matches).
- **Storage (H3)**: `DATABASE_URL` switches jrb/ombud stores to Postgres
  (`jrb_authorities`, `jrb_eoi`, `ombud_cases`; JSONB docs, auto-migrated).
- **Bus (H3)**: `KAFKA_BROKERS` switches the emitter (`packages/eventx`) to
  franz-go (SPEC 1.1 envelope, nrs.* topics); unset → `outbox.jsonl` embedded bus.
- **Console**: `VITE_AUTH_MODE=keycloak` → authorization-code + PKCE login via
  oidc-client-ts, tokens in memory only (never localStorage), silent renew.

### CI

`.github/workflows/ci.yml` (copy at `ci/workflows/ci.yml`, see `ci/README.md`):
Go build/vet/`go test -race` per module, pytest for analytics, `npm ci` +
`tsc` + build for gov-console.

## Hardening + innovations (branch feature/inclusion-hardening)
- FIX: prod fail-closed — Config.Validate refuses non-dev AUTH_MODE without TLS cert pair and an explicit INTERNAL_FLOW_TOKEN; dev defaults applied only in dev.
- I19 (REAL): sovereign audit-ledger cross-anchoring — POST /v1/audit/anchors folds the WORM manifest chain into a Merkle root and appends an HMAC-sealed, hash-chained anchor record (ANCHOR_HMAC_KEY; ANCHOR_LEDGER_URL optional external endpoint); GET /v1/audit/anchors/verify re-verifies seals, chain linkage and chain-tip coverage. Tamper test included.
- I20 (REAL): NDPA consent-receipt data-sharing gateway — POST /v1/share/disclose requires a valid consent receipt (local store; SIMULATED — prod wires CONSENT_STORE_URL) or statutory basis, enforces per-agency minimisation allowlists and k=5 anonymity, and writes a full disclosure log (GET /v1/share/disclosures).
