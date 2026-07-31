# ombud

Tax Ombud institutional service (T13i): case registry with lifecycle +
deadlines (rp-procedure-ombud), 20% appeal deposit holds (ledger 500,
rp-deposit-20pct), WORM evidence packs, registry/clerk/member roles,
privilege-filtered search, activation gate on Ombud rules (reg-watch).

## Environment

| Var | Purpose | Dev default |
|---|---|---|
| `PORT` | listen port | 8403 |
| `AUTH_MODE` | `dev` (HS256 + `X-Dev-Role`) or `keycloak` (RS256 JWKS via `packages/authx`) | dev |
| `KEYCLOAK_ISSUER` / `KEYCLOAK_AUDIENCE` / `KEYCLOAK_JWKS_URL` | Keycloak OIDC settings | unset |
| `MERIDIAN_DEV_JWT_SECRET` | dev HMAC secret | meridian-dev-secret |
| `DATABASE_URL` | Postgres (pgx/v5): `ombud_cases` JSONB table, idempotent auto-migrate; docs match the JSON-file schema | unset → JSON files |
| `KAFKA_BROKERS` | comma list (Redpanda) → franz-go emitter (`packages/eventx`); emits `nrs.dispute.ombud.v1` on intake | unset → `outbox.jsonl` embedded bus |
| `OMBUD_DATA_ROOT` | local store root | ./data |
| `LEDGER_URL` | core ledger API | unset → dev TigerBeetle-semantics |
| `AUDIT_EVIDENCE_URL` | core audit-evidence API | unset → local WORM |
| `REG_WATCH_URL` | core reg-watch API | unset → local gate file |
| `PACKS_DIR` | rp-* fallback packs | packs |

## Prod profile

```sh
AUTH_MODE=keycloak KEYCLOAK_ISSUER=https://keycloak:8443/realms/meridian \
DATABASE_URL=postgres://ombud:...@postgres:5432/meridian \
KAFKA_BROKERS=redpanda:9092 go run .
```

Pseudonymisation contract preserved: only `ptin_...` appellant ids are stored
or emitted; raw TINs are rejected at intake.

## Auth note (H-2)

Institutional roles derive from verified token claims (`admin`→registry,
`operator`→clerk, otherwise member). The `X-Ombud-Role` header is honored
**only in `AUTH_MODE=dev`**; in keycloak mode it is ignored. As in the other
gov services, keycloak mode rejects Bearer tokens (and never honors dev
headers) when OIDC is misconfigured — fail closed.
