# jrb

Joint Revenue Board service (T11): authority registry (NRS + JRB secretariat +
36 states + FCT, CRUD), authority onboarding, EOI with four-party visibility
(requester + responder + secretariat; any fourth party hard-denied), per-state
adapter framework with `lagos_lirs` + `fct_irs` reference adapters, NTAA
attribution feed builder (30% place-of-consumption, ed25519-signed),
`wf-jrb-*` workflows. Cross-zone sends go ONLY via enclave-gateway F6 with
WORM receipt capture.

## Environment

| Var | Purpose | Dev default |
|---|---|---|
| `PORT` | listen port | 8402 |
| `AUTH_MODE` | `dev` or `keycloak` (RS256 JWKS via `packages/authx`) | dev |
| `KEYCLOAK_ISSUER` / `KEYCLOAK_AUDIENCE` / `KEYCLOAK_JWKS_URL` | Keycloak OIDC settings | unset |
| `MERIDIAN_DEV_JWT_SECRET` | dev HMAC secret | meridian-dev-secret |
| `DATABASE_URL` | Postgres (`postgres://user:pass@host:5432/db`); tables `jrb_authorities`, `jrb_eoi` (JSONB docs, idempotent auto-migrate) | unset → JSON files |
| `KAFKA_BROKERS` | Redpanda brokers (franz-go via `packages/eventx`) | unset → embedded outbox bus |
| `ENCLAVE_GATEWAY_URL` | gateway base URL for F6 sends | unset → simulated receipt |
| `INTERNAL_FLOW_TOKEN` | F6 shared token (mTLS in prod profile) | dev-internal-token |
| `JRB_DATA_ROOT` | data root | ./data |

## Prod profile

```sh
AUTH_MODE=keycloak KEYCLOAK_ISSUER=https://keycloak:8443/realms/meridian \
DATABASE_URL=postgres://jrb:secret@postgres:5432/jrb \
KAFKA_BROKERS=redpanda:9092 ENCLAVE_GATEWAY_URL=https://enclave-gateway:8400 go run .
```

Tests: `go build ./... && go vet ./... && go test -race ./...` (7 tests).
