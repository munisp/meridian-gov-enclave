# jrb

Joint Revenue Board service (T11): authority registry with mTLS+OIDC
onboarding (dev: cert upload + SHA-256 fingerprint), EOI with four-party
visibility, per-state adapter framework (lagos_lirs, fct_irs), NTAA 30%
attribution feed builder (ed25519-signed), wf-jrb-* workflows. Cross-zone
sends go only via enclave-gateway with WORM receipt capture.

## Environment

| Var | Purpose | Dev default |
|---|---|---|
| `PORT` | listen port | 8402 |
| `AUTH_MODE` | `dev` (HS256 + `X-Dev-Role`) or `keycloak` (RS256 JWKS via `packages/authx`) | dev |
| `KEYCLOAK_ISSUER` / `KEYCLOAK_AUDIENCE` / `KEYCLOAK_JWKS_URL` | Keycloak OIDC settings | unset |
| `MERIDIAN_DEV_JWT_SECRET` | dev HMAC secret | meridian-dev-secret |
| `DATABASE_URL` | Postgres (pgx/v5): `jrb_authorities` + `jrb_eoi` JSONB tables, idempotent auto-migrate; docs match the JSON-file schema | unset → JSON files |
| `KAFKA_BROKERS` | comma list (Redpanda) → franz-go emitter (`packages/eventx`); emits `nrs.jrb.onboard.v1`, `nrs.jrb.attribution.v1` | unset → `outbox.jsonl` embedded bus |
| `JRB_DATA_ROOT` | local store root | ./data |
| `ENCLAVE_GATEWAY_URL` | cross-zone send path | unset → local receipt capture |
| `INTERNAL_FLOW_TOKEN` | F6 internal token | dev-internal-token |
| `PACKS_DIR` | rp-* fallback packs | packs |

## Prod profile

```sh
AUTH_MODE=keycloak KEYCLOAK_ISSUER=https://keycloak:8443/realms/meridian \
DATABASE_URL=postgres://jrb:...@postgres:5432/meridian \
KAFKA_BROKERS=redpanda:9092 go run .
```

Startup logs `profile=prod component=jrb store=postgres` / `bus=kafka`; with
vars unset it logs `profile=dev ...` and runs standalone.
