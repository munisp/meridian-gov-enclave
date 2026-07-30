# analytics

T4 + T15 analytics service (Python FastAPI): lakehouse-lite (bronze/silver/gold
partitioned parquet via DuckDB), feature materialisation, transparent daily
scoring with explanation payloads, rp-disclosure-control k-anonymity checks,
case feed API, MBS taxview ingest, NSW declarations ingest (T15). Gold zone is
pseudonymised (`pseudo_tin`) only.

## Environment

| Var | Purpose | Dev default |
|---|---|---|
| `PORT` | listen port | 8401 |
| `AUTH_MODE` | `dev` (HS256 + `X-Dev-Role`) or `keycloak` (RS256 JWKS, PyJWT[crypto] + PyJWKClient, iss/exp/aud enforced, realm roles mapped) | dev |
| `KEYCLOAK_ISSUER` / `KEYCLOAK_AUDIENCE` / `KEYCLOAK_JWKS_URL` | Keycloak OIDC settings (JWKS URL derived from issuer) | unset |
| `MERIDIAN_DEV_JWT_SECRET` | dev HMAC secret | meridian-dev-secret |
| `TIN_HMAC_KEY` | HMAC key for `pseudo_tin` pseudonymisation | dev key |
| `ANALYTICS_DATA_ROOT` | lakehouse data root | ./data |

## Prod profile

```sh
AUTH_MODE=keycloak KEYCLOAK_ISSUER=https://keycloak:8443/realms/meridian \
uvicorn app.main:app --port 8401
```

Tests: `python -m pytest tests -q` (7 tests).
