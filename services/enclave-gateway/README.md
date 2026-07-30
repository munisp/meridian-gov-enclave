# enclave-gateway

THE audited API gateway for the Meridian sovereign zone (SPEC §5): the sole
north-south path. F1–F8 flows are schema-validated, scope-checked, issued a
synchronous WORM evidence receipt, then dispatched. F9/F10 are forbidden by
construction — no routes exist and the deny middleware rejects their paths
(proven by `TestForbiddenFlowsDenied`).

## Environment

| Var | Purpose | Dev default |
|---|---|---|
| `PORT` | listen port | 8400 |
| `AUTH_MODE` | `dev` (HS256 + `X-Dev-Role`) or `keycloak` (RS256 JWKS) | dev |
| `KEYCLOAK_ISSUER` / `KEYCLOAK_AUDIENCE` / `KEYCLOAK_JWKS_URL` | Keycloak OIDC; audience defaults to `meridian-services` for service-to-service client-credentials tokens | unset |
| `MERIDIAN_DEV_JWT_SECRET` | dev HMAC secret | meridian-dev-secret |
| `GATEWAY_DATA_ROOT` | local WORM/spool/feeds root | ./data |
| `AUDIT_EVIDENCE_URL` | core audit-evidence API for WORM receipts | unset → local WORM |
| `F1..F5_CONSUMER_URL` | enclave consumer APIs per flow | unset → local spool |
| `JRB_URL` / `WHT_RECON_URL` | F7 feed source / F8 recon source | unset → local files |
| `INTERNAL_FLOW_TOKEN` | F6 enclave-internal token | dev-internal-token |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | server TLS | unset → plain HTTP |
| `GATEWAY_MTLS_CA_FILE` | CA pool verifying client certs | unset |
| `GATEWAY_REQUIRE_CLIENT_CERT` | `true` → require-and-verify client certs | false |

## Prod profile (mTLS, H5)

```sh
AUTH_MODE=keycloak \
KEYCLOAK_ISSUER=https://keycloak:8443/realms/meridian \
TLS_CERT_FILE=/etc/meridian/gateway.crt TLS_KEY_FILE=/etc/meridian/gateway.key \
GATEWAY_MTLS_CA_FILE=/etc/meridian/zone-ca.pem GATEWAY_REQUIRE_CLIENT_CERT=true \
go run .
```

- Mutual TLS both directions for sovereign↔market calls; the verified client
  certificate CN (or JWT `sub` without mTLS) is stamped as `X-Meridian-Caller`
  on every request before forwarding to enclave consumers (F1–F5 dispatch,
  F7/F8 upstream reads).
- Client-credentials tokens with `aud=meridian-services` are accepted for
  service-to-service calls in keycloak mode.
- WORM receipt flow is unchanged: receipt BEFORE the consumer sees the message.
