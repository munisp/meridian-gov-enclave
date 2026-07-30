# gov-console

Government consoles for the Meridian sovereign zone (React 18 + TS + Vite + Tailwind).

Sections: NRS console (scoring dashboard with explanation drill-down, case feed,
NSW declarations), JRB console (authorities, EOI inbox with four-party visibility
banner, attribution feeds), state-IRS portal view, Ombud registry console.

## Run

```bash
npm install
npm run dev      # :8404 — proxies /api/{analytics,jrb,ombud,gateway} to :8401-8403/:8400
npm run build    # type-check + production build
```

Login is a dev JWT (HS256) minted in the browser with `VITE_DEV_JWT_SECRET`
(default `meridian-dev-secret`, matching the services' `MERIDIAN_DEV_JWT_SECRET`).
Service base URLs can be overridden with `VITE_ANALYTICS_URL`, `VITE_JRB_URL`,
`VITE_OMBUD_URL`, `VITE_GATEWAY_URL`.

Design: low-saturation warm-neutral palette (sand/clay/moss), no gradients.

## Prod profile (Keycloak OIDC, HARDENING H2)

| Var | Purpose | Dev default |
|---|---|---|
| `VITE_AUTH_MODE` | `keycloak` enables OIDC login | `dev` (dev-token) |
| `VITE_KEYCLOAK_ISSUER` | realm URL, e.g. `https://keycloak:8443/realms/meridian` | unset |
| `VITE_KEYCLOAK_CLIENT_ID` | public client | `gov-console` |

With `VITE_AUTH_MODE=keycloak` the console signs in via oidc-client-ts
(authorization code + PKCE, `src/oidc.ts`). Access tokens live in memory only
(never localStorage) and are renewed silently; realm roles map to the console
roles (admin/operator/auditor). The dev-token login stays the default when the
var is unset.
