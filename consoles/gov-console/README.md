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
