# packages/otelx (gov-enclave)

Mirror of `meridian-core-platform/packages/events/otelx` implementing the
OTel design contract (`otel-foundation/DESIGN-CONTRACT.md`) for the gov
enclave. Env vars, attribute names (`tenant.id`, `http.route`,
`deployment.environment`), span conventions (SERVER `<METHOD> <route>`,
CLIENT `<METHOD> <host><path>`, W3C tracecontext+baggage propagation),
sampling (`OTEL_TRACES_SAMPLER_ARG`, parent-based head sampling) and the
fail-soft rule (no endpoint => no-op providers; `PROFILE=prod` without an
endpoint logs a loud warning and continues) are identical to core.

- `InitProviders(ctx)` / `InitProvidersWith(ctx, cfg)` — env-driven bootstrap
- `otelx.Middleware(next)` — server spans with `tenant.id` resolution
  (`X-Meridian-Tenant` -> `X-Tenant-ID` -> unverified `tenant_id` JWT claim
  (telemetry only, never authz) -> inbound baggage) and baggage mirroring
- `otelx.Client(rt)` — outbound RoundTripper injecting
  traceparent/tracestate/baggage
- `otelx.TenantAttr(tenant)` / `otelx.TenantKey`

Cardinality ban-list (never span attributes): taxpayer TIN, account numbers,
amounts, names, emails.
