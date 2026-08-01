# Hermes WhatsApp Business Cloud channel

Taxpayer-copilot access over WhatsApp using the Meta WhatsApp Business Cloud
API. The channel reuses the SAME `AgentLoop` and guardrails as the web/USSD
channels (`channel="whatsapp"`, agent `taxpayer-copilot`); multilingual
system prompts (en/ha/yo/ig/pcm) come from the session language unchanged.

## Endpoints

| Method | Path                    | Purpose |
|--------|-------------------------|---------|
| GET    | /v1/whatsapp/webhook    | Meta webhook verification (`hub.mode`, `hub.verify_token`, `hub.challenge`) |
| POST   | /v1/whatsapp/webhook    | Inbound messages; HMAC-verified, 200 fast-ack, async processing |

Security:

- POST requires `X-Hub-Signature-256`: HMAC-SHA256 over the **raw** request
  body keyed by `WHATSAPP_APP_SECRET`, compared in constant time. Mismatch or
  missing header -> 401. No signature secret configured -> every POST is
  rejected (fail-closed).
- `PROFILE=prod` with `WHATSAPP_APP_SECRET` unset: the service **refuses to
  start** (`RuntimeError`). Dev profile starts but all POSTs fail closed.
- GET verification compares `hub.verify_token` to `WHATSAPP_VERIFY_TOKEN`
  (constant time); unset token is rejected (503 in prod, 403 in dev).
- Dedup by Meta message id (Redis `SET NX PX` with 48h TTL when `REDIS_URL`
  is set and reachable; bounded in-memory set, 4096 ids, otherwise). Only
  `text` and `interactive` (button/list reply) messages are processed;
  statuses and media are acked and ignored.
- Session state (wa_id -> session) and TIN bindings use the same Redis /
  in-memory-fallback pattern; session TTL is 24h (matches
  `agent/memory.py`). Fallbacks log an honest line (`REDIS_URL unset` /
  `unreachable ... falling back to in-memory`).

## TIN-binding onboarding (NDPA)

WhatsApp has no logged-in user, so TIN-scoped tools require a verified
wa_id <-> TIN binding first (this closes the previous empty-user-token
residual — bound turns carry a scoped session token):

1. An unbound number that sends a TIN-scoped request (obligations,
   estimates/liability, nil filing, calendar — anything needing a TIN)
   gets an onboarding prompt. General questions (e.g. "What is VAT?")
   remain answerable without binding.
2. The user replies with their TIN (`NNNNNNNN-NNNN`). Format + weighted
   mod-11 check digit (12th digit) are validated locally, mirroring the
   services/wht validator.
3. A 6-digit OTP is issued (default 10-minute TTL, 3 attempts then
   lockout) and delivered through the `OtpSender` seam: the REAL
   `HttpOtpSender` posts to the notification service
   (`{NOTIFICATION_URL}/v1/send`, channel `sms`, template `wa_otp`,
   one retry on 5xx) and fails closed with an honest "couldn't send the
   verification code" reply; the dev fallback `SimOtpSender` logs the
   code with an honest `[SIM]` tag.
4. On success the binding `{wa_id, tin, consent_ref, ts}` is persisted
   with an NDPA consent note, and a scoped session token is minted via
   the `TokenIssuer` seam and attached to the AgentLoop context. The
   REAL `IdentityTokenIssuer` exchanges the verified binding at
   `{IDENTITY_URL}/v1/whatsapp/exchange` (`{wa_id, tin, consent_ref}`
   -> `{access_token, ttl}`); the exchange is fail-closed (no token, no
   binding). The dev fallback `SimTokenIssuer` returns a `wa-sim-*`
   token with an honest log.

Commands (case-insensitive):

- `STATUS` — shows the bound TIN masked (`12******-**19`) + consent ref.
- `UNLINK` — removes the binding, withdraws consent, disables TIN-scoped
  tools for the number.

Guardrail parity: a bound user may use TIN-scoped tools for THEIR bound
TIN only; requests naming any other TIN are still refused
(`Cross-tenant access denied`), and prompt-injection refusals are
unchanged (bound or not).
- Answers are PII-redacted and chunked at `WHATSAPP_MAX_CHARS` (default
  4096, the WhatsApp text limit). Action-tool `confirmation_request`s are
  delivered as interactive buttons [Confirm/Cancel]; tapping a button routes
  its id payload back and the original action proceeds (or is cancelled).

## Meta app setup

1. Create a Meta app at https://developers.facebook.com/apps (type: Business)
   and add the **WhatsApp** product.
2. Note the **App Secret** (App Settings > Basic) -> `WHATSAPP_APP_SECRET`.
3. In WhatsApp > API Setup, note the **Phone number ID** ->
   `WHATSAPP_PHONE_NUMBER_ID`, and create a permanent **system-user access
   token** with `whatsapp_business_messaging` -> `WHATSAPP_ACCESS_TOKEN`.
4. WhatsApp > Configuration > Webhook: callback URL
   `https://<gateway-host>/v1/whatsapp/webhook`, verify token = your
   `WHATSAPP_VERIFY_TOKEN`. Subscribe to the `messages` field.
5. Route traffic: expose the hermes service (default :8405) via the APISIX
   gateway / ingress so Meta can reach both GET and POST.

## Environment variables

| Var                       | Required (prod) | Purpose |
|---------------------------|-----------------|---------|
| WHATSAPP_VERIFY_TOKEN     | yes             | webhook verification shared secret |
| WHATSAPP_APP_SECRET       | yes (fail-closed) | HMAC-SHA256 key for X-Hub-Signature-256 |
| WHATSAPP_ACCESS_TOKEN     | for real sends  | Cloud API bearer token |
| WHATSAPP_PHONE_NUMBER_ID  | for real sends  | sender phone number id |
| WHATSAPP_GRAPH_URL        | no              | default `https://graph.facebook.com` (API version v21.0 pinned in code) |
| WHATSAPP_MAX_CHARS        | no              | outbound chunk size, default 4096 |
| REDIS_URL                 | recommended     | session/binding/dedup stores; in-memory fallback (honest log) when unset/unreachable |
| WHATSAPP_SESSION_TTL_S    | no              | session TTL, default 86400 (24h) |
| WHATSAPP_DEDUP_TTL_S      | no              | message-id dedup TTL, default 172800 (48h) |
| WHATSAPP_OTP_TTL_S        | no              | onboarding OTP TTL, default 600 (10 min) |
| WHATSAPP_OTP_MAX_ATTEMPTS | no              | OTP attempts before lockout, default 3 |
| NOTIFICATION_URL          | yes (fail-closed) | notification-service base URL; REAL OTP delivery via `POST {url}/v1/send` (`HttpOtpSender`); unset in dev -> SIM with honest log |
| OTP_SEND_TIMEOUT_S        | no              | OTP send timeout, default 5 (one retry on 5xx) |
| IDENTITY_URL              | yes (fail-closed) | identity-service base URL; REAL token exchange via `POST {url}/v1/whatsapp/exchange` (`IdentityTokenIssuer`); unset in dev -> SIM with honest log |
| IDENTITY_EXCHANGE_TIMEOUT_S | no            | token-exchange timeout, default 10 |

`PROFILE=prod` requires both `NOTIFICATION_URL` and `IDENTITY_URL` when the
WhatsApp channel is active — otherwise the service refuses to start
(`RuntimeError`, fail-closed; SIM onboarding is never allowed in prod).
Dev profile falls back to `SimOtpSender` / `SimTokenIssuer` with honest
`SIM` log lines. Both REAL clients fail closed at runtime too: an OTP
delivery failure drops the challenge and tells the user "couldn't send the
verification code ... try again"; a token-exchange failure aborts the
binding (nothing persisted) and asks the user to resend their TIN.

## REAL vs SIM

| Capability                              | Status |
|-----------------------------------------|--------|
| Webhook verification (GET)              | REAL, tested |
| X-Hub-Signature-256 HMAC verify (POST)  | REAL, tested (accept/reject/tamper) |
| Dedup, fast-ack, async processing       | REAL, tested (Redis SET NX PX 48h, in-memory fallback; dedup survives restart with Redis) |
| Session / binding stores                | REAL (Redis) with tested in-memory fallback when `REDIS_URL` unset/unreachable |
| Agent loop + guardrails (injection, cross-tenant, confirmation) | REAL, tested — identical to web/ussd |
| TIN format + check-digit validation     | REAL, tested (mirrors services/wht local validator) |
| Onboarding state machine (prompt, TIN, OTP verify, lockout, UNLINK, STATUS) | REAL, tested |
| Binding record + NDPA consent ref       | REAL, tested |
| OTP delivery                            | REAL when `NOTIFICATION_URL` set (`HttpOtpSender` -> `POST /v1/send`, sms `wa_otp` template, 5xx retry once, fail-closed); SIM (`SimOtpSender` logs `[SIM]`) as dev fallback; prod requires the URL (fail-closed start) |
| Scoped session token                    | REAL when `IDENTITY_URL` set (`IdentityTokenIssuer` -> `POST /v1/whatsapp/exchange` `{wa_id, tin, consent_ref}` -> `{access_token, ttl}`, fail-closed); SIM (`wa-sim-*` via `SimTokenIssuer`) as dev fallback; prod requires the URL (fail-closed start) |
| Interactive confirm/cancel buttons      | REAL payloads, tested with injected transport |
| Meta message delivery (send)            | SIM unless `WHATSAPP_ACCESS_TOKEN` + `WHATSAPP_PHONE_NUMBER_ID` are set; SIM sends are logged with a `[SIM]` tag and return a fake `sim-wamid-*` id — no real Meta call is made |

## Tests

`tests/test_whatsapp.py` — 36 tests, fully offline (transport injected):
verify ok/bad/unset token, prod fail-closed start, HMAC accept/wrong-secret/
tampered/missing-header, dedup, non-text filtering, text->reply->send with
URL/headers asserted, chunking, confirm-buttons->tap->action proceeds, cancel,
SIM-mode logging, injection refusal + cross-tenant block on the channel;
onboarding happy path (TIN -> OTP -> bound -> liability tool runs with the
scoped token), invalid TIN, wrong OTP, expiry, 3-attempt lockout, UNLINK,
STATUS masking, other-TIN block for bound users, Redis stores via injected
fake client, unreachable/unset `REDIS_URL` fallback log lines, and dedup
across a simulated restart.

`tests/test_wa_clients.py` — 19 tests, fully offline (transports injected):
`HttpOtpSender` success payload, 5xx retry-once, 5xx-twice fail, 4xx no
retry, timeout, missing base URL; `IdentityTokenIssuer` success payload +
token, 401, network error, missing `access_token`, missing base URL; wiring
(REAL selection when URLs set, dev SIM fallback log lines, prod fail-closed
start without either URL, prod start with both); end-to-end onboarding over
the real-impl classes with fake transports (OTP delivered via notification
payload, code reply, identity exchange asserted, binding token + consent_ref
match), OTP-delivery failure (honest reply, challenge dropped), and
token-exchange failure (binding aborted, nothing persisted).
