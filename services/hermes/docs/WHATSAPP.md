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
- Dedup by Meta message id (bounded in-memory set, 4096 ids). Only `text`
  and `interactive` (button/list reply) messages are processed; statuses and
  media are acked and ignored.
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

## REAL vs SIM

| Capability                              | Status |
|-----------------------------------------|--------|
| Webhook verification (GET)              | REAL, tested |
| X-Hub-Signature-256 HMAC verify (POST)  | REAL, tested (accept/reject/tamper) |
| Dedup, fast-ack, async processing       | REAL, tested |
| Agent loop + guardrails (injection, cross-tenant, confirmation) | REAL, tested — identical to web/ussd |
| Interactive confirm/cancel buttons      | REAL payloads, tested with injected transport |
| Meta message delivery (send)            | SIM unless `WHATSAPP_ACCESS_TOKEN` + `WHATSAPP_PHONE_NUMBER_ID` are set; SIM sends are logged with a `[SIM]` tag and return a fake `sim-wamid-*` id — no real Meta call is made |

## Tests

`tests/test_whatsapp.py` — 16 tests, fully offline (transport injected):
verify ok/bad/unset token, prod fail-closed start, HMAC accept/wrong-secret/
tampered/missing-header, dedup, non-text filtering, text->reply->send with
URL/headers asserted, chunking, confirm-buttons->tap->action proceeds, cancel,
SIM-mode logging, injection refusal + cross-tenant block on the channel.
