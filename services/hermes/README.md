# services/hermes (SPEC D — agentic copilots)

Hermes is the enclave agentic copilot service: 5 agents (taxpayer, auditor,
ops/SRE, policy, onboarding) doing tool-use over the platform's APISIX /v1
APIs with hard guardrails, hash-chained audit, and an offline-runnable eval
harness.

## Layout

```
hermes/
  config.py            # env settings + canonical platform endpoint constants
  llm/base.py          # adapter protocol (chat -> tool_calls[])
  llm/ollama.py        # OllamaAdapter: POST {OLLAMA_URL}/api/chat tools= (qwen2.5:32b-instruct)
  llm/rule.py          # RuleAdapter: deterministic offline fallback (responses tagged sim=true)
  agent/tools.py       # pydantic tool schemas + typed REST wrappers (user-token passthrough)
  agent/loop.py        # tool-call loop: max 8 calls/turn, 30s timeout, citations
  agent/guardrails.py  # RBAC, PII redactor (NIN/phone), injection filter, cross-tenant block
  agent/audit.py       # EVERY tool call -> hash-chained record -> Kafka hermes.toolcalls.v1
                       # (7y retention; JSONL fallback when Kafka unreachable)
  agent/memory.py      # session memory TTL 24h, refs not PII (Redis or embedded fallback)
  gateway/main.py      # FastAPI /v1/chat (web + USSD bridge), /healthz /readyz
  gateway/whatsapp.py  # WhatsApp Cloud channel: /v1/whatsapp/webhook (HMAC, dedup,
                       # interactive confirm buttons, SIM send mode) - docs/WHATSAPP.md
  gateway/auth.py      # Keycloak RS256, fail-closed in prod (sibling analytics pattern)
  gateway/prompts.py   # multilingual system prompts (en/ha/yo/ig/pcm)
  eval/cases.py        # 46 real cases (happy / adversarial / groundedness)
  eval/runner.py       # harness: python -m hermes.eval.runner
tests/                 # loop, tools, guardrails, redactor, approval, audit, gateway, eval
```

## LLM strategy

No PII leaves the sovereign zone: inference runs on in-enclave ollama
(`HERMES_LLM_ADAPTER=ollama`, `OLLAMA_URL`, model default
`qwen2.5:32b-instruct`; USSD path uses `qwen2.5:14b`). For dev/CI without
ollama, `HERMES_LLM_ADAPTER=rule` (default) uses a deterministic
intent-matching adapter that emits the SAME tool-call protocol; every
response it produces is tagged `sim: true`.

## Security invariants

- Tool HTTP calls carry the END USER's Keycloak token (`Authorization:
  Bearer <user token>`) — never a service super-token.
- `AUTH_MODE=keycloak` verifies RS256 against the Keycloak JWKS and is
  fail-closed; `PROFILE=prod` disables the dev auth path entirely.
- Action tools (`file_nil_return`, `assemble_evidence`, `draft_finding`,
  `run_runbook`, `save_scenario`, `create_kyc_case`) short-circuit into a
  `confirmation_request` until the user confirms (web dialog / USSD PIN).
- Runbooks are allowlisted; `dry_run=true` is forced on first invocation;
  prod actions need an approver (two-person rule).
- Cross-tenant TIN access is blocked unless case-linked; prompt-injection
  patterns are refused 100%; NIN/phone are masked in all model-visible text.

## Run

```
pip install -r requirements.txt
AUTH_MODE=dev uvicorn hermes.gateway.main:app --port 8405
python -m pytest tests -q
python -m hermes.eval.runner     # gates: accuracy>=90%, refusal 100%, groundedness>=95%
```

USSD answers are truncated to 160 chars (`HERMES_USSD_MAX_CHARS`). The
WhatsApp Business Cloud channel (docs/WHATSAPP.md) verifies Meta webhook
signatures (HMAC-SHA256, fail-closed), dedups by message id, chunks answers
at 4096 chars, delivers confirmation flows as interactive buttons, and runs
the send client in honest `[SIM]` mode when Cloud API creds are absent.
