"""WhatsApp Business Cloud channel for Hermes (SPEC D section 0, taxpayer copilot).

- GET  /v1/whatsapp/webhook : Meta webhook verification (hub.mode /
  hub.verify_token / hub.challenge against WHATSAPP_VERIFY_TOKEN; fail-closed
  when the token is unset under PROFILE=prod).
- POST /v1/whatsapp/webhook : inbound messages. X-Hub-Signature-256 is
  HMAC-SHA256 over the RAW body keyed by WHATSAPP_APP_SECRET, compared in
  constant time; mismatch -> 401. 200 fast-ack; agent turn runs as a
  background task. Dedup by Meta message id. Only `text` and `interactive`
  (button reply) messages are processed; everything else is acked + ignored.
- Channel mapping: wa_id -> hermes session (channel="whatsapp"), reusing the
  SAME AgentLoop + guardrails as web/ussd (agent="taxpayer-copilot").
- Outbound: WhatsAppClient (urllib, injectable transport) posts to
  graph.facebook.com/v21.0/{phone_number_id}/messages. When credentials are
  absent it runs in SIM mode: payloads are logged with an honest [SIM] tag
  and a fake message id is returned. No real Meta call is ever made in SIM.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import urllib.request
import uuid
from typing import Any, Callable, Optional

from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from ..agent.loop import AgentLoop, UserContext
from ..agent.memory import MemoryStore
from ..agent.audit import AuditChain
from ..agent.guardrails import redact_text
from ..config import Settings
from .prompts import system_prompt

log = logging.getLogger("hermes.whatsapp")

GRAPH_VERSION = "v21.0"
CONFIRM_PREFIX = "wa_confirm:"
CANCEL_PREFIX = "wa_cancel:"


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def chunk_text(text: str, max_chars: int = 4096) -> list[str]:
    """Split a long answer into <=max_chars chunks (WhatsApp text limit)."""
    text = text or ""
    if len(text) <= max_chars:
        return [text] if text else []
    chunks: list[str] = []
    rest = text
    while len(rest) > max_chars:
        cut = rest.rfind("\n", 0, max_chars)
        if cut < max_chars // 2:
            cut = rest.rfind(" ", 0, max_chars)
        if cut < max_chars // 2:
            cut = max_chars
        chunks.append(rest[:cut].rstrip())
        rest = rest[cut:].lstrip()
    if rest:
        chunks.append(rest)
    return chunks


# ---------------------------------------------------------------------------
# Send client
# ---------------------------------------------------------------------------
Transport = Callable[[str, dict[str, str], bytes], dict[str, Any]]


def _urllib_transport(url: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosec - fixed host
        return json.loads(resp.read().decode())


class WhatsAppClient:
    """Cloud API send client. SIM mode (no access token / phone number id):
    logs the would-be payload with a [SIM] tag and returns a fake id."""

    def __init__(self, access_token: str = "", phone_number_id: str = "",
                 graph_url: str = "https://graph.facebook.com",
                 transport: Optional[Transport] = None):
        self.access_token = access_token
        self.phone_number_id = phone_number_id
        self.graph_url = graph_url.rstrip("/")
        self.transport = transport or _urllib_transport

    @property
    def sim(self) -> bool:
        return not (self.access_token and self.phone_number_id)

    def _post(self, payload: dict[str, Any]) -> str:
        if self.sim:
            fake_id = f"sim-wamid-{uuid.uuid4().hex[:12]}"
            log.info("[SIM] whatsapp send to=%s payload=%s -> %s",
                     payload.get("to"), json.dumps(payload, default=str), fake_id)
            return fake_id
        url = f"{self.graph_url}/{GRAPH_VERSION}/{self.phone_number_id}/messages"
        headers = {"Authorization": f"Bearer {self.access_token}",
                   "Content-Type": "application/json"}
        resp = self.transport(url, headers,
                              json.dumps(payload).encode())
        msgs = resp.get("messages") or []
        return str(msgs[0].get("id", "")) if msgs else ""

    def send_text(self, to: str, body: str) -> str:
        return self._post({"messaging_product": "whatsapp", "to": to,
                           "type": "text", "text": {"body": body}})

    def send_buttons(self, to: str, body: str,
                     buttons: list[tuple[str, str]]) -> str:
        return self._post({
            "messaging_product": "whatsapp", "to": to,
            "type": "interactive",
            "interactive": {
                "type": "button",
                "body": {"text": body[:1024]},
                "action": {"buttons": [
                    {"type": "reply",
                     "reply": {"id": bid, "title": title[:20]}}
                    for bid, title in buttons[:3]]}}})


# ---------------------------------------------------------------------------
# Webhook payload parsing
# ---------------------------------------------------------------------------
def extract_messages(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull processable messages out of a Cloud API webhook payload.

    Returns dicts: {from, id, kind, text} where kind is "text" or "button".
    Status callbacks and non-text/interactive types are skipped."""
    out: list[dict[str, Any]] = []
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            value = change.get("value") or {}
            for msg in value.get("messages") or []:
                mtype = msg.get("type")
                base = {"from": msg.get("from", ""), "id": msg.get("id", "")}
                if mtype == "text":
                    out.append({**base, "kind": "text",
                                "text": (msg.get("text") or {}).get("body", "")})
                elif mtype == "interactive":
                    inter = msg.get("interactive") or {}
                    reply = inter.get("button_reply") or inter.get("list_reply") or {}
                    out.append({**base, "kind": "button",
                                "text": str(reply.get("id", ""))})
                else:
                    log.info("whatsapp: ignoring message type=%s id=%s",
                             mtype, msg.get("id"))
    return out


def verify_signature(app_secret: str, raw_body: bytes, header: str) -> bool:
    """Constant-time check of X-Hub-Signature-256 (HMAC-SHA256 over raw body)."""
    if not app_secret or not header.startswith("sha256="):
        return False
    expected = hmac.new(app_secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header[len("sha256="):])


# ---------------------------------------------------------------------------
# Route wiring
# ---------------------------------------------------------------------------
class _SeenIds:
    """Bounded dedup set for Meta message ids."""

    def __init__(self, capacity: int = 4096):
        self.capacity = capacity
        self._ids: list[str] = []
        self._set: set[str] = set()

    def is_new(self, mid: str) -> bool:
        if not mid:
            return True
        if mid in self._set:
            return False
        self._set.add(mid)
        self._ids.append(mid)
        if len(self._ids) > self.capacity:
            self._set.discard(self._ids.pop(0))
        return True


def add_whatsapp_routes(app: FastAPI, s: Settings, audit: AuditChain,
                        memory: MemoryStore,
                        build_loop: Callable[[str, str], AgentLoop],
                        client: Optional[WhatsAppClient] = None) -> WhatsAppClient:
    if s.profile == "prod" and not s.whatsapp_app_secret:
        raise RuntimeError(
            "hermes whatsapp: PROFILE=prod requires WHATSAPP_APP_SECRET "
            "(fail-closed); refusing to start")
    wa = client or WhatsAppClient(
        access_token=s.whatsapp_access_token,
        phone_number_id=s.whatsapp_phone_number_id,
        graph_url=s.whatsapp_graph_url)
    if wa.sim:
        log.warning("hermes whatsapp: SIM mode (no WHATSAPP_ACCESS_TOKEN/"
                    "WHATSAPP_PHONE_NUMBER_ID) - sends are logged, not delivered")
    if not s.whatsapp_app_secret:
        log.warning("hermes whatsapp: WHATSAPP_APP_SECRET unset; inbound "
                    "signature verification is fail-closed (all POSTs -> 401)")

    sessions: dict[str, dict[str, Any]] = {}   # wa_id -> session state
    app.state.whatsapp_sessions = sessions     # exposed for ops/tests
    seen = _SeenIds()

    def _session(wa_id: str) -> dict[str, Any]:
        st = sessions.get(wa_id)
        if st is None:
            st = {"session_id": str(uuid.uuid4()), "lang": "en", "pending": None}
            sessions[wa_id] = st
        return st

    def _run_agent(wa_id: str, text: str, confirmed: bool = False) -> None:
        st = _session(wa_id)
        lang = st["lang"]
        ctx = UserContext(
            sub=f"wa:{wa_id}", roles=["nrs.taxpayer"], token="",
            agent="taxpayer-copilot", session_id=st["session_id"],
            channel="whatsapp", lang=lang, tin=st.get("tin", ""),
            linked_tins={st["tin"]} if st.get("tin") else set(),
            user_confirmed=confirmed)
        loop = build_loop("taxpayer-copilot", "whatsapp")
        result = loop.run_turn(ctx, text, system_prompt=system_prompt("taxpayer-copilot", lang))
        if result.confirmation_request is not None:
            st["pending"] = {"message": text}
            prompt = redact_text(result.confirmation_request["prompt"])
            wa.send_buttons(wa_id, prompt,
                            [(CONFIRM_PREFIX + st["session_id"], "Confirm"),
                             (CANCEL_PREFIX + st["session_id"], "Cancel")])
            return
        answer = redact_text(result.answer)
        for chunk in chunk_text(answer, s.whatsapp_max_chars):
            wa.send_text(wa_id, chunk)

    def _process(messages: list[dict[str, Any]]) -> None:
        for msg in messages:
            if not seen.is_new(msg["id"]):
                log.info("whatsapp: duplicate message id=%s skipped", msg["id"])
                continue
            wa_id, text = msg["from"], msg["text"]
            if not wa_id or not text:
                continue
            if msg["kind"] == "button":
                st = _session(wa_id)
                if text.startswith(CONFIRM_PREFIX) and st.get("pending"):
                    original = st.pop("pending")["message"]
                    _run_agent(wa_id, original, confirmed=True)
                elif text.startswith(CANCEL_PREFIX):
                    st["pending"] = None
                    wa.send_text(wa_id, "Action cancelled.")
                else:
                    wa.send_text(wa_id, "No pending action to confirm.")
            else:
                _run_agent(wa_id, text)

    @app.get("/v1/whatsapp/webhook")
    def whatsapp_verify(request: Request):
        token = s.whatsapp_verify_token
        q = request.query_params
        if not token:
            if s.profile == "prod":
                log.error("whatsapp verify: WHATSAPP_VERIFY_TOKEN unset in prod (fail-closed)")
                return JSONResponse(status_code=503, content={"detail": "webhook not configured"})
            log.warning("whatsapp verify: WHATSAPP_VERIFY_TOKEN unset (dev); rejecting")
            return JSONResponse(status_code=403, content={"detail": "verify token unset"})
        if q.get("hub.mode") == "subscribe" and hmac.compare_digest(
                q.get("hub.verify_token", ""), token):
            return PlainTextResponse(q.get("hub.challenge", ""))
        return JSONResponse(status_code=403, content={"detail": "verification failed"})

    @app.post("/v1/whatsapp/webhook")
    async def whatsapp_inbound(request: Request, background: BackgroundTasks):
        raw = await request.body()
        sig = request.headers.get("x-hub-signature-256", "")
        if not verify_signature(s.whatsapp_app_secret, raw, sig):
            return JSONResponse(status_code=401, content={"detail": "invalid signature"})
        try:
            payload = json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            return JSONResponse(status_code=400, content={"detail": "invalid payload"})
        messages = extract_messages(payload)
        background.add_task(_process, messages)   # 200 fast-ack
        return {"status": "ok", "accepted": len(messages)}

    return wa
