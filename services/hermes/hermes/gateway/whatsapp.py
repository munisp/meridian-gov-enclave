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
import re
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
from .wa_onboarding import (IdentityExchangeError, OtpDeliveryError, OtpManager,
                            OtpSender, SimOtpSender, SimTokenIssuer,
                            TokenIssuer, WaStores, build_wa_stores, mask_tin,
                            new_binding, valid_tin, TIN_RE)

log = logging.getLogger("hermes.whatsapp")

GRAPH_VERSION = "v21.0"
CONFIRM_PREFIX = "wa_confirm:"
CANCEL_PREFIX = "wa_cancel:"

_OTP_RE = re.compile(r"^\d{6}$")
# Heuristic: requests that need a bound TIN (TIN-scoped tools). General
# questions (e.g. "What is VAT?") stay answerable without binding.
_TIN_SCOPED_RE = re.compile(
    r"\bTIN\b|obligation|what do i owe|owe\b|estimate|liability|"
    r"file (a )?nil|nil return|calendar|due date|deadline", re.IGNORECASE)

ONBOARDING_PROMPT = (
    "Nigeria Revenue Service (NRS) taxpayer channel. To check your "
    "outstanding liabilities, filing deadlines or e-invoice (IRN) status "
    "here, link your TIN (Tax Identification Number) to this WhatsApp "
    "number. Reply with your TIN (format NNNNNNNN-NNNN). We'll verify it "
    "with a one-time code. Your consent is recorded per NDPA; send UNLINK "
    "anytime to remove the link.")


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
def add_whatsapp_routes(app: FastAPI, s: Settings, audit: AuditChain,
                        memory: MemoryStore,
                        build_loop: Callable[[str, str], AgentLoop],
                        client: Optional[WhatsAppClient] = None,
                        stores: Optional[WaStores] = None,
                        otp: Optional[OtpManager] = None,
                        otp_sender: Optional[OtpSender] = None,
                        token_issuer: Optional[TokenIssuer] = None) -> WhatsAppClient:
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

    # Stores: Redis when REDIS_URL is reachable, honest in-memory fallback.
    stores = stores or build_wa_stores(
        redis_url=s.redis_url, session_ttl_s=s.whatsapp_session_ttl_s,
        dedup_ttl_s=s.whatsapp_dedup_ttl_s)
    otp = otp or OtpManager(ttl_s=s.whatsapp_otp_ttl_s,
                            max_attempts=s.whatsapp_otp_max_attempts)
    otp_sender = otp_sender or SimOtpSender()
    token_issuer = token_issuer or SimTokenIssuer()
    app.state.whatsapp_sessions = stores.sessions   # exposed for ops/tests
    app.state.whatsapp_stores = stores

    def _session(wa_id: str) -> dict[str, Any]:
        st = stores.sessions.get(wa_id)
        if st is None:
            st = {"session_id": str(uuid.uuid4()), "lang": "en", "pending": None}
            stores.sessions.put(wa_id, st)
        return st

    def _save(wa_id: str, st: dict[str, Any]) -> None:
        stores.sessions.put(wa_id, st)

    def _apply_binding(wa_id: str, st: dict[str, Any]) -> bool:
        """Mirror a persisted binding into the session. Returns bound?"""
        b = stores.binding.get(wa_id)
        if b is None:
            return bool(st.get("tin"))   # ops/test-seeded session TIN
        st["tin"], st["token"] = b.tin, b.token
        _save(wa_id, st)
        return True

    def _run_agent(wa_id: str, text: str, confirmed: bool = False) -> None:
        st = _session(wa_id)
        lang = st["lang"]
        ctx = UserContext(
            sub=f"wa:{wa_id}", roles=["nrs.taxpayer"],
            token=st.get("token", ""),
            agent="taxpayer-copilot", session_id=st["session_id"],
            channel="whatsapp", lang=lang, tin=st.get("tin", ""),
            linked_tins={st["tin"]} if st.get("tin") else set(),
            user_confirmed=confirmed)
        loop = build_loop("taxpayer-copilot", "whatsapp")
        result = loop.run_turn(ctx, text, system_prompt=system_prompt("taxpayer-copilot", lang))
        if result.confirmation_request is not None:
            st["pending"] = {"message": text}
            _save(wa_id, st)
            prompt = redact_text(result.confirmation_request["prompt"])
            wa.send_buttons(wa_id, prompt,
                            [(CONFIRM_PREFIX + st["session_id"], "Confirm"),
                             (CANCEL_PREFIX + st["session_id"], "Cancel")])
            return
        answer = redact_text(result.answer)
        for chunk in chunk_text(answer, s.whatsapp_max_chars):
            wa.send_text(wa_id, chunk)

    def _onboard_text(wa_id: str, st: dict[str, Any], text: str) -> bool:
        """TIN-binding onboarding for unbound numbers. Returns True when the
        message was consumed by the onboarding/command flow."""
        cmd = text.strip()
        upper = cmd.upper()

        if upper == "UNLINK":
            if stores.binding.get(wa_id) is not None or st.get("tin"):
                stores.binding.delete(wa_id)
                st["tin"], st["token"] = "", ""
                _save(wa_id, st)
                wa.send_text(wa_id, "Your TIN link has been removed and your "
                                    "NDPA consent withdrawn. TIN-scoped NRS "
                                    "services (liabilities, filings, e-invoice "
                                    "status) are now disabled for this number.")
            else:
                wa.send_text(wa_id, "No TIN is linked to this WhatsApp number.")
            return True

        if upper == "STATUS":
            b = stores.binding.get(wa_id)
            if b is not None:
                wa.send_text(wa_id, f"Bound TIN: {mask_tin(b.tin)} "
                                    f"(consent ref {b.consent_ref}). "
                                    "Send UNLINK to remove the link.")
            elif st.get("tin"):
                wa.send_text(wa_id, f"Bound TIN: {mask_tin(st['tin'])}")
            else:
                wa.send_text(wa_id, "No TIN is linked to this WhatsApp number. "
                                    + ONBOARDING_PROMPT)
            return True

        bound = _apply_binding(wa_id, st)
        if not bound:
            # OTP challenge outstanding -> expect the 6-digit code. (Track via
            # session flag so an expired challenge still yields an honest
            # "expired" reply instead of falling through to the agent.)
            if st.get("onboarding_tin"):
                if not _OTP_RE.match(cmd):
                    wa.send_text(wa_id, "Please reply with the 6-digit code we "
                                        "sent you to finish linking your TIN.")
                    return True
                outcome = otp.verify(wa_id, cmd)
                if outcome == "ok":
                    ch_tin = st.get("onboarding_tin", "")
                    binding = new_binding(wa_id, ch_tin, "")
                    try:
                        binding.token = token_issuer.issue(
                            wa_id, ch_tin, binding.consent_ref)
                    except IdentityExchangeError as e:
                        # Fail-closed: no binding without a scoped token.
                        st.pop("onboarding_tin", None)
                        _save(wa_id, st)
                        log.error("whatsapp: binding aborted, token exchange "
                                  "failed wa_id=%s: %s", wa_id, e)
                        wa.send_text(wa_id, "We couldn't complete the TIN link "
                                            "right now - please send your TIN "
                                            "again to retry.")
                        return True
                    stores.binding.put(binding)
                    st["tin"], st["token"] = binding.tin, binding.token
                    st.pop("onboarding_tin", None)
                    _save(wa_id, st)
                    log.info("whatsapp: TIN bound wa_id=%s tin=%s consent_ref=%s",
                             wa_id, mask_tin(binding.tin), binding.consent_ref)
                    wa.send_text(wa_id, f"TIN {mask_tin(binding.tin)} is now linked "
                                        "to this number. You can now ask about "
                                        "your outstanding liabilities, upcoming "
                                        "filing deadlines (VAT/WHT 21st, PAYE "
                                        "10th), e-invoice (IRN) status and "
                                        "refunds. Send STATUS to view the link "
                                        "or UNLINK to remove it.")
                elif outcome == "wrong":
                    wa.send_text(wa_id, "That code is incorrect. Please try again "
                                        f"({otp.max_attempts} attempts allowed).")
                elif outcome == "locked":
                    st.pop("onboarding_tin", None)
                    _save(wa_id, st)
                    wa.send_text(wa_id, "Too many incorrect codes. For your "
                                        "security the linking attempt was "
                                        "cancelled - send your TIN again to "
                                        "restart.")
                else:  # expired / no_challenge
                    st.pop("onboarding_tin", None)
                    _save(wa_id, st)
                    wa.send_text(wa_id, "That code has expired. Send your TIN "
                                        "again to get a new code.")
                return True

            # TIN submission -> validate + issue OTP.
            if TIN_RE.match(cmd):
                if not valid_tin(cmd):
                    wa.send_text(wa_id, "That TIN is not valid (NRS format "
                                        "NNNNNNNN-NNNN with check digit). "
                                        "Please check the number on your TIN "
                                        "certificate and resend.")
                    return True
                code = otp.start(wa_id, cmd)
                st["onboarding_tin"] = cmd
                _save(wa_id, st)
                try:
                    otp_sender.send_otp(wa_id, code, otp.ttl_s)
                except OtpDeliveryError as e:
                    # Fail-closed: drop the challenge, tell the user honestly.
                    otp.cancel(wa_id)
                    st.pop("onboarding_tin", None)
                    _save(wa_id, st)
                    log.error("whatsapp: OTP delivery failed wa_id=%s: %s", wa_id, e)
                    wa.send_text(wa_id, "We couldn't send the verification code "
                                        "right now - please try again.")
                    return True
                wa.send_text(wa_id, "NRS TIN verification: we've sent you a "
                                    "6-digit verification code "
                                    f"(valid {otp.ttl_s // 60} minutes). Reply "
                                    "with the code to link your TIN.")
                return True

            # TIN-scoped request from an unbound number -> onboarding prompt.
            if _TIN_SCOPED_RE.search(text):
                wa.send_text(wa_id, ONBOARDING_PROMPT)
                return True
        return False

    def _process(messages: list[dict[str, Any]]) -> None:
        for msg in messages:
            if not stores.dedup.is_new(msg["id"]):
                log.info("whatsapp: duplicate message id=%s skipped", msg["id"])
                continue
            wa_id, text = msg["from"], msg["text"]
            if not wa_id or not text:
                continue
            if msg["kind"] == "button":
                st = _session(wa_id)
                _apply_binding(wa_id, st)
                if text.startswith(CONFIRM_PREFIX) and st.get("pending"):
                    original = st.pop("pending")["message"]
                    _save(wa_id, st)
                    _run_agent(wa_id, original, confirmed=True)
                elif text.startswith(CANCEL_PREFIX):
                    st["pending"] = None
                    _save(wa_id, st)
                    wa.send_text(wa_id, "Action cancelled.")
                else:
                    wa.send_text(wa_id, "No pending action to confirm.")
            else:
                st = _session(wa_id)
                if not _onboard_text(wa_id, st, text):
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
