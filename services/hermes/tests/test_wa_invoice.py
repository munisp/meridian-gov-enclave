"""Feature I4: WhatsApp e-invoice bot. Full conversation flows mocked at the
einvoicing HTTP boundary (injectable transport), idempotent redelivery,
unknown-number authz, fail-closed gate, upstream-failure honesty."""
import hashlib
import hmac
import json
import logging
import urllib.error

import pytest
from fastapi.testclient import TestClient

from hermes.config import Settings
from hermes.gateway.main import create_app
from hermes.gateway.wa_invoice import (EinvoicingClient, EinvoicingError,
                                       parse_amount_kobo)
from hermes.gateway.wa_onboarding import compute_tin_check_digit
from hermes.gateway.whatsapp import WhatsAppClient

SECRET = "test-app-secret"
VERIFY = "test-verify-token"
WA_ID = "2348012345678"
UNKNOWN_WA = "2348099999999"


def _tin(base11: str) -> str:
    return f"{base11[:8]}-{base11[8:]}{compute_tin_check_digit(base11)}"


SUPPLIER_TIN = _tin("12345678901")
BUYER_TIN = _tin("98765432109")
IRN = "INV-0001-SVC01-20260115"
QR_PAYLOAD = f"NRS1|{IRN}|{SUPPLIER_TIN}|15000000|20260115120000|ab12cd34ef56"


def _sig(body: bytes) -> str:
    return "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


def _msg_payload(text=None, *, mid, wa_id=WA_ID, button_id=None):
    msg = {"id": mid, "from": wa_id}
    if button_id is not None:
        msg["type"] = "interactive"
        msg["interactive"] = {"button_reply": {"id": button_id}}
    else:
        msg["type"] = "text"
        msg["text"] = {"body": text}
    return json.dumps({"object": "whatsapp_business_account", "entry": [{
        "id": "1", "changes": [{"field": "messages", "value": {
            "messaging_product": "whatsapp",
            "metadata": {"phone_number_id": "pn-1"},
            "messages": [msg]}}]}]}).encode()


class WaRecorder:
    def __init__(self):
        self.payloads = []

    def __call__(self, url, headers, body):
        self.payloads.append(json.loads(body.decode()))
        return {"messages": [{"id": f"wamid.fake{len(self.payloads)}"}]}

    def texts(self):
        return [p["text"]["body"] for p in self.payloads if p.get("type") == "text"]

    def buttons(self):
        return [b["reply"]["id"] for p in self.payloads
                if p.get("type") == "interactive"
                for b in p["interactive"]["action"]["buttons"]]


class EinvTransport:
    """Mocked einvoicing HTTP boundary. records requests; mode controls the
    response: ok | fail | reject | flaky | notfound.

    fail  = ambiguous network/timeout error on every call.
    reject = definitive 4xx-style rejection (ambiguous=False).
    flaky = first create_invoice times out (ambiguous) AFTER the service
            created the invoice; the retry with the same idempotency key
            replays the stored invoice (backend dedup)."""
    def __init__(self, mode="ok"):
        self.mode = mode
        self.requests = []   # (url, headers, payload)
        self.created = {}    # idempotency-key -> stored invoice (dedup)

    def __call__(self, url, headers, body, timeout_s):
        payload = json.loads(body.decode())
        self.requests.append((url, dict(headers), payload))
        if self.mode == "fail":
            raise EinvoicingError("einvoicing service unreachable: TimeoutError")
        if self.mode == "reject":
            raise EinvoicingError(
                "einvoicing service rejected the request: HTTP 400 "
                "(buyer TIN not on NRS registry)", ambiguous=False)
        if payload.get("irn") and len(payload) == 1:
            if self.mode == "notfound":
                return {}
            return {"irn": payload["irn"], "status": "CONFIRMED",
                    "payment_status": "PAID",
                    "qr": {"payload": QR_PAYLOAD}}
        key = headers.get("idempotency-key", "")
        if key and key in self.created:
            inv = dict(self.created[key])
            inv["idempotent_replay"] = True
            return inv
        inv = {"irn": IRN, "status": "CONFIRMED", "invoice_id": "inv-1",
               "payment_status": "PENDING",
               "qr": {"payload": QR_PAYLOAD, "signature": "ab12cd34ef56"}}
        if key:
            self.created[key] = inv
        if self.mode == "flaky" and len(self.created) == 1 and \
                not getattr(self, "_flaked", False):
            # timeout AFTER the invoice was created server-side
            self._flaked = True
            raise EinvoicingError("einvoicing service unreachable: TimeoutError")
        return inv


def make(mode="ok", enabled=True, profile="dev", seed=True, wa_id=WA_ID):
    wa_rec = WaRecorder()
    einv_rec = EinvTransport(mode)
    einv = EinvoicingClient(
        base_url="http://einv.test" if enabled else "",
        service_token="svc-token" if enabled else "",
        transport=einv_rec)
    s = Settings(llm_adapter="rule", auth_mode="dev", profile=profile,
                 whatsapp_app_secret=SECRET, whatsapp_verify_token=VERIFY)
    wa = WhatsAppClient(access_token="tok", phone_number_id="pn-1",
                        transport=wa_rec)
    c = TestClient(create_app(s, whatsapp_client=wa,
                              whatsapp_invoice_client=einv))
    if seed:
        store = c.app.state.whatsapp_sessions
        store.put(wa_id, {"session_id": "seed", "lang": "en",
                          "pending": None, "tin": SUPPLIER_TIN})
    return c, wa_rec, einv_rec


def post(c, body):
    return c.post("/v1/whatsapp/webhook", content=body,
                  headers={"x-hub-signature-256": _sig(body),
                           "content-type": "application/json"})


def run_full_issue_flow(c, wa_rec, einv_rec, first_mid="wamid.start1"):
    """Drive menu -> buyer TIN -> amount -> description -> confirm."""
    assert post(c, _msg_payload("invoice", mid=first_mid)).status_code == 200
    assert "inv_new" in wa_rec.buttons()
    post(c, _msg_payload(mid="wamid.2", button_id="inv_new"))
    post(c, _msg_payload(BUYER_TIN, mid="wamid.3"))
    post(c, _msg_payload("150,000.00", mid="wamid.4"))
    post(c, _msg_payload("Consulting services March", mid="wamid.5"))
    assert "inv_confirm_go" in wa_rec.buttons()
    post(c, _msg_payload(mid="wamid.6", button_id="inv_confirm_go"))


# ---------------------------------------------------------------------------
# amount parsing (kobo integers)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("text,expected", [
    ("150000", 15000000), ("2,500.50", 250050), ("₦100", 10000),
    ("NGN 1,000,000.99", 100000099), ("0.01", 1)])
def test_parse_amount_ok(text, expected):
    assert parse_amount_kobo(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "10.005", "-5", "0", "1.2.3",
                                  "1000000000"])
def test_parse_amount_reject(text):
    assert parse_amount_kobo(text) is None


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------
def test_full_issue_flow():
    c, wa_rec, einv_rec = make()
    run_full_issue_flow(c, wa_rec, einv_rec)
    texts = wa_rec.texts()
    assert any("Step 1 of 3" in t for t in texts)
    assert any("Step 2 of 3" in t for t in texts)
    assert any("Step 3 of 3" in t for t in texts)
    final = texts[-1]
    assert "E-invoice issued" in final and IRN in final
    assert QR_PAYLOAD in final          # NRS1|... verification reference
    # Upstream call: NRS payload + durable idempotency key + service token.
    assert len(einv_rec.requests) == 1
    url, headers, payload = einv_rec.requests[0]
    assert url == "http://einv.test/v1/invoices/nrs"
    assert headers["authorization"] == "Bearer svc-token"
    # key pinned to the stable Meta message id that started the flow
    assert headers["idempotency-key"] == f"wa-invoice:{WA_ID}:wamid.2"
    # kobo integers internally, exact decimal NGN on the wire
    assert payload["legal_monetary_total"]["payable_amount"] == 150000.00
    assert payload["invoice_line"][0]["line_extension_amount"] == 150000.00
    assert payload["accounting_supplier_party"]["tin"] == SUPPLIER_TIN
    assert payload["accounting_customer_party"]["tin"] == BUYER_TIN
    assert payload["invoice_type_code"] == "380"
    assert payload["document_currency_code"] == "NGN"


def test_invalid_inputs_reprompt_without_upstream_call():
    c, wa_rec, einv_rec = make()
    post(c, _msg_payload("invoice", mid="m1"))
    post(c, _msg_payload(mid="m2", button_id="inv_new"))
    post(c, _msg_payload("1234", mid="m3"))           # bad TIN
    assert "not valid" in wa_rec.texts()[-1]
    post(c, _msg_payload(BUYER_TIN, mid="m4"))
    post(c, _msg_payload("lots of money", mid="m5"))  # bad amount
    assert "couldn't read that amount" in wa_rec.texts()[-1]
    post(c, _msg_payload("10.005", mid="m6"))         # >2dp rejected
    assert "couldn't read that amount" in wa_rec.texts()[-1]
    assert einv_rec.requests == []                    # nothing reached upstream


def test_cancel_mid_flow():
    c, wa_rec, einv_rec = make()
    post(c, _msg_payload("invoice", mid="m1"))
    post(c, _msg_payload(mid="m2", button_id="inv_new"))
    post(c, _msg_payload("cancel", mid="m3"))
    assert "cancelled" in wa_rec.texts()[-1].lower()
    assert einv_rec.requests == []


# ---------------------------------------------------------------------------
# idempotency
# ---------------------------------------------------------------------------
def test_redelivered_messages_never_duplicate():
    """Meta redelivery (same message id) is deduped at every step; exactly
    one invoice is created upstream."""
    c, wa_rec, einv_rec = make()
    post(c, _msg_payload("invoice", mid="s1"))
    post(c, _msg_payload("invoice", mid="s1"))   # redelivery
    menus = [p for p in wa_rec.payloads if p.get("type") == "interactive"]
    assert len(menus) == 1
    post(c, _msg_payload(mid="s2", button_id="inv_new"))
    post(c, _msg_payload(mid="s2", button_id="inv_new"))   # redelivery
    assert wa_rec.texts().count(next(t for t in wa_rec.texts()
                                     if "Step 1 of 3" in t)) == 1
    post(c, _msg_payload(BUYER_TIN, mid="s3"))
    post(c, _msg_payload("5000", mid="s4"))
    post(c, _msg_payload("Supplies", mid="s5"))
    post(c, _msg_payload(mid="s6", button_id="inv_confirm_go"))
    post(c, _msg_payload(mid="s6", button_id="inv_confirm_go"))  # redelivery
    assert len(einv_rec.requests) == 1
    _, headers, _ = einv_rec.requests[0]
    assert headers["idempotency-key"] == f"wa-invoice:{WA_ID}:s2"


def test_double_confirm_replays_same_idempotency_key():
    c, wa_rec, einv_rec = make()
    post(c, _msg_payload("invoice", mid="s1"))
    post(c, _msg_payload(mid="s2", button_id="inv_new"))
    post(c, _msg_payload(BUYER_TIN, mid="s3"))
    post(c, _msg_payload("5000", mid="s4"))
    post(c, _msg_payload("Supplies", mid="s5"))
    post(c, _msg_payload(mid="s6", button_id="inv_confirm_go"))
    # Meta redelivers the SAME confirm message id -> dedup, no second call.
    post(c, _msg_payload(mid="s6", button_id="inv_confirm_go"))
    assert len(einv_rec.requests) == 1


# ---------------------------------------------------------------------------
# authz: unknown / unbound numbers
# ---------------------------------------------------------------------------
def test_unknown_number_gets_enrollment_never_issuance():
    c, wa_rec, einv_rec = make(seed=False)
    post(c, _msg_payload("invoice", mid="u1", wa_id=UNKNOWN_WA))
    txt = wa_rec.texts()[-1]
    assert "must first be linked" in txt and "TIN" in txt
    assert einv_rec.requests == []
    # even pressing the button id out of band must not bypass authz
    post(c, _msg_payload(mid="u2", wa_id=UNKNOWN_WA, button_id="inv_new"))
    assert "must first be linked" in wa_rec.texts()[-1]
    assert einv_rec.requests == []


# ---------------------------------------------------------------------------
# fail-closed feature gate
# ---------------------------------------------------------------------------
def test_feature_disabled_says_unavailable_and_logs(caplog):
    c, wa_rec, einv_rec = make(enabled=False)
    with caplog.at_level(logging.WARNING, logger="hermes.whatsapp.invoice"):
        post(c, _msg_payload("invoice", mid="d1"))
    assert "currently unavailable" in wa_rec.texts()[-1]
    assert einv_rec.requests == []
    assert any("DISABLED" in r.message for r in caplog.records)


def test_prod_missing_config_logs_error(caplog):
    """PROFILE=prod + missing einvoicing config: feature disabled with an
    explicit error-level log (the channel itself still starts)."""
    from fastapi import FastAPI
    from hermes.agent.audit import AuditChain
    from hermes.agent.memory import build_memory
    from hermes.gateway.whatsapp import add_whatsapp_routes
    s = Settings(profile="prod", auth_mode="keycloak",
                 whatsapp_app_secret=SECRET, whatsapp_verify_token=VERIFY)
    wa = WhatsAppClient(access_token="tok", phone_number_id="pn-1",
                        transport=WaRecorder())
    with caplog.at_level(logging.ERROR, logger="hermes.whatsapp"):
        add_whatsapp_routes(FastAPI(), s, AuditChain(None),
                            build_memory("", 60), lambda a, c: None,
                            client=wa,
                            invoice_client=EinvoicingClient("", ""))
    assert any("e-invoice feature DISABLED" in r.message
               and r.levelno == logging.ERROR for r in caplog.records)


# ---------------------------------------------------------------------------
# honesty + idempotency on upstream failure (S3#4 regression)
# ---------------------------------------------------------------------------
def test_definitive_rejection_honest_error_no_fake_confirmation():
    """A definitive 4xx proves nothing was created: the flow + idempotency
    key are cleared and the user is told no invoice exists."""
    c, wa_rec, einv_rec = make(mode="reject")
    run_full_issue_flow(c, wa_rec, einv_rec)
    final = wa_rec.texts()[-1]
    assert "could NOT issue" in final
    assert "No invoice was created" in final
    assert IRN not in final and "NRS1|" not in final  # nothing fabricated
    # flow was reset: the next "invoice" command starts a brand-new flow
    # whose idempotency key is pinned to the NEW starting message id.
    post(c, _msg_payload("invoice", mid="r7"))
    post(c, _msg_payload(mid="r8", button_id="inv_new"))
    post(c, _msg_payload(BUYER_TIN, mid="r9"))
    post(c, _msg_payload("5000", mid="r10"))
    post(c, _msg_payload("Supplies", mid="r11"))
    c2_mode = einv_rec.mode
    einv_rec.mode = "ok"
    post(c, _msg_payload(mid="r12", button_id="inv_confirm_go"))
    einv_rec.mode = c2_mode
    keys = [h.get("idempotency-key") for _, h, p in einv_rec.requests
            if not (p.get("irn") and len(p) == 1)]
    assert keys[-1] == f"wa-invoice:{WA_ID}:r8"
    assert keys[-1] != keys[0]


def test_ambiguous_timeout_preserves_key_retry_single_invoice():
    """Timeout AFTER the service created the invoice: the bot must NOT say
    'no invoice was created', must PRESERVE the pinned idempotency key, and
    the retry must reuse the SAME key so the backend dedups — exactly one
    real invoice ever exists for the sale."""
    c, wa_rec, einv_rec = make(mode="flaky")
    post(c, _msg_payload("invoice", mid="s1"))
    post(c, _msg_payload(mid="s2", button_id="inv_new"))
    post(c, _msg_payload(BUYER_TIN, mid="s3"))
    post(c, _msg_payload("150,000.00", mid="s4"))
    post(c, _msg_payload("Consulting services March", mid="s5"))
    post(c, _msg_payload(mid="s6", button_id="inv_confirm_go"))
    # ambiguous outcome: honest "status being confirmed", NOT a false
    # "no invoice was created"; nothing fabricated either way. The reply
    # is sent with retry buttons (interactive payload).
    interactives = [p for p in wa_rec.payloads if p.get("type") == "interactive"]
    ambiguous_reply = interactives[-1]["interactive"]["body"]["text"]
    assert "being confirmed" in ambiguous_reply
    assert "may already have been issued" in ambiguous_reply
    assert "No invoice was created" not in ambiguous_reply
    assert IRN not in ambiguous_reply and "NRS1|" not in ambiguous_reply
    # the flow is still alive at confirm: retry buttons were offered.
    assert "inv_confirm_go" in wa_rec.buttons()
    # retry (new Meta message id): SAME idempotency key reused; backend
    # replays the already-created invoice — no duplicate is minted.
    post(c, _msg_payload(mid="s7", button_id="inv_confirm_go"))
    create_keys = [h.get("idempotency-key") for _, h, p in einv_rec.requests
                   if not (p.get("irn") and len(p) == 1)]
    assert create_keys == [f"wa-invoice:{WA_ID}:s2"] * 2
    assert len(einv_rec.created) == 1            # single real invoice
    final = wa_rec.texts()[-1]
    assert "E-invoice issued" in final and IRN in final
    assert "already issued" in final             # idempotent replay surfaced


def test_ambiguous_failure_then_cancel_keeps_no_stale_charge():
    """After an ambiguous failure the user may cancel; no second upstream
    call is made and nothing was ever confirmed to them."""
    c, wa_rec, einv_rec = make(mode="fail")
    run_full_issue_flow(c, wa_rec, einv_rec)
    post(c, _msg_payload(mid="c9", button_id="inv_confirm_no"))
    assert "cancelled" in wa_rec.texts()[-1].lower()
    assert len(einv_rec.requests) == 1


def test_status_flow_and_failure():
    c, wa_rec, einv_rec = make()
    post(c, _msg_payload("invoice status", mid="t1"))
    assert "IRN" in wa_rec.texts()[-1]
    post(c, _msg_payload(IRN, mid="t2"))
    final = wa_rec.texts()[-1]
    assert IRN in final and "CONFIRMED" in final and QR_PAYLOAD in final
    _, _, payload = einv_rec.requests[0]
    assert payload == {"irn": IRN}

    c2, wa_rec2, einv_rec2 = make(mode="notfound")
    post(c2, _msg_payload("invoice status", mid="t1"))
    post(c2, _msg_payload("NOPE-1-X-20260101", mid="t2"))
    assert "No invoice was found" in wa_rec2.texts()[-1]

    c3, wa_rec3, _ = make(mode="fail")
    post(c3, _msg_payload("invoice status", mid="t1"))
    post(c3, _msg_payload(IRN, mid="t2"))
    assert "could not retrieve" in wa_rec3.texts()[-1]
