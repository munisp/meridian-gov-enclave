"""REAL WhatsApp onboarding clients: HttpOtpSender (notification service),
IdentityTokenIssuer (identity service), env wiring in gateway/main.py
(REAL vs SIM selection, prod fail-closed), and end-to-end onboarding with
the real-impl classes over fake transports. Fully offline."""
import json
import urllib.error

import pytest
from fastapi.testclient import TestClient

from hermes.config import Settings
from hermes.gateway.main import build_onboarding_clients, create_app
from hermes.gateway.wa_onboarding import (HttpOtpSender, IdentityExchangeError,
                                          IdentityTokenIssuer, OtpDeliveryError)
from hermes.gateway.whatsapp import WhatsAppClient
from .test_whatsapp import SECRET, VERIFY, WA_ID, Recorder, _payload, post

TIN_OK = "12345678-0019"  # valid format + check digit
NOTIF = "http://notification:8080"
IDENT = "http://identity:8080"


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("http://x", code, "err", {}, None)


class Transport:
    """Fake HTTP transport: records calls; queued results may be dicts
    (returned) or Exceptions (raised)."""

    def __init__(self, *results):
        self.calls = []          # (url, headers, body_bytes, timeout_s)
        self.payloads = []
        self.results = list(results) or [{}]

    def __call__(self, url, headers, body, timeout_s):
        self.calls.append((url, headers, body, timeout_s))
        self.payloads.append(json.loads(body.decode()))
        r = self.results.pop(0) if self.results else {}
        if isinstance(r, Exception):
            raise r
        return r


# ---------------------------------------------------------------------------
# HttpOtpSender
# ---------------------------------------------------------------------------
def test_otp_sender_success_posts_to_notification_service():
    t = Transport({"ok": True})
    HttpOtpSender(NOTIF, timeout_s=3, transport=t).send_otp(WA_ID, "123456", 600)
    assert len(t.calls) == 1
    url, headers, _, timeout_s = t.calls[0]
    assert url == f"{NOTIF}/v1/send" and timeout_s == 3
    assert headers["content-type"] == "application/json"
    p = t.payloads[0]
    assert p == {"channel": "sms", "to": WA_ID, "template": "wa_otp",
                 "params": {"code": "123456", "ttl_s": 600}}


def test_otp_sender_retries_once_on_5xx_then_succeeds():
    t = Transport(_http_error(503), {"ok": True})
    HttpOtpSender(NOTIF, transport=t).send_otp(WA_ID, "123456", 600)
    assert len(t.calls) == 2  # retried exactly once


def test_otp_sender_5xx_twice_fails_closed():
    t = Transport(_http_error(500), _http_error(502))
    with pytest.raises(OtpDeliveryError):
        HttpOtpSender(NOTIF, transport=t).send_otp(WA_ID, "123456", 600)
    assert len(t.calls) == 2


def test_otp_sender_4xx_fails_closed_without_retry():
    t = Transport(_http_error(400), {"ok": True})
    with pytest.raises(OtpDeliveryError):
        HttpOtpSender(NOTIF, transport=t).send_otp(WA_ID, "123456", 600)
    assert len(t.calls) == 1


def test_otp_sender_timeout_fails_closed():
    t = Transport(TimeoutError("timed out"))
    with pytest.raises(OtpDeliveryError):
        HttpOtpSender(NOTIF, transport=t).send_otp(WA_ID, "123456", 600)


def test_otp_sender_requires_base_url():
    with pytest.raises(ValueError):
        HttpOtpSender("")


# ---------------------------------------------------------------------------
# IdentityTokenIssuer
# ---------------------------------------------------------------------------
def test_identity_issuer_success_exchanges_binding_for_token():
    t = Transport({"access_token": "kc.jwt.token", "ttl": 3600})
    tok = IdentityTokenIssuer(IDENT, timeout_s=7, transport=t).issue(
        WA_ID, TIN_OK, "ndpa-consent-abc")
    assert tok == "kc.jwt.token"
    url, _, _, timeout_s = t.calls[0]
    assert url == f"{IDENT}/v1/whatsapp/exchange" and timeout_s == 7
    assert t.payloads[0] == {"wa_id": WA_ID, "tin": TIN_OK,
                             "consent_ref": "ndpa-consent-abc"}


def test_identity_issuer_401_fails_closed():
    t = Transport(_http_error(401))
    with pytest.raises(IdentityExchangeError, match="401"):
        IdentityTokenIssuer(IDENT, transport=t).issue(WA_ID, TIN_OK, "c")


def test_identity_issuer_network_error_fails_closed():
    t = Transport(ConnectionError("refused"))
    with pytest.raises(IdentityExchangeError):
        IdentityTokenIssuer(IDENT, transport=t).issue(WA_ID, TIN_OK, "c")


def test_identity_issuer_missing_access_token_fails_closed():
    t = Transport({"ttl": 3600})
    with pytest.raises(IdentityExchangeError):
        IdentityTokenIssuer(IDENT, transport=t).issue(WA_ID, TIN_OK, "c")


def test_identity_issuer_requires_base_url():
    with pytest.raises(ValueError):
        IdentityTokenIssuer("")


# ---------------------------------------------------------------------------
# Wiring (gateway/main.py): REAL vs SIM selection, prod fail-closed
# ---------------------------------------------------------------------------
def test_wiring_selects_real_impls_when_urls_set():
    s = Settings(profile="dev", notification_url=NOTIF, identity_url=IDENT)
    otp_sender, issuer = build_onboarding_clients(s)
    assert isinstance(otp_sender, HttpOtpSender)
    assert isinstance(issuer, IdentityTokenIssuer)


def test_wiring_dev_falls_back_to_sim_with_honest_log(caplog):
    s = Settings(profile="dev")
    with caplog.at_level("INFO", logger="hermes.gateway"):
        otp_sender, issuer = build_onboarding_clients(s)
    assert otp_sender is None and issuer is None  # whatsapp.py installs SIM
    assert "NOTIFICATION_URL unset; SIM OTP delivery" in caplog.text
    assert "IDENTITY_URL unset; SIM token issuer" in caplog.text


def test_prod_startup_fail_closed_without_urls():
    with pytest.raises(RuntimeError, match="NOTIFICATION_URL"):
        create_app(Settings(profile="prod", whatsapp_app_secret="prod-secret"))


def test_prod_startup_fail_closed_with_only_notification_url():
    with pytest.raises(RuntimeError, match="IDENTITY_URL"):
        create_app(Settings(profile="prod", whatsapp_app_secret="prod-secret",
                            notification_url=NOTIF))


def test_prod_startup_ok_with_both_urls():
    app = create_app(Settings(profile="prod", auth_mode="keycloak",
                              whatsapp_app_secret="prod-secret",
                              notification_url=NOTIF, identity_url=IDENT))
    assert app is not None


# ---------------------------------------------------------------------------
# End-to-end onboarding with the REAL impl classes (fake transports)
# ---------------------------------------------------------------------------
def make_real_client():
    notif_t = Transport({"ok": True})
    ident_t = Transport({"access_token": "kc.scoped.token", "ttl": 3600})
    rec = Recorder()
    wa = WhatsAppClient(access_token="tok", phone_number_id="pn-1",
                        transport=rec)
    s = Settings(llm_adapter="rule", auth_mode="dev", profile="dev",
                 whatsapp_app_secret=SECRET, whatsapp_verify_token=VERIFY)
    app = create_app(
        s, whatsapp_client=wa,
        whatsapp_otp_sender=HttpOtpSender(NOTIF, transport=notif_t),
        whatsapp_token_issuer=IdentityTokenIssuer(IDENT, transport=ident_t))
    return TestClient(app), rec, notif_t, ident_t


def test_e2e_onboarding_with_real_clients():
    c, rec, notif_t, ident_t = make_real_client()
    post(c, _payload("Estimate my liability", mid="wamid.r1"))
    assert "link your TIN" in rec.texts()[-1]
    # TIN -> OTP delivered through the notification-service client
    post(c, _payload(TIN_OK, mid="wamid.r2"))
    assert notif_t.payloads[0]["template"] == "wa_otp"
    code = notif_t.payloads[0]["params"]["code"]
    assert "6-digit verification code" in rec.texts()[-1]
    # OTP -> token exchanged via the identity service, binding persisted
    post(c, _payload(code, mid="wamid.r3"))
    assert "now linked" in rec.texts()[-1]
    assert ident_t.payloads[0]["wa_id"] == WA_ID
    assert ident_t.payloads[0]["tin"] == TIN_OK
    b = c.app.state.whatsapp_stores.binding.get(WA_ID)
    assert b is not None and b.token == "kc.scoped.token"
    assert ident_t.payloads[0]["consent_ref"] == b.consent_ref
    assert c.app.state.whatsapp_sessions.get(WA_ID)["token"] == "kc.scoped.token"


def test_e2e_otp_delivery_failure_is_honest_and_fail_closed():
    notif_t = Transport(ConnectionError("down"))
    rec = Recorder()
    wa = WhatsAppClient(access_token="tok", phone_number_id="pn-1",
                        transport=rec)
    s = Settings(llm_adapter="rule", auth_mode="dev", profile="dev",
                 whatsapp_app_secret=SECRET, whatsapp_verify_token=VERIFY)
    app = create_app(s, whatsapp_client=wa,
                     whatsapp_otp_sender=HttpOtpSender(NOTIF, transport=notif_t))
    c = TestClient(app)
    post(c, _payload(TIN_OK, mid="wamid.f1"))
    assert "couldn't send the verification code" in rec.texts()[-1]
    # challenge dropped: resending the TIN starts over cleanly
    assert c.app.state.whatsapp_sessions.get(WA_ID).get("onboarding_tin") is None


def test_e2e_token_exchange_failure_aborts_binding():
    notif_t = Transport({"ok": True})
    ident_t = Transport(_http_error(401))
    rec = Recorder()
    wa = WhatsAppClient(access_token="tok", phone_number_id="pn-1",
                        transport=rec)
    s = Settings(llm_adapter="rule", auth_mode="dev", profile="dev",
                 whatsapp_app_secret=SECRET, whatsapp_verify_token=VERIFY)
    app = create_app(
        s, whatsapp_client=wa,
        whatsapp_otp_sender=HttpOtpSender(NOTIF, transport=notif_t),
        whatsapp_token_issuer=IdentityTokenIssuer(IDENT, transport=ident_t))
    c = TestClient(app)
    post(c, _payload(TIN_OK, mid="wamid.e1"))
    post(c, _payload(notif_t.payloads[0]["params"]["code"], mid="wamid.e2"))
    assert "couldn't complete the TIN link" in rec.texts()[-1]
    assert c.app.state.whatsapp_stores.binding.get(WA_ID) is None
