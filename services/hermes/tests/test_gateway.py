"""Gateway: /healthz /readyz, auth, USSD truncation, RBAC wiring."""
from fastapi.testclient import TestClient

from hermes.config import Settings
from hermes.gateway.main import create_app, truncate_ussd


def make_client(**kw):
    s = Settings(llm_adapter="rule", auth_mode="dev", profile="dev", **kw)
    return TestClient(create_app(s))


def test_healthz_readyz():
    c = make_client()
    assert c.get("/healthz").json()["status"] == "ok"
    assert c.get("/readyz").json()["status"] == "ready"


def test_unauthorized_without_token():
    c = make_client()
    r = c.post("/v1/chat", json={"agent": "taxpayer-copilot", "message": "hi"})
    assert r.status_code == 401


def test_rbac_forbidden_wrong_role():
    c = make_client()
    r = c.post("/v1/chat", json={"agent": "ops-copilot", "message": "pod health"},
               headers={"x-dev-role": "nrs.taxpayer"})
    assert r.status_code == 403


def test_chat_web_dev_role():
    c = make_client()
    r = c.post("/v1/chat",
               json={"agent": "taxpayer-copilot", "message": "What is VAT?"},
               headers={"x-dev-role": "nrs.taxpayer", "x-dev-tin": "12345678"})
    assert r.status_code == 200
    body = r.json()
    assert body["sim"] is True and "7.5" in body["answer"]


def test_ussd_truncation_160():
    long = "x" * 500
    assert len(truncate_ussd(long, 160)) == 160
    c = make_client()
    r = c.post("/v1/chat",
               json={"agent": "taxpayer-copilot", "channel": "ussd",
                     "message": "Show my filing calendar for TIN 12345678"},
               headers={"x-dev-role": "nrs.taxpayer", "x-dev-tin": "12345678"})
    assert r.status_code == 200
    assert len(r.json()["answer"]) <= 160


def test_prod_profile_disables_dev_auth():
    from hermes.config import Settings
    c = TestClient(create_app(Settings(auth_mode="dev", profile="prod",
                                       whatsapp_app_secret="prod-secret")))
    r = c.post("/v1/chat", json={"agent": "taxpayer-copilot", "message": "hi"},
               headers={"x-dev-role": "nrs.taxpayer"})
    assert r.status_code == 401  # fail-closed in prod
