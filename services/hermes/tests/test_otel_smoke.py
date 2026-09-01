"""OTel smoke tests (DESIGN-CONTRACT.md): tenant.id on server spans, baggage
propagation, fail-soft no-endpoint mode, and create_app wiring intact."""

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from hermes import otel
from hermes.config import Settings
from hermes.gateway.main import create_app


def _jwt(tenant: str) -> str:
    import base64
    import json

    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()

    return f"Bearer {b64({'alg': 'none'})}.{b64({'tenant_id': tenant})}.sig"


def test_span_has_tenant_id(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    monkeypatch.setenv("PROFILE", "dev")
    import fastapi
    from fastapi.testclient import TestClient

    exp = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exp))
    app = fastapi.FastAPI()

    @app.get("/v1/chat")
    def chat():
        return {"ok": True}

    assert otel.init_otel(app, tracer_provider=tp) is False  # no endpoint
    app.add_middleware(otel.TenantBaggageMiddleware)
    r = TestClient(app).get("/v1/chat", headers={"X-Meridian-Tenant": "tenant-gov-9"})
    assert r.status_code == 200
    server = [s for s in exp.get_finished_spans() if s.kind == trace.SpanKind.SERVER]
    assert server, "no server spans"
    assert any(s.attributes and s.attributes.get("tenant.id") == "tenant-gov-9"
               for s in server)


def test_tenant_from_jwt_claim():
    assert otel._tenant_from_headers({"authorization": _jwt("tenant-jwt-1")}) == "tenant-jwt-1"


def test_create_app_fail_soft_no_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.setenv("PROFILE", "dev")
    from fastapi.testclient import TestClient

    app = create_app(Settings(llm_adapter="rule", auth_mode="dev", profile="dev"))
    assert TestClient(app).get("/healthz").json()["status"] == "ok"
