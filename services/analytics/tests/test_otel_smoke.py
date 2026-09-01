"""OTel smoke tests (DESIGN-CONTRACT.md): fail-soft init, tenant.id span
stamping via the vendored helper, and the app still serves with no endpoint."""
from __future__ import annotations

import os

os.environ["AUTH_MODE"] = "dev"
os.environ["TIN_HMAC_KEY"] = "test-hmac-key"
os.environ["ANALYTICS_DATA_ROOT"] = "/tmp/analytics-otel-test"

from opentelemetry import trace  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)

from app import otel  # noqa: E402


def test_app_serves_without_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.setenv("PROFILE", "dev")
    from fastapi.testclient import TestClient

    from app.main import app

    assert TestClient(app).get("/healthz").status_code == 200


def test_span_has_tenant_id(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    import fastapi
    from fastapi.testclient import TestClient

    exp = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exp))
    app = fastapi.FastAPI()

    @app.get("/v1/features")
    def features():
        return {"ok": True}

    assert otel.init_otel(app, tracer_provider=tp) is False
    app.add_middleware(otel.TenantBaggageMiddleware)
    r = TestClient(app).get("/v1/features", headers={"X-Tenant-ID": "tenant-an-1"})
    assert r.status_code == 200
    server = [s for s in exp.get_finished_spans() if s.kind == trace.SpanKind.SERVER]
    assert server
    assert any(s.attributes and s.attributes.get("tenant.id") == "tenant-an-1"
               for s in server)
