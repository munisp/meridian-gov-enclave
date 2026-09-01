package main

// otel_test.go — smoke tests for the OTel wiring (otel-foundation contract):
// server middleware emits tenant.id spans named by route template, and the
// instrumented outbound client injects W3C traceparent/baggage into
// upstream dispatch calls.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/munisp/meridian-gov-enclave/packages/otelx"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestOTelMiddlewareTenantSpan(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := otelx.Middleware(mux)

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.Header.Set("X-Meridian-Tenant", "tenant-gov-1")
	h.ServeHTTP(httptest.NewRecorder(), r)

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	sp := spans[0]
	if sp.Name() != "GET /healthz" {
		t.Fatalf("span name = %q, want route template 'GET /healthz'", sp.Name())
	}
	found := false
	for _, a := range sp.Attributes() {
		if string(a.Key) == "tenant.id" && a.Value.AsString() == "tenant-gov-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("span missing tenant.id=tenant-gov-1 attribute: %v", sp.Attributes())
	}
}

func TestOTelDispatchInjectsTraceparent(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	var gotTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	s := &Server{http: &http.Client{Transport: otelx.Client(nil)}}
	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "parent")
	defer span.End()

	f := &Flow{ID: "F1", ConsumerURL: upstream.URL}
	if _, err := s.dispatch(ctx, f, []byte(`{}`), "caller"); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if gotTraceparent == "" {
		t.Fatal("upstream received no traceparent header — propagation broken")
	}
}

func TestOTelDisabledIsNoop(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("PROFILE", "dev")
	p := otelx.InitProviders(context.Background())
	if p.Enabled() {
		t.Fatal("providers enabled without endpoint")
	}
	p.Shutdown(context.Background()) // must not panic
}
