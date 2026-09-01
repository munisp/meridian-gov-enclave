package main

// otel_test.go — smoke tests for jrb OTel wiring: F6 gateway sends carry a
// client span and inject W3C traceparent; the server middleware path is
// covered by packages/otelx tests and gateway smoke tests.

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

func TestOTelGatewaySendInjectsTraceparent(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	var gotTraceparent string
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"evidence_receipt":{"evidence_id":"ev-1","sha256":"abc"}}`))
	}))
	defer gw.Close()

	g := &GatewayClient{base: gw.URL, token: "t",
		http: &http.Client{Transport: otelx.Client(nil)}}

	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "parent")
	res, err := g.SendF6EOI(ctx, []byte(`{"eoi_id":"e1"}`))
	span.End()
	if err != nil {
		t.Fatalf("SendF6EOI: %v", err)
	}
	if res.ReceiptID != "ev-1" {
		t.Fatalf("receipt = %q, want ev-1", res.ReceiptID)
	}
	if gotTraceparent == "" {
		t.Fatal("gateway received no traceparent header — propagation broken")
	}
	clientSpans := 0
	for _, sp := range rec.Ended() {
		if sp.SpanKind() == 3 { // CLIENT
			clientSpans++
		}
	}
	if clientSpans == 0 {
		t.Fatal("no CLIENT span recorded for gateway send")
	}
}

func TestOTelSimulatedLocalStillWorks(t *testing.T) {
	// No endpoint configured: telemetry no-op must not break the dev path.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	g := &GatewayClient{base: "", http: &http.Client{Transport: otelx.Client(nil)}}
	res, err := g.SendF6EOI(context.Background(), []byte(`{}`))
	if err != nil || res.Mode != "simulated-local" {
		t.Fatalf("simulated-local broken: res=%+v err=%v", res, err)
	}
}
