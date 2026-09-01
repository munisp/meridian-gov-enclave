package main

// otel_test.go — smoke tests for ombud OTel wiring: ledger money-path calls
// emit CLIENT spans and inject W3C traceparent; telemetry-off mode leaves
// the dev in-memory ledger path untouched.

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

func TestOTelLedgerHoldClientSpan(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))

	var gotTraceparent string
	ledger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"transfer_id":"tb-hold-000001"}`))
	}))
	defer ledger.Close()

	c := NewCoreLedgerClient(ledger.URL)
	hold, err := c.Hold("OMB-000001", 1, 2000)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if hold.HoldID != "tb-hold-000001" || hold.AmountKobo != 2000 {
		t.Fatalf("unexpected hold: %+v", hold)
	}
	if gotTraceparent == "" {
		t.Fatal("ledger received no traceparent header — propagation broken")
	}
	clientSpans := 0
	for _, sp := range rec.Ended() {
		if sp.SpanKind() == 3 { // CLIENT
			clientSpans++
		}
	}
	if clientSpans == 0 {
		t.Fatal("no CLIENT span recorded for ledger Hold")
	}
}

func TestOTelInMemLedgerUnaffected(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	p := otelx.InitProviders(context.Background())
	defer p.Shutdown(context.Background())
	c := NewInMemLedgerClient()
	hold, err := c.Hold("OMB-000002", 2, 5000)
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if err := c.Settle(hold.HoldID); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	bal, err := c.Balance("pool")
	if err != nil || bal != 5000 {
		t.Fatalf("Balance = %d, %v; want 5000", bal, err)
	}
}
