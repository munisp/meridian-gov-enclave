package otelx

// middleware.go — server + client HTTP instrumentation wrapping the existing
// httpx servers. One span per request named "<METHOD> <route-template>" using
// the Go 1.22 ServeMux pattern (r.Pattern, low cardinality), with tenant.id
// set from TenantFromRequest. The client wrapper injects W3C tracecontext +
// baggage into outbound requests.

import (
	"fmt"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/munisp/meridian-gov-enclave/packages/otelx"

// spanStatusRecorder mirrors httpx's recorder: default 200, capture explicit
// WriteHeader, and satisfy http.Flusher for streaming handlers.
type spanStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *spanStatusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *spanStatusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware wraps an httpx handler: extracts inbound trace context, starts a
// server span, labels it with tenant.id, and stamps the route template after
// the handler runs (r.Pattern is only populated post-routing).
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(),
			propagationHeaderCarrier(r.Header))
		tracer := otel.Tracer(tracerName)
		ctx, span := tracer.Start(ctx, r.Method+" "+r.URL.Path,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.URLPath(r.URL.Path),
			))
		defer span.End()

		tenant := TenantFromRequest(r.WithContext(ctx))
		if tenant != "" {
			span.SetAttributes(TenantAttr(tenant))
			// Reflect tenant into baggage so downstream hops inherit it.
			if m, err := baggage.NewMember(TenantKey, tenant); err == nil {
				if bg, err := baggage.New(m); err == nil {
					ctx = baggage.ContextWithBaggage(ctx, bg)
				}
			}
		}

		sr := &spanStatusRecorder{ResponseWriter: w, status: http.StatusOK}
		r2 := r.WithContext(ctx)
		next.ServeHTTP(sr, r2)

		route := r2.Pattern
		if route == "" {
			route = "unmatched"
		}
		// Go 1.22 ServeMux patterns include the method ("GET /healthz");
		// strip it for the span name so we get "<METHOD> <route-template>"
		// once (http.route keeps the full pattern per contract).
		nameRoute := route
		if strings.HasPrefix(nameRoute, r.Method+" ") {
			nameRoute = nameRoute[len(r.Method)+1:]
		}
		span.SetName(r.Method + " " + nameRoute)
		span.SetAttributes(
			semconv.HTTPRoute(route),
			semconv.HTTPResponseStatusCode(sr.status),
		)
		if sr.status >= 500 {
			span.SetStatus(codes.Error, fmt.Sprintf("status %d", sr.status))
		} else {
			span.SetStatus(codes.Ok, "")
		}
	})
}

// propagationHeaderCarrier adapts http.Header to propagation.TextMapCarrier.
type propagationHeaderCarrier http.Header

func (c propagationHeaderCarrier) Get(key string) string { return http.Header(c).Get(key) }
func (c propagationHeaderCarrier) Set(key, value string) { http.Header(c).Set(key, value) }
func (c propagationHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	return keys
}

// Client instruments an outbound HTTP client: traceparent/tracestate/baggage
// are injected from the request context and a client span is created per call.
// Pass nil to wrap http.DefaultTransport.
func Client(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &clientTransport{base: rt}
}

type clientTransport struct{ base http.RoundTripper }

func (t *clientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tracer := otel.Tracer(tracerName)
	ctx, span := tracer.Start(req.Context(), req.Method+" "+req.URL.Host+req.URL.Path,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(req.Method),
			semconv.URLFull(req.URL.String()),
			attribute.String("server.address", req.URL.Host),
		))
	defer span.End()
	otel.GetTextMapPropagator().Inject(ctx, propagationHeaderCarrier(req.Header))
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	span.SetAttributes(semconv.HTTPResponseStatusCode(resp.StatusCode))
	if resp.StatusCode >= 500 {
		span.SetStatus(codes.Error, fmt.Sprintf("status %d", resp.StatusCode))
	}
	return resp, nil
}
