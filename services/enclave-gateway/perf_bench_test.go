// perf_bench_test.go — measured before/after for the PERF changes:
// Permify check cache (P5) and F7 verified-feed cache (P6).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Permify: N checks of the same (entity, permission, subject) — uncached
// pays N upstream RTTs; cached pays 1.
func BenchmarkPermifyCheck(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"can":"RESULT_ALLOWED"}`))
	}))
	defer srv.Close()
	ctx := context.Background()

	b.Run("uncached", func(b *testing.B) {
		c := NewPermifyClient(srv.URL, "t1")
		c.cacheTTL = 0 // disable (pre-change behaviour)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = c.Check(ctx, "flow:f1", "send", "user:u1")
		}
	})
	b.Run("cached_5s_ttl", func(b *testing.B) {
		c := NewPermifyClient(srv.URL, "t1")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = c.Check(ctx, "flow:f1", "send", "user:u1")
		}
	})
}

// F7: upstream fetch + ed25519 verify per request vs verified-feed cache.
func BenchmarkHandleF7(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	feed := []byte(`{"period":"2026-01","rows":[]}`)
	sig := ed25519.Sign(priv, feed)
	doc, _ := json.Marshal(map[string]any{
		"feed":       json.RawMessage(feed),
		"signature":  hex.EncodeToString(sig),
		"public_key": hex.EncodeToString(pub),
	})
	var fetches int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.Write(doc)
	}))
	defer upstream.Close()

	for _, cached := range []bool{false, true} {
		name := "fetch_verify_per_request"
		if cached {
			name = "verified_feed_cache_60s"
		}
		b.Run(name, func(b *testing.B) {
			s := &Server{cfg: Config{JRBURL: upstream.URL},
				http: &http.Client{Timeout: 5 * time.Second}}
			if cached {
				s.feedCacheTTL = time.Minute
			}
			p := &Principal{Sub: "u1", Roles: []string{"operator"}}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest("GET", "/v1/flows/f7/feeds/LAG/latest", nil)
				req = req.WithContext(context.WithValue(req.Context(), ctxPrincipal, p))
				req.SetPathValue("state", "LAG")
				rec := httptest.NewRecorder()
				s.handleF7(rec, req)
				if rec.Code != http.StatusOK {
					b.Fatalf("status %d", rec.Code)
				}
			}
		})
	}
}
