// perf_bench_test.go — measured before/after: latestFeed served from the
// in-memory feed cache vs os.ReadFile of latest.json on every request (P6).
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkLatestFeed(b *testing.B) {
	dir := b.TempDir()
	feeds := filepath.Join(dir, "feeds")
	_ = os.MkdirAll(feeds, 0o755)
	data := []byte(`{"feed":{"period":"2026-01"},"signature":"ab","public_key":"cd"}`)
	_ = os.WriteFile(filepath.Join(feeds, "latest.json"), data, 0o644)

	b.Run("disk_read_per_request", func(b *testing.B) {
		s := &Server{cfg: Config{DataRoot: dir}}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := httptest.NewRecorder()
			s.latestFeed(rec, httptest.NewRequest("GET", "/v1/attribution/feeds/LAG/latest", nil))
			if rec.Code != http.StatusOK {
				b.Fatal(rec.Code)
			}
		}
	})
	b.Run("in_memory_cache", func(b *testing.B) {
		s := &Server{cfg: Config{DataRoot: dir}, feedCache: data} // warm cache
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := httptest.NewRecorder()
			s.latestFeed(rec, httptest.NewRequest("GET", "/v1/attribution/feeds/LAG/latest", nil))
			if rec.Code != http.StatusOK {
				b.Fatal(rec.Code)
			}
		}
	})
}
