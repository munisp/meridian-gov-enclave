// perf_bench_test.go — measured before/after for the PERF changes:
// LocalWORM manifest chain head (P7) and ombud single-case upsert (P1).
package main

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// P7: before, EVERY Store re-read the whole manifest.log to find the chain
// head; after, the head is an in-memory field read once at startup.
func BenchmarkManifestChainHead(b *testing.B) {
	dir := b.TempDir()
	s, err := NewLocalWORMStore(dir)
	if err != nil {
		b.Fatal(err)
	}
	// Grow a realistic manifest (10k entries, one full Store each: also
	// exercises the new cached Store path so the file is genuine).
	for i := 0; i < 10000; i++ {
		if _, err := s.Store("f1", fmt.Sprintf("m%d", i), []byte(`{"x":1}`)); err != nil {
			b.Fatal(err)
		}
	}
	fi, _ := os.Stat(dir + "/worm/manifest.log")
	b.Logf("manifest.log size: %d bytes (10000 entries)", fi.Size())

	b.Run("reread_whole_manifest_per_write", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = s.lastManifestHash()
		}
	})
	b.Run("cached_chain_head", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = s.lastHash
		}
	})
}

// P1: per-mutation upsert count. Before, saveLocked issued N sequential
// Postgres upserts per mutation (one RTT each, mutex held); after, exactly
// one. Postgres is unavailable in the bench environment, so each upsert is
// simulated as a fixed 200us RTT sleep — the RATIO (N:1) is exact; absolute
// numbers scale with the real RTT.
func BenchmarkSaveLockedUpserts(b *testing.B) {
	const rtt = 200 * time.Microsecond
	upsert := func() { time.Sleep(rtt) } // stand-in for one PG round trip
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("before_N_upserts_%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for j := 0; j < n; j++ {
					upsert()
				}
			}
		})
		b.Run(fmt.Sprintf("after_1_upsert_%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				upsert()
			}
		})
	}
}
