package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCoreLedger enforces the real TigerBeetle code-reuse rule the dev
// InMemLedgerClient masks: a post/void with a non-zero code that differs
// from the pending's code (6=hold) is rejected with 422, exactly like the
// core ledger (PENDING_TRANSFER_HAS_DIFFERENT_CODE).
type fakeCoreLedger struct {
	mu       sync.Mutex
	pendings map[string]uint16 // id -> code
	amounts  map[string]int64
	timeouts map[string]uint32
	posted   map[string]bool
	voided   map[string]bool
}

func newFakeCoreLedger() *fakeCoreLedger {
	return &fakeCoreLedger{pendings: map[string]uint16{}, amounts: map[string]int64{},
		timeouts: map[string]uint32{}, posted: map[string]bool{}, voided: map[string]bool{}}
}

func (f *fakeCoreLedger) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/transfers/pending", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID             string `json:"id"`
			Code           uint16 `json:"code"`
			AmountKobo     int64  `json:"amount_kobo"`
			TimeoutSeconds uint32 `json:"timeout_seconds"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, dup := f.pendings[req.ID]; dup {
			// deterministic-id replay: identical attributes -> 200, no double hold
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"transfer_id": req.ID})
			return
		}
		f.pendings[req.ID] = req.Code
		f.amounts[req.ID] = req.AmountKobo
		f.timeouts[req.ID] = req.TimeoutSeconds
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"transfer_id": req.ID})
	})
	resolve := func(w http.ResponseWriter, r *http.Request, isPost bool) {
		id := r.PathValue("id")
		var req struct {
			Code int64 `json:"code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		code, ok := f.pendings[id]
		if !ok {
			http.Error(w, "pending not found", http.StatusNotFound)
			return
		}
		if req.Code != 0 && uint16(req.Code) != code {
			http.Error(w, "PENDING_TRANSFER_HAS_DIFFERENT_CODE", http.StatusUnprocessableEntity)
			return
		}
		if isPost {
			f.posted[id] = true
		} else {
			f.voided[id] = true
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"transfer_id": id})
	}
	mux.HandleFunc("POST /v1/transfers/{id}/post", func(w http.ResponseWriter, r *http.Request) { resolve(w, r, true) })
	mux.HandleFunc("POST /v1/transfers/{id}/void", func(w http.ResponseWriter, r *http.Request) { resolve(w, r, false) })
	return mux
}

// FF-2 regression: settle of a code=6 hold must reuse the pending's code.
// Pre-fix the settle POSTed code=5 and the real ledger rejected it — every
// deposit settle failed in LEDGER_URL mode while the dev in-mem client
// (which ignored codes) masked it.
func TestSettleAgainstCodeEnforcingLedger(t *testing.T) {
	fake := newFakeCoreLedger()
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := NewCoreLedgerClient(srv.URL)

	h, err := c.Hold("case-100", 7, 250_000)
	if err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := c.Settle(h.HoldID); err != nil {
		t.Fatalf("settle must succeed (pre-fix: code mismatch rejected): %v", err)
	}
	if err := c.Release(h2ID(t, c, "case-101")); err != nil {
		t.Fatalf("release must succeed: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !fake.posted[h.HoldID] {
		t.Fatal("settle never reached the ledger")
	}
	// the hold must carry its amount (pre-fix sent "amount", which the
	// ledger API drops — zero-amount holds)
	if fake.amounts[h.HoldID] != 250_000 {
		t.Fatalf("hold amount lost: got %d, want 250000", fake.amounts[h.HoldID])
	}
}

func h2ID(t *testing.T, c *CoreLedgerClient, caseID string) string {
	t.Helper()
	h, err := c.Hold(caseID, 8, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	return h.HoldID
}

// FF-8 regression (API mode): Hold sends a deterministic id (idempotency
// key) and a timeout so retries dedup and abandoned holds expire.
func TestHoldIdempotentRetryAndTTL(t *testing.T) {
	fake := newFakeCoreLedger()
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := NewCoreLedgerClient(srv.URL)

	h1, err := c.Hold("case-200", 3, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h1.HoldID, "000000000000232b") { // ns 9003 = 0x232b
		t.Fatalf("hold id must be deterministic under nsDepositHold: %q", h1.HoldID)
	}
	h2, err := c.Hold("case-200", 3, 100_000) // retry after imagined timeout
	if err != nil {
		t.Fatal(err)
	}
	if h1.HoldID != h2.HoldID {
		t.Fatalf("retry must replay the same deterministic id: %s vs %s", h1.HoldID, h2.HoldID)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.pendings) != 1 {
		t.Fatalf("retry double-held: %d pendings", len(fake.pendings))
	}
	if fake.timeouts[h1.HoldID] != DepositHoldTTLSeconds {
		t.Fatalf("hold must carry a TTL: got %d", fake.timeouts[h1.HoldID])
	}
}

// FF-8 regression (dev mode): in-mem Hold dedups retries by case id and
// expires holds past their TTL.
func TestInMemHoldIdempotencyAndExpiry(t *testing.T) {
	c := NewInMemLedgerClient()
	h1, err := c.Hold("case-300", 1, 50_000)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := c.Hold("case-300", 1, 50_000)
	if err != nil {
		t.Fatal(err)
	}
	if h1.HoldID != h2.HoldID {
		t.Fatal("in-mem retry double-held")
	}
	if _, err := c.Hold("case-300", 1, 60_000); err == nil {
		t.Fatal("same case id with a different amount must be rejected")
	}
	// force expiry
	c.mu.Lock()
	c.transfers[h1.HoldID].expiresAt = time.Now().Add(-time.Minute)
	c.mu.Unlock()
	if err := c.Settle(h1.HoldID); err == nil {
		t.Fatal("settle of an expired hold must fail")
	}
	if got := c.holds[h1.HoldID].Status; got != "released" {
		t.Fatalf("expired hold must be released, got %q", got)
	}
}
