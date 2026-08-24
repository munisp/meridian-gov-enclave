package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// B3 #5 regression: the ombud core-ledger client must authenticate with
// the env-injected shared service token (X-Service-Token), falling back
// to the forgeable X-Dev-Role only when no token is configured (dev).

func capturePostHeaders(t *testing.T, fn func(base string) error) http.Header {
	t.Helper()
	got := make(http.Header)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"transfer_id":"tx1"}`))
	}))
	defer srv.Close()
	if err := fn(srv.URL); err != nil {
		t.Fatalf("call: %v", err)
	}
	return got
}

func TestCoreLedgerSendsServiceToken(t *testing.T) {
	t.Setenv("MERIDIAN_SERVICE_TOKEN", "svc-tok-xyz")
	got := capturePostHeaders(t, func(base string) error {
		return NewCoreLedgerClient(base).Release("tx1")
	})
	if got.Get("X-Service-Token") != "svc-tok-xyz" {
		t.Fatalf("X-Service-Token = %q", got.Get("X-Service-Token"))
	}
	if got.Get("X-Service-Name") != "ombud" {
		t.Fatalf("X-Service-Name = %q", got.Get("X-Service-Name"))
	}
	if got.Get("X-Dev-Role") != "" {
		t.Fatal("X-Dev-Role sent while a service token is configured")
	}
}

func TestCoreLedgerDevRoleOnlyWithoutToken(t *testing.T) {
	got := capturePostHeaders(t, func(base string) error {
		return NewCoreLedgerClient(base).Release("tx1")
	})
	if got.Get("X-Service-Token") != "" {
		t.Fatal("X-Service-Token sent with none configured")
	}
	if got.Get("X-Dev-Role") != "operator" {
		t.Fatalf("dev fallback X-Dev-Role = %q", got.Get("X-Dev-Role"))
	}
}
