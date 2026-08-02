// permify_test.go — P0 authz: live client fake-transport, dev fallback,
// prod fail-closed, and schema consistency (every permission segment in the
// gateway's scopes must exist in schemas/enclave-gateway.perm, vendored from
// the canonical core permify-models schema family).
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestPermifyClient(h http.HandlerFunc) (*PermifyClient, func()) {
	srv := httptest.NewServer(h)
	return NewPermifyClient(srv.URL, "t1"), srv.Close
}

func TestPermifyCheckAllowedDenied(t *testing.T) {
	c, done := newTestPermifyClient(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Entity     struct{ Type, ID string } `json:"entity"`
			Permission string                    `json:"permission"`
			Subject    struct{ Type, ID string } `json:"subject"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Entity.Type+":"+req.Entity.ID != "flow:f1" || req.Permission != "send" || req.Subject.ID != "u1" {
			t.Errorf("bad check payload %+v", req)
		}
		w.Write([]byte(`{"can":"RESULT_ALLOWED"}`))
	})
	defer done()
	ok, err := c.Check(context.Background(), "flow:f1", "send", "user:u1")
	if err != nil || !ok {
		t.Fatalf("want allowed, got %v %v", ok, err)
	}
}

func TestPermifyCheckDenied(t *testing.T) {
	c, done := newTestPermifyClient(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"can":"RESULT_DENIED"}`))
	})
	defer done()
	ok, err := c.Check(context.Background(), "flow:f2", "send", "user:u2")
	if err != nil || ok {
		t.Fatalf("want denied nil-error, got %v %v", ok, err)
	}
}

func TestPermifyCheckRetriesOn5xx(t *testing.T) {
	var calls int32
	c, done := newTestPermifyClient(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{"can":"RESULT_ALLOWED"}`))
	})
	defer done()
	ok, err := c.Check(context.Background(), "receipts:gateway", "read", "user:u1")
	if err != nil || !ok {
		t.Fatalf("want allowed after retry, got %v %v", ok, err)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("want exactly one retry, got %d calls", calls)
	}
}

func TestPermifyCheckTimeout(t *testing.T) {
	c, done := newTestPermifyClient(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Write([]byte(`{"can":"RESULT_ALLOWED"}`))
	})
	defer done()
	c.timeout = 50 * time.Millisecond
	ok, err := c.Check(context.Background(), "flow:f1", "send", "user:u1")
	if err == nil || ok {
		t.Fatalf("want timeout error+denied, got %v %v", ok, err)
	}
}

func TestScopeToRef(t *testing.T) {
	ent, perm, err := scopeToRef("flow:f1:send")
	if err != nil || ent != "flow:f1" || perm != "send" {
		t.Fatalf("flow scope: %s %s %v", ent, perm, err)
	}
	ent, perm, err = scopeToRef("receipts:read")
	if err != nil || ent != "receipts:gateway" || perm != "read" {
		t.Fatalf("receipts scope: %s %s %v", ent, perm, err)
	}
	if _, _, err := scopeToRef("garbage"); err == nil {
		t.Fatal("malformed scope must error")
	}
}

func TestPermifyFromEnvDevFallback(t *testing.T) {
	t.Setenv("PERMIFY_URL", "")
	c, err := permifyFromEnv(Config{AuthMode: "dev"})
	if err != nil || c != nil {
		t.Fatalf("dev without PERMIFY_URL must fall back, got %v %v", c, err)
	}
}

func TestPermifyFromEnvProdFailClosed(t *testing.T) {
	t.Setenv("PERMIFY_URL", "")
	if _, err := permifyFromEnv(Config{AuthMode: "keycloak"}); err == nil {
		t.Fatal("non-dev AUTH_MODE without PERMIFY_URL must fail closed")
	}
}

func TestPermifyFromEnvLive(t *testing.T) {
	t.Setenv("PERMIFY_URL", "http://permify:3476")
	c, err := permifyFromEnv(Config{AuthMode: "keycloak"})
	if err != nil || c == nil {
		t.Fatalf("PERMIFY_URL set must yield live client, got %v %v", c, err)
	}
}

// Live scope check through the Server seam: server decision is authoritative
// and unreachable Permify fails closed.
func TestScopeCheckAuthzLive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"can":"RESULT_DENIED"}`))
	}))
	s := &Server{perm: NewPermifyClient(srv.URL, "t1")}
	req := httptest.NewRequest("POST", "/v1/flows/F1", nil)
	p := &Principal{Sub: "u1", Roles: []string{"admin"}} // dev map would ALLOW
	if s.scopeCheckAuthz(req, p, "flow:f1:send") {
		t.Fatal("Permify RESULT_DENIED must override the dev role map")
	}
	srv.Close()
	if s.scopeCheckAuthz(req, p, "flow:f1:send") {
		t.Fatal("unreachable Permify must fail closed")
	}
}

func TestScopeCheckAuthzDevFallback(t *testing.T) {
	s := &Server{} // perm nil -> dev role map
	req := httptest.NewRequest("POST", "/v1/flows/F1", nil)
	if !s.scopeCheckAuthz(req, &Principal{Sub: "u1", Roles: []string{"operator"}}, "flow:f1:send") {
		t.Fatal("operator must hold flow:f1:send in dev fallback")
	}
	if s.scopeCheckAuthz(req, &Principal{Sub: "u2", Roles: []string{"auditor"}}, "flow:f1:send") {
		t.Fatal("auditor must NOT hold flow:f1:send in dev fallback")
	}
}

// TestSchemaConsistency: every permission segment in the gateway's scopes
// (flow scopes + receipts:read) must be declared in
// schemas/enclave-gateway.perm.
func TestSchemaConsistency(t *testing.T) {
	b, err := os.ReadFile("schemas/enclave-gateway.perm")
	if err != nil {
		t.Fatalf("schema file missing: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*permission\s+([a-z_]+)\s*=`)
	declared := map[string]bool{}
	for _, m := range re.FindAllSubmatch(b, -1) {
		declared[string(m[1])] = true
	}
	s := &Server{}
	scopes := []string{"receipts:read", "flow:f7:read", "flow:f8:read"}
	for _, f := range s.flows() {
		scopes = append(scopes, f.Scope)
	}
	for _, sc := range scopes {
		_, perm, err := scopeToRef(sc)
		if err != nil {
			t.Errorf("scope %q: %v", sc, err)
			continue
		}
		if strings.HasPrefix(sc, "flow:f6:") {
			continue // F6 is enclave-internal; no Permify scope check applies
		}
		if !declared[perm] {
			t.Errorf("permission %q (scope %q) checked in code but missing from schemas/enclave-gateway.perm", perm, sc)
		}
	}
}
