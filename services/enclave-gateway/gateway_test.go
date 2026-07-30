package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	cfg := loadConfig()
	cfg.DataRoot = t.TempDir()
	cfg.AuthMode = "dev"
	worm, local, err := newWORMStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg, authn: newAuthenticator(cfg), http: http.DefaultClient, worm: worm, localWorm: local}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	for id, f := range s.flows() {
		flow := f
		mux.HandleFunc("POST /flows/"+strings.ToLower(id)+"/"+flow.Name,
			s.withAuth(func(w http.ResponseWriter, r *http.Request) { s.pipeline(w, r, flow) }))
	}
	mux.HandleFunc("GET /flows/f8/wht-credit-recon", s.withAuth(s.handleF8))
	mux.HandleFunc("GET /v1/receipts", s.withAuth(s.handleReceipts))
	return s, s.denyForbiddenFlows(mux)
}

func do(t *testing.T, h http.Handler, method, path, body, role string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if role != "" {
		req.Header.Set("X-Dev-Role", role)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	_, h := newTestServer(t)
	rec := do(t, h, "GET", "/healthz", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: %d", rec.Code)
	}
}

func TestPipelineF1ValidateWormDispatch(t *testing.T) {
	_, h := newTestServer(t)
	good := `{"invoice_id":"INV-1","supplier_tin":"12345678-0001","issue_date":"2026-07-01","lines":[],"total_kobo":1000}`
	rec := do(t, h, "POST", "/flows/f1/ubl-preclearance-invoices", good, "operator")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("accepted: %d body=%s", rec.Code, rec.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	rc := out["evidence_receipt"].(map[string]any)
	if rc["immutable"] != true || rc["sha256"] == "" {
		t.Fatalf("bad receipt: %v", rc)
	}
	disp := out["dispatch"].(map[string]any)
	if disp["mode"] != "local-spool" {
		t.Fatalf("dispatch: %v", disp)
	}
}

func TestPipelineRejectsBadSchemaBeforeWorm(t *testing.T) {
	s, h := newTestServer(t)
	rec := do(t, h, "POST", "/flows/f1/ubl-preclearance-invoices", `{"invoice_id":"X"}`, "operator")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("schema: %d", rec.Code)
	}
	if len(s.receipts) != 0 {
		t.Fatal("receipt must NOT be issued for schema-invalid message")
	}
}

func TestScopeCheckDeniesAuditorSend(t *testing.T) {
	_, h := newTestServer(t)
	good := `{"report_id":"R1","supplier_tin":"1","period":"2026-07","total_sales_kobo":1,"total_vat_kobo":1}`
	rec := do(t, h, "POST", "/flows/f2/b2c-reports", good, "auditor")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scope: %d", rec.Code)
	}
}

func TestAuthRequired(t *testing.T) {
	_, h := newTestServer(t)
	rec := do(t, h, "POST", "/flows/f1/ubl-preclearance-invoices", `{}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("auth: %d", rec.Code)
	}
}

// F9/F10 are forbidden by construction: deny middleware answers 403 and no
// consumer path exists.
func TestForbiddenFlowsF9F10(t *testing.T) {
	s, h := newTestServer(t)
	for _, path := range []string{
		"/flows/f9/anything", "/flows/f10/direct-db-extract", "/flows/F9/", "/flows/f10",
	} {
		rec := do(t, h, "POST", path, `{}`, "admin")
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
			t.Fatalf("forbidden flow %s: got %d", path, rec.Code)
		}
	}
	if len(s.receipts) != 0 {
		t.Fatal("no receipt may be issued for forbidden flows")
	}
}

func TestF6InternalOnly(t *testing.T) {
	_, h := newTestServer(t)
	good := `{"eoi_id":"E1","requester_state":"lagos","responder_state":"kano","subject_pseudo_tin":"ptin_x"}`
	rec := do(t, h, "POST", "/flows/f6/eoi-exchange", good, "admin")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("F6 without internal token: %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/flows/f6/eoi-exchange", bytes.NewBufferString(good))
	req.Header.Set("X-Dev-Role", "admin")
	req.Header.Set("X-Internal-Flow-Token", "dev-internal-token")
	rec2 := httptest.NewRecorder()
	h2 := h
	h2.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusAccepted {
		t.Fatalf("F6 with internal token: %d body=%s", rec2.Code, rec2.Body)
	}
}

func TestF8PseudonymisedAndLogged(t *testing.T) {
	s, h := newTestServer(t)
	rec := do(t, h, "GET", "/flows/f8/wht-credit-recon?pseudo_tin=ptin_abc", "", "auditor")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown pseudo: %d", rec.Code)
	}
	rec = do(t, h, "GET", "/flows/f8/wht-credit-recon?pseudo_tin=12345678-0001", "", "auditor")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("raw TIN must be rejected: %d", rec.Code)
	}
	_ = s
}
