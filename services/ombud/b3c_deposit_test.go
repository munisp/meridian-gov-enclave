package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// B3 #8 + B2-#7 regression tests:
//  - #8: deposit status stayed "held" forever after settle/release even
//    though the money moved on ledger 500.
//  - B2-#7: release/settle moved money with no role gate — any caller
//    (including members) could release/settle a deposit.

func depositRequest(t *testing.T, s *Server, caseID string, p *Principal, roleHeader string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/cases/"+caseID+"/deposit/resolve", nil)
	req.SetPathValue("id", caseID)
	if roleHeader != "" {
		req.Header.Set("X-Ombud-Role", roleHeader)
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxPrincipal, p))
	return httptest.NewRecorder(), req
}

func setupHeldDeposit(t *testing.T, s *Server) *Case {
	t.Helper()
	c, err := s.cases.Intake("clerk-1", &Case{
		AppellantPseudoTIN: "ptin_dep1", Authority: "NRS", TaxType: "CIT",
		DisputedAmountKobo: 50_000_000_00, Grounds: "wrong assessment"})
	if err != nil {
		t.Fatal(err)
	}
	hold, err := s.ledger.Hold(c.ID, 1, c.DisputedAmountKobo*2000/10000)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.cases.AttachDeposit(c.ID, hold); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDepositReleaseUpdatesStatusAndRequiresRole(t *testing.T) {
	s := newTestServer(t)
	s.authn = newAuthenticator(s.cfg) // dev mode
	c := setupHeldDeposit(t, s)

	// B2-#7: a member (no admin/operator role) must NOT release money.
	rec, req := depositRequest(t, s, c.ID, &Principal{Sub: "member-1"}, RoleMember)
	s.releaseDeposit(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member release: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	got, _ := s.cases.Get(c.ID)
	if got.Deposit.Status != "held" {
		t.Fatalf("forbidden release must not change status, got %q", got.Deposit.Status)
	}

	// operator (clerk) release succeeds and flips the status (#8).
	rec, req = depositRequest(t, s, c.ID, &Principal{Sub: "op-1", Roles: []string{"operator"}}, "")
	s.releaseDeposit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator release: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	got, _ = s.cases.Get(c.ID)
	if got.Deposit.Status != "released" {
		t.Fatalf("#8: deposit status stuck %q after successful release", got.Deposit.Status)
	}

	// terminal: a second resolve must conflict, not re-move money.
	rec, req = depositRequest(t, s, c.ID, &Principal{Sub: "admin-1", Roles: []string{"admin"}}, "")
	s.releaseDeposit(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second release: want 409, got %d", rec.Code)
	}
}

func TestDepositSettleUpdatesStatus(t *testing.T) {
	s := newTestServer(t)
	s.authn = newAuthenticator(s.cfg)
	c := setupHeldDeposit(t, s)

	rec, req := depositRequest(t, s, c.ID, &Principal{Sub: "admin-1", Roles: []string{"admin"}}, "")
	s.settleDeposit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin settle: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	got, _ := s.cases.Get(c.ID)
	if got.Deposit.Status != "settled" {
		t.Fatalf("#8: deposit status stuck %q after successful settle", got.Deposit.Status)
	}
	// history records the money movement
	found := false
	for _, h := range got.History {
		if h.Action == "deposit_settled" {
			found = true
		}
	}
	if !found {
		t.Fatal("settle must be recorded in case history")
	}
}
