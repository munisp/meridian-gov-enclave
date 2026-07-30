package main

import (
	"strings"
	"testing"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := loadConfig()
	cfg.DataRoot = t.TempDir()
	cases, err := NewCaseStore(cfg.DataRoot, 7, 90)
	if err != nil {
		t.Fatal(err)
	}
	worm, _, err := newWORMStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gate, local := newGateClient(cfg)
	return &Server{cfg: cfg, cases: cases, ledger: NewInMemLedgerClient(), worm: worm,
		gate: gate, localGate: local, depositBps: 2000}
}

func TestCaseIntakeLifecycleDeadlines(t *testing.T) {
	s := newTestServer(t)
	c, err := s.cases.Intake("clerk-1", &Case{
		AppellantPseudoTIN: "ptin_app1", Authority: "NRS", TaxType: "CIT",
		DisputedAmountKobo: 50_000_000_00, Grounds: "wrong assessment"})
	if err != nil {
		t.Fatal(err)
	}
	if c.State != "received" || c.AckDeadline == "" || c.DecideDeadline == "" {
		t.Fatalf("intake: %+v", c)
	}
	// raw TIN refused
	if _, err := s.cases.Intake("clerk-1", &Case{AppellantPseudoTIN: "12345678-0001",
		DisputedAmountKobo: 100}); err == nil {
		t.Fatal("raw TIN must be refused")
	}
	// lifecycle forward only
	if _, err := s.cases.Transition("clerk-1", c.ID, "review", ""); err == nil {
		t.Fatal("must acknowledge before review")
	}
	if _, err := s.cases.Transition("clerk-1", c.ID, "acknowledge", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.cases.Transition("clerk-1", c.ID, "review", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.cases.Transition("member-1", c.ID, "schedule_hearing", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.cases.Transition("member-1", c.ID, "decide", "assessment reduced"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.cases.Transition("member-1", c.ID, "close", ""); err != nil {
		t.Fatal(err)
	}
	got, _ := s.cases.Get(c.ID)
	if got.State != "closed" || len(got.History) < 6 {
		t.Fatalf("lifecycle: %+v", got)
	}
}

func TestDeposit20PctHoldReleaseSettle(t *testing.T) {
	s := newTestServer(t)
	c, _ := s.cases.Intake("clerk-1", &Case{
		AppellantPseudoTIN: "ptin_app2", Authority: "NG-LA", TaxType: "VAT",
		DisputedAmountKobo: 10_000_000_00, Grounds: "double assessment"})
	// 20% of 10,000,000.00 = 2,000,000.00 kobo = 200_000_000
	hold, err := s.ledger.Hold(c.ID, 1, c.DisputedAmountKobo*2000/10000)
	if err != nil {
		t.Fatal(err)
	}
	if hold.AmountKobo != 200_000_000 {
		t.Fatalf("20%% deposit: got %d", hold.AmountKobo)
	}
	_ = s.cases.AttachDeposit(c.ID, hold)
	if err := s.ledger.Settle(hold.HoldID); err != nil {
		t.Fatal(err)
	}
	bal, _ := s.ledger.Balance("pool")
	if bal != 200_000_000 {
		t.Fatalf("pool balance after settle: %d", bal)
	}
	// double settle must fail (TigerBeetle semantics: pending already posted)
	if err := s.ledger.Settle(hold.HoldID); err == nil {
		t.Fatal("double settle must fail")
	}
	// release path on a fresh hold
	hold2, _ := s.ledger.Hold(c.ID, 1, 1000)
	if err := s.ledger.Release(hold2.HoldID); err != nil {
		t.Fatal(err)
	}
	if err := s.ledger.Settle(hold2.HoldID); err == nil {
		t.Fatal("settle after release must fail")
	}
}

func TestPrivilegeFilteredSearch(t *testing.T) {
	s := newTestServer(t)
	c, _ := s.cases.Intake("clerk-1", &Case{
		AppellantPseudoTIN: "ptin_app3", Authority: "NRS", TaxType: "PIT",
		DisputedAmountKobo: 5_000_00, Grounds: "penalty dispute"})
	_ = s.cases.AddDocument(c.ID, CaseDoc{DocID: "D1", Title: "assessment notice"})
	_ = s.cases.AddDocument(c.ID, CaseDoc{DocID: "D2", Title: "counsel advice", Privileged: true})

	pub := s.cases.Search("penalty", false)
	if len(pub) != 1 || len(pub[0].Documents) != 1 {
		t.Fatalf("public search must hide privileged docs: %+v", pub)
	}
	priv := s.cases.Search("penalty", true)
	if len(priv[0].Documents) != 2 {
		t.Fatalf("privileged search must show all docs: %+v", priv)
	}
}

func TestEvidencePackWORM(t *testing.T) {
	s := newTestServer(t)
	c, _ := s.cases.Intake("clerk-1", &Case{
		AppellantPseudoTIN: "ptin_app4", Authority: "NRS", TaxType: "CIT",
		DisputedAmountKobo: 100_000_00, Grounds: "computation error"})
	payload := []byte(`{"case":"` + c.ID + `"}`)
	rc, err := s.worm.Store("ombud", c.ID, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !rc.Immutable || rc.SHA256 == "" || !strings.HasPrefix(rc.WormURI, "worm://") {
		t.Fatalf("receipt: %+v", rc)
	}
}

func TestActivationGate(t *testing.T) {
	s := newTestServer(t)
	active, mode, err := s.gate.Active("ombud.rules_active")
	if err != nil || !active {
		t.Fatalf("dev default gate should be active: %v %v", active, err)
	}
	if mode != "local-gate-file" {
		t.Fatalf("mode: %s", mode)
	}
	if err := s.localGate.Flip("ombud.rules_active", false); err != nil {
		t.Fatal(err)
	}
	active, _, _ = s.gate.Active("ombud.rules_active")
	if active {
		t.Fatal("gate should be off after flip")
	}
}

func TestPackParamsLoaded(t *testing.T) {
	if got := packInt("packs", "rp-deposit-20pct", "rate_bps", 0); got != 2000 {
		t.Fatalf("deposit rate from pack: %d", got)
	}
	if got := packInt("packs", "rp-procedure-ombud", "days", 0); got != 7 {
		t.Fatalf("first 'days' scalar (ack deadline) from pack: %d", got)
	}
}
