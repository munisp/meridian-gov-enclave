package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func devCertPEM(t *testing.T, cn string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAuthorityRegistrySeeded(t *testing.T) {
	store, err := NewAuthorityStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	auths := store.List()
	if len(auths) != 2+37 { // NRS + secretariat + 36 states + FCT
		t.Fatalf("expected 39 authorities, got %d", len(auths))
	}
	a, ok := store.Get("NG-LA")
	if !ok || !strings.Contains(a.Name, "Lagos") {
		t.Fatalf("lagos seed: %+v", a)
	}
}

func TestOnboardCertFingerprint(t *testing.T) {
	store, _ := NewAuthorityStore(t.TempDir(), nil)
	pemStr := devCertPEM(t, "Kano State IRS Dev Cert")
	a, err := store.Onboard("NG-KN", pemStr)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != "active" || len(a.CertFingerprint) != 64 {
		t.Fatalf("onboard: %+v", a)
	}
	if _, err := store.Onboard("NG-KN", "not a pem"); err == nil {
		t.Fatal("expected PEM error")
	}
	// rotation invalidates old fingerprint
	old := a.CertFingerprint
	a2, revoked, err := store.RotateCert("NG-KN", devCertPEM(t, "Kano rotated"))
	if err != nil || revoked != old || a2.CertFingerprint == old {
		t.Fatalf("rotate: %v %v", a2, err)
	}
}

func TestEOIFourPartyVisibility(t *testing.T) {
	store, _ := NewEOIStore(t.TempDir(), nil)
	e, err := store.Create(&EOI{RequesterID: "NG-LA", ResponderID: "NG-KN",
		SubjectPseudoTIN: "ptin_x", Purpose: "audit", Request: "provide filings"})
	if err != nil {
		t.Fatal(err)
	}
	// requester, responder, secretariat can view
	for _, id := range []string{"NG-LA", "NG-KN"} {
		if _, err := store.GetFor(e.ID, id, false); err != nil {
			t.Fatalf("%s should see EOI: %v", id, err)
		}
	}
	if _, err := store.GetFor(e.ID, "JRB-SEC", true); err != nil {
		t.Fatalf("secretariat should see EOI: %v", err)
	}
	// fourth party HARD DENIED
	if _, err := store.GetFor(e.ID, "NG-RI", false); err == nil {
		t.Fatal("fourth party must be denied")
	}
	// inbox filtering
	if got := len(store.ListFor("NG-RI", false)); got != 0 {
		t.Fatalf("fourth party inbox must be empty, got %d", got)
	}
	if got := len(store.ListFor("JRB-SEC", true)); got != 1 {
		t.Fatalf("secretariat inbox: %d", got)
	}
	// only responder answers
	if _, err := store.Answer(e.ID, "NG-LA", "no"); err == nil {
		t.Fatal("requester must not answer")
	}
	if _, err := store.Answer(e.ID, "NG-KN", "attached filings"); err != nil {
		t.Fatal(err)
	}
}

func TestAttributionFormulaNTAA(t *testing.T) {
	f := LoadAttributionFormula("packs")
	if f.PlaceOfConsumptionWeightBps != 3000 {
		t.Fatalf("NTAA 30%% place-of-consumption: got %d bps", f.PlaceOfConsumptionWeightBps)
	}
	inputs := []StateConsumptionInput{
		{StateCode: "NG-LA", ConsumptionBps: 6000, DerivationBps: 5000},
		{StateCode: "NG-KN", ConsumptionBps: 4000, DerivationBps: 5000},
	}
	feed, err := f.BuildAttributionFeed("2026-07", 1_000_000_00, inputs)
	if err != nil {
		t.Fatal(err)
	}
	// Lagos consumption portion = 30% of pool * 60% share = 180,000.00
	if feed.States[0].ConsumptionPortionKobo != 18_000_000 {
		t.Fatalf("lagos consumption portion: %d", feed.States[0].ConsumptionPortionKobo)
	}
	var total int64
	for _, s := range feed.States {
		total += s.TotalKobo
	}
	if total != 1_000_000_00 {
		t.Fatalf("feed must conserve pool: got %d", total)
	}
}

func TestSignedFeedVerifies(t *testing.T) {
	signer, err := NewFeedSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := LoadAttributionFormula("packs")
	feed, _ := f.BuildAttributionFeed("2026-07", 1000, []StateConsumptionInput{
		{StateCode: "NG-LA", ConsumptionBps: 10000, DerivationBps: 10000}})
	doc, err := signer.Sign(feed)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(doc) {
		t.Fatal("signature must verify")
	}
	doc.Feed = append(doc.Feed, ' ') // tamper
	if Verify(doc) {
		t.Fatal("tampered feed must not verify")
	}
}

func TestAdapters(t *testing.T) {
	reg := NewAdapterRegistry()
	f, err := reg.For("NG-LA").PullFilings("2026-07")
	if err != nil || len(f) == 0 {
		t.Fatalf("lagos adapter: %v %v", f, err)
	}
	ack, err := reg.For("NG-FC").PushAssessment(AssessmentNotice{NoticeID: "N1", PseudoTIN: "ptin_a"})
	if err != nil || !strings.HasPrefix(ack, "FCTIRS-ACK-") {
		t.Fatalf("fct ack: %v %v", ack, err)
	}
	// generic fallback covers all states
	if _, err := reg.For("NG-ZA").PullFilings("2026-07"); err != nil {
		t.Fatal(err)
	}
}
