package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePack(t *testing.T, root, id, body string) {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1.0.0.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

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
	// Gazetted NTAA 2025 weights: 50% equality / 20% population / 30%
	// place of consumption; there is NO derivation limb.
	if f.EqualityWeightBps != 5000 {
		t.Fatalf("NTAA 50%% equality: got %d bps", f.EqualityWeightBps)
	}
	if f.PopulationWeightBps != 2000 {
		t.Fatalf("NTAA 20%% population: got %d bps", f.PopulationWeightBps)
	}
	if f.PlaceOfConsumptionWeightBps != 3000 {
		t.Fatalf("NTAA 30%% place-of-consumption: got %d bps", f.PlaceOfConsumptionWeightBps)
	}
	inputs := []StateConsumptionInput{
		{StateCode: "NG-LA", ConsumptionBps: 6000, PopulationBps: 5000},
		{StateCode: "NG-KN", ConsumptionBps: 4000, PopulationBps: 5000},
	}
	feed, err := f.BuildAttributionFeed("2026-07", 1_000_000_00, inputs)
	if err != nil {
		t.Fatal(err)
	}
	// Lagos consumption portion = 30% of pool * 60% share = 180,000.00
	if feed.States[0].ConsumptionPortionKobo != 18_000_000 {
		t.Fatalf("lagos consumption portion: %d", feed.States[0].ConsumptionPortionKobo)
	}
	// Equality portion = 50% of pool shared equally = 250,000.00 each.
	if feed.States[0].EqualityPortionKobo != 25_000_000 {
		t.Fatalf("lagos equality portion: %d", feed.States[0].EqualityPortionKobo)
	}
	// Population portion = 20% of pool * 50% share = 100,000.00 each.
	if feed.States[0].PopulationPortionKobo != 10_000_000 {
		t.Fatalf("lagos population portion: %d", feed.States[0].PopulationPortionKobo)
	}
	var total, eq, pop, cons int64
	for _, s := range feed.States {
		total += s.TotalKobo
		eq += s.EqualityPortionKobo
		pop += s.PopulationPortionKobo
		cons += s.ConsumptionPortionKobo
	}
	if total != 1_000_000_00 {
		t.Fatalf("feed must conserve pool: got %d", total)
	}
	// Statutory split: portions must sum to the 50/20/30 partition of the
	// pool (up to the exact-conservation remainder on consumption).
	if eq != 50_000_000 || pop != 20_000_000 {
		t.Fatalf("equality/population pools must be 50%%/20%%: got eq=%d pop=%d", eq, pop)
	}
	if cons < 30_000_000 || cons-30_000_000 > int64(len(inputs)) {
		t.Fatalf("consumption pool must be 30%% (+ rounding remainder): got %d", cons)
	}
}

func TestAttributionFormulaEffectiveDated(t *testing.T) {
	f := LoadAttributionFormula("packs")
	inputs := []StateConsumptionInput{
		{StateCode: "NG-LA", ConsumptionBps: 10000, PopulationBps: 10000}}
	// Pre-effective-date period: refuse rather than compute with a formula
	// not in force.
	if _, err := f.BuildAttributionFeed("2025-12", 1000, inputs); err == nil {
		t.Fatal("pre-NTAA period must be refused (formula effective 2026-01)")
	}
	if _, err := f.BuildAttributionFeed("2026-01", 1000, inputs); err != nil {
		t.Fatalf("first in-force period must compute: %v", err)
	}
}

func TestAttributionPackMisSummingRejected(t *testing.T) {
	// A pack whose weights do not partition 100% exactly must fail closed to
	// the statutory constants, never silently scale allocations.
	dir := t.TempDir()
	writePack(t, dir, "rp-attribution-formula", `id: rp-attribution-formula
version: 1.0.0
effective_from: 2026-01-01
rules:
  - id: attr.vat.state_share
    then:
      equality_weight_bps: 4000
      population_weight_bps: 2000
      place_of_consumption_weight_bps: 3000
`)
	f := LoadAttributionFormula(dir)
	if f.EqualityWeightBps != 5000 || f.PopulationWeightBps != 2000 ||
		f.PlaceOfConsumptionWeightBps != 3000 {
		t.Fatalf("mis-summing pack must fail closed to statutory 50/20/30: got %d/%d/%d",
			f.EqualityWeightBps, f.PopulationWeightBps, f.PlaceOfConsumptionWeightBps)
	}
}

func TestAttributionPackNegativeWeightRejected(t *testing.T) {
	// V2 residual: a pack 11000/-500/-500 still sums to 10000 bps but must
	// be rejected — negative weights produce NEGATIVE state portions. Fail
	// closed to the statutory 50/20/30 constants.
	dir := t.TempDir()
	writePack(t, dir, "rp-attribution-formula", `id: rp-attribution-formula
version: 1.0.0
effective_from: 2026-01-01
rules:
  - id: attr.vat.state_share
    then:
      equality_weight_bps: 11000
      population_weight_bps: -500
      place_of_consumption_weight_bps: -500
`)
	f := LoadAttributionFormula(dir)
	if f.EqualityWeightBps != 5000 || f.PopulationWeightBps != 2000 ||
		f.PlaceOfConsumptionWeightBps != 3000 {
		t.Fatalf("negative-weight pack must fail closed to statutory 50/20/30: got %d/%d/%d",
			f.EqualityWeightBps, f.PopulationWeightBps, f.PlaceOfConsumptionWeightBps)
	}
	// And the formula must still compute non-negative portions.
	inputs := []StateConsumptionInput{
		{StateCode: "NG-LA", ConsumptionBps: 5000, PopulationBps: 5000},
		{StateCode: "NG-KN", ConsumptionBps: 5000, PopulationBps: 5000},
	}
	feed, err := f.BuildAttributionFeed("2026-07", 1_000_000_00, inputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range feed.States {
		if s.EqualityPortionKobo < 0 || s.PopulationPortionKobo < 0 ||
			s.ConsumptionPortionKobo < 0 || s.TotalKobo < 0 {
			t.Fatalf("state %s has a negative portion: %+v", s.StateCode, s)
		}
	}
}

func TestSignedFeedVerifies(t *testing.T) {
	signer, err := NewFeedSigner(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := LoadAttributionFormula("packs")
	feed, _ := f.BuildAttributionFeed("2026-07", 1000, []StateConsumptionInput{
		{StateCode: "NG-LA", ConsumptionBps: 10000, PopulationBps: 10000}})
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
