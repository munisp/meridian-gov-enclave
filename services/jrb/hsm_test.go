package main

// Tests for the HSM/KMS key-provider wiring of attribution-feed (tcc)
// signing. The [SIM] soft-token stands in for the HSM; fail-closed startup
// behaviour is asserted directly.

import (
	"errors"
	"testing"
	"time"

	"github.com/munisp/meridian-gov-enclave/packages/keyx/provider"
)

func testFeed() *AttributionFeed {
	return &AttributionFeed{
		FeedID:  "feed-test-1",
		Period:  "2026-01",
		PackRef: "rp-attribution-formula@1.0.0",
		BuiltAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func TestFeedSignerProviderBacked(t *testing.T) {
	tok := provider.NewSoftToken() // [SIM] HSM soft-token
	signer, err := NewFeedSignerWithProvider(t.TempDir(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if signer.priv != nil {
		t.Fatal("provider-backed signer must not hold private key material")
	}
	doc, err := signer.Sign(testFeed())
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(doc) {
		t.Fatal("provider-backed feed signature did not verify")
	}
}

func TestFeedSignerSoftwareParity(t *testing.T) {
	// Explicit software provider must behave exactly like legacy NewFeedSigner.
	prov, err := provider.NewSoftware(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s1, err := NewFeedSignerWithProvider(dir, prov)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewFeedSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := s1.Sign(testFeed())
	if err != nil {
		t.Fatal(err)
	}
	d2, err := s2.Sign(testFeed())
	if err != nil {
		t.Fatal(err)
	}
	if d1.PublicKey != d2.PublicKey {
		t.Fatal("software-provider path diverged from legacy NewFeedSigner")
	}
}

func TestFeedSignerFailClosed(t *testing.T) {
	// Unreachable cloud KMS: construction must fail (no software fallback).
	p, err := provider.NewCloudKMS(provider.CloudKMSConfig{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFeedSignerWithProvider(t.TempDir(), p); err == nil {
		t.Fatal("expected fail-closed construction against unreachable KMS")
	}
	// KEY_PROVIDER=hsm without plugin binary must fail closed.
	t.Setenv("KEY_PROVIDER", "hsm")
	t.Setenv("KEY_PKCS11_PLUGIN", "")
	if _, err := provider.NewFromEnv(); !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("expected fail-closed ErrUnavailable, got %v", err)
	}
}
