package main

// Tests for HSM/KMS key-provider wiring of WORM evidence-receipt signing.
// The [SIM] soft-token stands in for the HSM; fail-closed behaviour is
// asserted directly.

import (
	"errors"
	"testing"

	"github.com/munisp/meridian-gov-enclave/packages/keyx/provider"
)

func TestReceiptSignVerifyLocalWORM(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocalWORMStore(root)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := NewReceiptSigner(root, nil) // dev software key
	if err != nil {
		t.Fatal(err)
	}
	store.SetReceiptSigner(rs)
	rc, err := store.Store("f1", "msg-1", []byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatal(err)
	}
	if rc.Signature == "" || rc.PublicKey == "" {
		t.Fatal("receipt not signed")
	}
	if !VerifyReceipt(rc) {
		t.Fatal("signed receipt did not verify")
	}
	// Tamper: modified receipt must not verify.
	bad := *rc
	bad.SHA256 = "00" + bad.SHA256[2:]
	if VerifyReceipt(&bad) {
		t.Fatal("tampered receipt verified")
	}
}

func TestReceiptSignProviderBacked(t *testing.T) {
	tok := provider.NewSoftToken() // [SIM] HSM soft-token
	root := t.TempDir()
	rs, err := NewReceiptSigner(root, tok)
	if err != nil {
		t.Fatal(err)
	}
	if rs.priv != nil {
		t.Fatal("provider-backed signer must not hold private key material")
	}
	store, err := NewLocalWORMStore(root)
	if err != nil {
		t.Fatal(err)
	}
	store.SetReceiptSigner(rs)
	rc, err := store.Store("f2", "msg-2", []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyReceipt(rc) {
		t.Fatal("provider-backed receipt signature did not verify")
	}
}

func TestReceiptSignerFailClosed(t *testing.T) {
	// Unreachable cloud KMS: construction must fail (no software fallback).
	p, err := provider.NewCloudKMS(provider.CloudKMSConfig{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReceiptSigner(t.TempDir(), p); err == nil {
		t.Fatal("expected fail-closed construction against unreachable KMS")
	}
	// KEY_PROVIDER=hsm without plugin binary must fail closed.
	t.Setenv("KEY_PROVIDER", "hsm")
	t.Setenv("KEY_PKCS11_PLUGIN", "")
	if _, err := provider.NewFromEnv(); !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("expected fail-closed ErrUnavailable, got %v", err)
	}
}

func TestReceiptUnsignedLegacyStillWorks(t *testing.T) {
	// Legacy path (no signer attached) keeps working: unsigned receipts,
	// VerifyReceipt reports false rather than failing the flow.
	store, err := NewLocalWORMStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rc, err := store.Store("f1", "msg-3", []byte(`{"legacy":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if rc.Signature != "" {
		t.Fatal("legacy store unexpectedly signed receipt")
	}
	if VerifyReceipt(rc) {
		t.Fatal("unsigned receipt must not verify")
	}
}
