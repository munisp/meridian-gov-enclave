package main

// Authoritative signing of WORM evidence receipts (SPEC 5): every receipt
// issued by the gateway is ed25519-signed. Dev keeps a software key under
// <dataRoot>/signing; KEY_PROVIDER=hsm|pkcs11|cloud-kms routes signing to
// the HSM/KMS "receipt" key (fail-closed — a configured but unavailable
// provider refuses startup in main, and signing errors fail the flow).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/munisp/meridian-gov-enclave/packages/keyx/provider"
)

// ReceiptSigner signs evidence receipts with an ed25519 keypair (dev
// software key, or HSM/KMS provider-backed when prov is non-software).
type ReceiptSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey // nil when provider-backed
	prov provider.SignerProvider
}

// NewReceiptSigner loads the receipt signing key through the key-provider
// abstraction. A nil or software-mode prov keeps the dev file key under
// <dataRoot>/signing (created on first use). A non-software prov signs via
// the HSM/KMS "receipt" key and fails closed if the public key cannot be
// served.
func NewReceiptSigner(dataRoot string, prov provider.SignerProvider) (*ReceiptSigner, error) {
	if prov != nil && prov.Mode() != "software" {
		pub, err := prov.PublicKey(context.Background(), "receipt")
		if err != nil {
			return nil, fmt.Errorf("receipt signer: provider public key: %w", err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("receipt signer: provider returned %d-byte public key, want ed25519", len(pub))
		}
		return &ReceiptSigner{prov: prov, pub: ed25519.PublicKey(append([]byte(nil), pub...))}, nil
	}
	dir := filepath.Join(dataRoot, "signing")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "receipt_ed25519.key")
	if raw, err := os.ReadFile(keyPath); err == nil && len(raw) == ed25519.PrivateKeySize {
		priv := ed25519.PrivateKey(raw)
		return &ReceiptSigner{pub: priv.Public().(ed25519.PublicKey), priv: priv}, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		return nil, err
	}
	return &ReceiptSigner{pub: pub, priv: priv}, nil
}

// receiptCanonical is the signed canonical string for a receipt.
func receiptCanonical(r *EvidenceReceipt) string {
	return strings.Join([]string{
		"NRS-RECEIPT1", r.EvidenceID, r.SHA256, r.WormURI, r.StoredAt, r.Mode, r.Flow, r.MessageID,
	}, "|")
}

// Sign signs the receipt in place (sets Signature and PublicKey).
func (s *ReceiptSigner) Sign(r *EvidenceReceipt) error {
	payload := receiptCanonical(r)
	var sig []byte
	var err error
	if s.prov != nil {
		sig, err = s.prov.Sign(context.Background(), "receipt", []byte(payload))
		if err != nil {
			return fmt.Errorf("receipt sign: %w", err)
		}
	} else {
		sig = ed25519.Sign(s.priv, []byte(payload))
	}
	r.Signature = hex.EncodeToString(sig)
	r.PublicKey = hex.EncodeToString(s.pub)
	return nil
}

// VerifyReceipt checks a signed receipt. Unsigned receipts (legacy dev)
// report false.
func VerifyReceipt(r *EvidenceReceipt) bool {
	if r.Signature == "" || r.PublicKey == "" {
		return false
	}
	pub, err1 := hex.DecodeString(r.PublicKey)
	sig, err2 := hex.DecodeString(r.Signature)
	if err1 != nil || err2 != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(receiptCanonical(r)), sig)
}
