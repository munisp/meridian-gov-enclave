package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Fix 6: prod profile must fail closed.
func TestConfigValidateFailClosed(t *testing.T) {
	dev := Config{AuthMode: "dev"}
	if err := dev.Validate(); err != nil {
		t.Fatalf("dev must validate: %v", err)
	}
	prod := Config{AuthMode: "keycloak"}
	if err := prod.Validate(); err == nil {
		t.Fatal("prod without TLS must fail closed")
	}
	prod.TLSCertFile, prod.TLSKeyFile = "c.pem", "k.pem"
	if err := prod.Validate(); err == nil {
		t.Fatal("prod with dev/default internal token must fail closed")
	}
	prod.InternalFlowToken = "real-token"
	if err := prod.Validate(); err != nil {
		t.Fatalf("fully configured prod must validate: %v", err)
	}
}

func newAnchorServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	worm, err := NewLocalWORMStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_MODE", "dev")
	return &Server{cfg: Config{AuthMode: "dev", DataRoot: dir}, localWorm: worm}
}

// I19: anchor records seal and verify; tampering is detected.
func TestAuditAnchorSealAndVerify(t *testing.T) {
	s := newAnchorServer(t)
	if _, err := s.localWorm.Store("f1", "m1", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.localWorm.Store("f1", "m2", []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	a, err := s.CreateAnchor()
	if err != nil {
		t.Fatal(err)
	}
	if a.MerkleRoot == "" || a.Entries != 2 || a.Seal == "" {
		t.Fatalf("bad anchor: %+v", a)
	}
	res, err := s.VerifyAnchors()
	if err != nil || res["valid"] != true {
		t.Fatalf("verify failed: %v %v", res, err)
	}
	if res["covers_current_chain_tip"] != true {
		t.Fatalf("anchor must cover chain tip: %v", res)
	}
	// tamper with the anchor log
	p := s.anchorLogPath()
	data, _ := os.ReadFile(p)
	var rec AnchorRecord
	_ = json.Unmarshal([]byte(string(data[:len(data)-1])), &rec)
	rec.Entries = 99
	line, _ := json.Marshal(rec)
	if err := os.WriteFile(p, append(line, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _ = s.VerifyAnchors()
	if res["valid"] != false {
		t.Fatalf("tampered anchor must fail verification: %v", res)
	}
}

// I20: sharing requires lawful basis, enforces k-anonymity and minimisation.
func TestSharingGateway(t *testing.T) {
	s := newAnchorServer(t)
	consents := []ConsentReceipt{{ReceiptID: "cr-1", Subject: "tinhash", Purpose: "data_sharing", Agency: "jtb", Granted: true}}
	b, _ := json.Marshal(consents)
	if err := os.WriteFile(filepath.Join(s.cfg.DataRoot, "consents.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	subjects := make([]map[string]any, 6)
	for i := range subjects {
		subjects[i] = map[string]any{"tin_hash": "h", "state": "Lagos", "band": "small", "nin": "MUST-NOT-LEAK", "full_name": "MUST-NOT-LEAK"}
	}
	// no basis -> denied
	if _, _, err := s.Disclose(DiscloseRequest{Agency: "jtb", Subjects: subjects}, "test"); err == nil {
		t.Fatal("sharing without basis must be denied")
	}
	// k-anonymity -> denied
	if _, _, err := s.Disclose(DiscloseRequest{Agency: "jtb", StatutoryBasis: "public_task", Subjects: subjects[:3]}, "test"); err == nil {
		t.Fatal("cohort below k must be denied")
	}
	// consent for the WRONG agency -> denied
	if _, _, err := s.Disclose(DiscloseRequest{Agency: "cbn", ConsentReceipt: "cr-1", Subjects: subjects}, "test"); err == nil {
		t.Fatal("consent scoped to another agency must be denied")
	}
	// valid consent -> minimised disclosure + log entry
	out, entry, err := s.Disclose(DiscloseRequest{Agency: "jtb", ConsentReceipt: "cr-1", Subjects: subjects}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 6 || entry.Basis != "consent:cr-1" {
		t.Fatalf("bad disclosure: %d %v", len(out), entry)
	}
	for _, row := range out {
		if _, ok := row["nin"]; ok {
			t.Fatal("minimisation leaked non-allowlisted field")
		}
		if _, ok := row["full_name"]; ok {
			t.Fatal("minimisation leaked PII")
		}
	}
	// statutory basis path also works
	if _, _, err := s.Disclose(DiscloseRequest{Agency: "firs", StatutoryBasis: "legal_obligation", Subjects: subjects}, "test"); err != nil {
		t.Fatal(err)
	}
	// disclosure log has both entries
	data, err := os.ReadFile(s.disclosureLogPath())
	if err != nil || len(data) == 0 {
		t.Fatal("disclosure log missing")
	}
}
